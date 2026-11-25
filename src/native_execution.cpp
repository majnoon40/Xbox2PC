// native_execution.cpp — M11 Phase 5 native-host execution with imports.
//
// Slices:
//   M11.5 (first):  forked child, fault-contained, no imports/GS/stack.
//   M11 Phase 5:    shared-memory import ring (ADR-0001), guest TEB via
//                   ARCH_SET_GS, thunk page + child IAT rewrite, SIGTRAP
//                   dispatch, structured fault classification, ExitProcess.
//
// The parent never shares function pointers with the child: every import
// call travels the ring and dispatches through the M7 ApiRegistry on the
// parent side, exactly like the deterministic backend's bridge.
#include "xbox2pc/execution_engine.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#if defined(__linux__) && defined(__x86_64__)
#include <csignal>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "xbox2pc/native_child.hpp"
#include "xbox2pc/native_ipc.hpp"
#endif


namespace xbox2pc::rt::exec {

namespace {
std::string hex32(std::uint32_t v) {
    static const char* d = "0123456789ABCDEF";
    std::string s = "00000000";
    for (int i = 7; i >= 0; --i) {
        s[static_cast<std::size_t>(i)] = d[v & 0xF];
        v >>= 4;
    }
    return s;
}

// Acquire-load of the ring's published request sequence.
std::uint64_t ring_req_seq(native::ImportRing* ring) {
    return __atomic_load_n(const_cast<const std::uint64_t*>(&ring->page()->req_seq),
                           __ATOMIC_ACQUIRE);
}
}  // namespace

NativeExecutionBackend::NativeExecutionBackend(api::ApiRegistry& registry,
                                               std::chrono::milliseconds timeout)
    : registry_(registry), timeout_(timeout) {
    if (timeout_.count() <= 0) timeout_ = std::chrono::milliseconds(1000);
}

Result<void> NativeExecutionBackend::bind_execution_context(
    std::uint64_t process_id, std::uint64_t thread_id, AddressSpace& space) {
    return bind_execution_context(process_id, thread_id, space, nullptr);
}

Result<void> NativeExecutionBackend::bind_execution_context(
    std::uint64_t process_id, std::uint64_t thread_id, AddressSpace& space,
    GuestThreadEnvironment* thread_environment) {
    if (process_id == 0 || thread_id == 0)
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "native guest process and thread identities must be nonzero");
    space_ = &space;
    pid_ = process_id;
    tid_ = thread_id;
    thread_environment_ = thread_environment;
    return Result<void>::ok_result();
}

ExecutionResult NativeExecutionBackend::run(
    const ExecutionRequest& req, cpu::CpuState& io_cpu,
    const std::atomic<bool>& interrupted) {
    ExecutionResult result;
    result.cpu.state = io_cpu;
    result.final_rip = io_cpu.rip;
    auto fail = [&](GuestFault fault, const std::string& detail,
                   Recoverability rec = Recoverability::Fatal) {
        result.outcome = Outcome::Faulted;
        GuestException exception;
        exception.fault = fault;
        exception.rip = req.entry_va;
        exception.access = AccessType::Execute;
        exception.fault_address = 0;
        exception.process_id = pid_;
        exception.thread_id = tid_;
        exception.recoverability = rec;
        exception.detail = detail;
        result.exception = std::move(exception);
        result.cpu.state = io_cpu;
        return result;
    };
    if (space_ == nullptr || pid_ == 0 || tid_ == 0)
        return fail(GuestFault::InvalidState, "native execution context is not bound");
    if (req.entry_va == 0)
        return fail(GuestFault::InvalidState, "native entry VA is null");
    if (req.entry_args.size() > 4 ||
        req.entry_args.size() != req.entry_spec.args.size() ||
        req.entry_spec.varargs ||
        (req.entry_spec.ret != abi::CallSpec::ReturnKind::Void &&
         req.entry_spec.ret != abi::CallSpec::ReturnKind::Int))
        return fail(GuestFault::UnsupportedInstruction,
                    "native slice accepts at most four integer-like register arguments and integer/void returns");
    for (std::size_t i = 0; i < req.entry_args.size(); ++i) {
        const auto kind = req.entry_spec.args[i].kind;
        if (kind != req.entry_args[i].kind ||
            (kind != abi::ArgKind::Int && kind != abi::ArgKind::Struct) ||
            (kind == abi::ArgKind::Struct &&
             req.entry_spec.args[i].struct_size != 1 &&
             req.entry_spec.args[i].struct_size != 2 &&
             req.entry_spec.args[i].struct_size != 4 &&
             req.entry_spec.args[i].struct_size != 8))
            return fail(GuestFault::UnsupportedInstruction,
                        "native slice rejects pointer, floating-point, and unsupported aggregate arguments");
    }
    if (req.control != nullptr)
        return fail(GuestFault::UnsupportedInstruction,
                    "native slice does not support cooperative execution control");
    // The child runs on a host-owned stack; guest stack state is rejected.
    if (req.stack_top_va != 0 || req.stack_size != 0)
        return fail(GuestFault::UnsupportedInstruction,
                    "native slice does not install a guest stack");
    if (interrupted.load(std::memory_order_acquire)) {
        result.outcome = Outcome::Interrupted;
        return result;
    }
    // Import table consistency: IAT VAs (when present) must be 1:1 with
    // the binding identities.
    if (!req.api_iat_vas.empty() &&
        req.api_iat_vas.size() != req.api_bindings.size())
        return fail(GuestFault::InvalidState,
                    "native import IAT vector does not match the binding vector");
#if defined(__linux__) && defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    guest::GuestMemory memory(*space_);
    if (!memory.validate_exec(req.entry_va).ok())
        return fail(GuestFault::PermissionExec, "native entry is not executable guest memory");
    auto host_entry = space_->translate(req.entry_va);
    if (!host_entry.ok())
        return fail(GuestFault::InvalidAccess,
                    "native entry has no committed host backing: " + host_entry.error_string());

    // ── Phase 5: imports are supported through the ring ────────────────
    const bool has_imports = !req.api_bindings.empty();
    // Pre-fork validation of every IAT VA (child stores must be safe).
    if (has_imports) {
        for (std::size_t i = 0; i < req.api_bindings.size(); ++i) {
            const auto& binding = req.api_bindings[i];
            if (binding.value == 0) continue;
            const std::uint64_t iat_va =
                i < req.api_iat_vas.size() ? req.api_iat_vas[i] : 0;
            if (iat_va == 0) continue;
            // The slot must be writable guest memory (the child rewrites it).
            if (!memory.validate(iat_va, 8, true, false).ok())
                return fail(GuestFault::InvalidAccess,
                            "native import IAT slot is not writable guest memory");
            // And the bound descriptor must exist parent-side (the ring
            // dispatch needs a plan).
            const auto* descriptor = binding.by_ordinal
                ? registry_.find_ordinal(binding.library, binding.ordinal)
                : registry_.find(binding.library, binding.export_name);
            if (descriptor == nullptr)
                return fail(GuestFault::MarshalFailure,
                            "native import has no verified descriptor: " +
                                binding.library + "!" + binding.export_name);
            auto plan = plan_for_descriptor(*descriptor);
            if (!plan.ok())
                return fail(GuestFault::MarshalFailure,
                            "native import marshalling plan unavailable: " +
                                plan.error_string());
        }
    }

    // TEB: resolve the host address once (child installs it as GS).
    std::uint64_t teb_host = 0;
    if (req.guest_teb_va != 0) {
        auto t = space_->translate(req.guest_teb_va);
        if (!t.ok())
            return fail(GuestFault::InvalidAccess,
                        "native TEB has no committed host backing");
        teb_host = reinterpret_cast<std::uint64_t>(t.value());
    }

    // Thunk page: mapped at the fixed synthetic binding VA so guest
    // call-through-IAT lands on thunks. Parent maps it before the fork;
    // the child inherits the mapping.
    void* thunk_host = nullptr;
    if (has_imports) {
        thunk_host = ::mmap(reinterpret_cast<void*>(native::kThunkPageBase), 4096,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (thunk_host == MAP_FAILED)
            return fail(GuestFault::Internal,
                        std::string("native thunk page mapping failed: ") +
                            std::strerror(errno));
    }

    // The ring (freed by scope exit on the parent side; the child only
    // touches the raw page + fds).
    std::unique_ptr<native::ImportRing> ring(native::ImportRing::create());
    if (ring == nullptr) {
        if (thunk_host != nullptr) ::munmap(thunk_host, 4096);
        return fail(GuestFault::Internal, "native import ring allocation failed");
    }

    // Import thunk table (inherited by the child as plain data).
    auto imports = std::make_unique<native::ImportThunkTable>();
    if (has_imports) {
        imports->count = static_cast<std::uint32_t>(req.api_bindings.size());
        for (std::size_t i = 0; i < req.api_bindings.size() &&
                               i < native::kMaxThunkImports; ++i) {
            imports->iat_vas[i] =
                i < req.api_iat_vas.size() ? req.api_iat_vas[i] : 0;
            imports->iat_values[i] = req.api_bindings[i].value;
        }
    }

    native::ChildRunState child_state;
    child_state.ring = ring.get();
    child_state.imports = imports.get();
    child_state.teb_host = teb_host;

    // Result pipe: the child's final RAX travels as 8 bytes (the ring
    // carries import-call replies; the entry return value has its own
    // documented channel, unchanged from M11.5).
    int result_pipe[2] = {-1, -1};
    if (::pipe(result_pipe) != 0) {
        if (thunk_host != nullptr) ::munmap(thunk_host, 4096);
        return fail(GuestFault::Internal,
                    std::string("native result pipe creation failed: ") + std::strerror(errno));
    }
    const pid_t child = ::fork();
    if (child < 0) {
        const int saved_errno = errno;
        ::close(result_pipe[0]); ::close(result_pipe[1]);
        if (thunk_host != nullptr) ::munmap(thunk_host, 4096);
        return fail(GuestFault::Internal,
                    std::string("native child creation failed: ") + std::strerror(saved_errno));
    }
    if (child == 0) {
        // ── child: everything after here must be async-signal-safe ──
        if (thunk_host != nullptr &&
            !native::child_write_thunks(thunk_host, imports->count))
            ::_exit(122);
        if (teb_host != 0 && !native::child_install_gs(teb_host))
            ::_exit(121);
        if (has_imports && !native::child_patch_iats(*imports))
            ::_exit(120);
        native::child_install_traps(&child_state);
        std::array<std::uint64_t, 4> arguments{};
        const std::array<cpu::Gpr, 4> argument_registers = {
            cpu::Gpr::Rcx, cpu::Gpr::Rdx, cpu::Gpr::R8, cpu::Gpr::R9};
        for (std::size_t i = 0; i < req.entry_args.size(); ++i)
            arguments[i] = io_cpu.reg(argument_registers[i]);
        const std::uint64_t value = native::child_invoke_entry(
            host_entry.value(), arguments[0], arguments[1], arguments[2], arguments[3]);
        ::close(result_pipe[0]);
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value);
        std::size_t written = 0;
        while (written < sizeof(value)) {
            const auto count = ::write(result_pipe[1], bytes + written, sizeof(value) - written);
            if (count < 0) { if (errno == EINTR) continue; ::_exit(126); }
            if (count == 0) ::_exit(126);
            written += static_cast<std::size_t>(count);
        }
        ::_exit(0);
    }

    ::close(result_pipe[1]);

    // ── parent: serve the ring until the child exits ────────────────────
    // Close the child's view of the parent-side fds? Both sides share the
    // same descriptors after fork — the parent keeps both doorbells open
    // and the child's exit is detected through waitpid, not EPIPE.
    std::uint64_t served = 0;
    bool child_exited = false;
    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() + timeout_;
    bool timed_out = false, was_interrupted = false;

    while (!child_exited && !timed_out && !was_interrupted) {
        // Non-blocking reap first (avoids classifying a just-returned
        // child as timed out).
        const pid_t waited = ::waitpid(child, &status, WNOHANG);
        if (waited == child) {
            child_exited = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            (void)::kill(child, SIGKILL);
            while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            ::close(result_pipe[0]);
            if (thunk_host != nullptr) ::munmap(thunk_host, 4096);
            return fail(GuestFault::Internal,
                        std::string("native child wait failed: ") + std::strerror(errno));
        }

        // Serve pending ring requests (poll without blocking when the
        // child already exited or a deadline looms).
        bool served_any = false;
        while (served < ring_req_seq(ring.get())) {
            native::RequestSlot request{};
            if (!ring->parent_wait_request(&served, request)) break;
            ++result.api_calls;
            native::ReplySlot reply{};
            if (request.call_class ==
                static_cast<std::uint32_t>(native::CallClass::ExitProcess)) {
                reply.status = static_cast<std::uint32_t>(native::ReplyStatus::Ok);
                reply.exit_code = static_cast<std::uint32_t>(request.args[0]);
                ring->parent_reply(served - 1, reply);
                // The child _exits right after the reply; fall through to
                // the reap loop.
                served_any = true;
                break;
            }
            // API_CALL: resolve the binding, plan, dispatch.
            if (request.api_index >= req.api_bindings.size()) {
                reply.status = static_cast<std::uint32_t>(native::ReplyStatus::UnknownApi);
                ring->parent_reply(served - 1, reply);
                served_any = true;
                continue;
            }
            const auto& binding = req.api_bindings[request.api_index];
            const auto* descriptor = binding.by_ordinal
                ? registry_.find_ordinal(binding.library, binding.ordinal)
                : registry_.find(binding.library, binding.export_name);
            if (descriptor == nullptr) {
                reply.status = static_cast<std::uint32_t>(native::ReplyStatus::UnknownApi);
                ring->parent_reply(served - 1, reply);
                served_any = true;
                continue;
            }
            auto plan = plan_for_descriptor(*descriptor);
            if (!plan.ok()) {
                reply.status = static_cast<std::uint32_t>(native::ReplyStatus::Rejected);
                ring->parent_reply(served - 1, reply);
                served_any = true;
                continue;
            }
            // Build a scratch CPU state with the wire args in the ABI
            // register slots and marshal through the SAME bridge used by
            // the deterministic engine (validation + dispatch + return).
            cpu::CpuState call_cpu;
            call_cpu.reset();
            call_cpu.set_reg(cpu::Gpr::Rcx, request.args[0]);
            call_cpu.set_reg(cpu::Gpr::Rdx, request.args[1]);
            call_cpu.set_reg(cpu::Gpr::R8, request.args[2]);
            call_cpu.set_reg(cpu::Gpr::R9, request.args[3]);
            const auto dispatched = marshal_and_dispatch(
                call_cpu, memory, registry_, plan.value(), pid_, 0, 64, tid_,
                {}, thread_environment_, {});
            if (!dispatched.ok()) {
                reply.status = static_cast<std::uint32_t>(native::ReplyStatus::Rejected);
                ring->parent_reply(served - 1, reply);
                served_any = true;
                continue;
            }
            const auto& api_res = dispatched.value().api_result;
            if (api_res.raise_guest_exception) {
                // Phase-1 unwind result (same contract as the
                // deterministic backend): report and stop the run.
                ring->parent_reply(served - 1,
                                   {static_cast<std::uint32_t>(native::ReplyStatus::Fatal),
                                    0, 0, {0, 0, 0, 0}});
                served_any = true;
                (void)::kill(child, SIGKILL);
                while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
                child_exited = true;
                if (thunk_host != nullptr) ::munmap(thunk_host, 4096);
                return fail(GuestFault::MarshalFailure,
                            "guest exception 0x" + hex32(api_res.exception_code) +
                                " raised under native import dispatch (phase-1 search only)");
            }
            reply.status = static_cast<std::uint32_t>(native::ReplyStatus::Ok);
            reply.rax = call_cpu.reg(cpu::Gpr::Rax);
            ring->parent_reply(served - 1, reply);
            served_any = true;
        }

        if (child_exited) break;
        if (interrupted.load(std::memory_order_acquire)) {
            was_interrupted = true;
            (void)::kill(child, SIGKILL);
            continue;
        }
        if (std::chrono::steady_clock::now() >= deadline && !served_any) {
            timed_out = true;
            (void)::kill(child, SIGKILL);
            continue;
        }
        if (!served_any) {
            // Nothing pending: wait for a doorbell token or child exit
            // with a small sleep so the reap path stays live.
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    if (!child_exited) {
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    ring->parent_drain();
    if (thunk_host != nullptr) ::munmap(thunk_host, 4096);
    // Read the child's final RAX (best effort: a killed or crashed child
    // leaves none — the callers classify by exit status below).
    std::uint64_t return_value = 0;
    bool have_return = false;
    {
        std::uint8_t buf[8];
        std::size_t got = 0;
        while (got < sizeof(buf)) {
            const auto n = ::read(result_pipe[0], buf + got, sizeof(buf) - got);
            if (n < 0) { if (errno == EINTR) continue; break; }
            if (n == 0) break;
            got += static_cast<std::size_t>(n);
        }
        if (got == sizeof(buf)) {
            std::memcpy(&return_value, buf, sizeof(buf));
            have_return = true;
        }
        ::close(result_pipe[0]);
    }

    if (was_interrupted) {
        ::close(result_pipe[0]);
        result.outcome = Outcome::Interrupted;
        return result;
    }
    if (timed_out) {
        ::close(result_pipe[0]);
        return fail(GuestFault::BudgetExceeded,
                    "native guest entry exceeded its child-process time limit");
    }

    // ── classify the child's exit ───────────────────────────────────────
    if (WIFEXITED(status)) {
        const int code = WEXITSTATUS(status);
        if (code == 0) {
            // Normal return: RAX traveled the result pipe.
            const std::uint64_t value =
                have_return && req.entry_spec.ret != abi::CallSpec::ReturnKind::Void
                    ? return_value : 0;
            io_cpu.set_reg(cpu::Gpr::Rax, value);
            io_cpu.rip = req.completion_va != 0 ? req.completion_va : req.entry_va;
            result.outcome = Outcome::Returned;
            result.return_value = value;
            result.final_rip = io_cpu.rip;
            result.cpu.state = io_cpu;
            return result;
        }
        // ExitProcess path: the exit code is the guest's process code.
        // The ring already observed the ExitProcess call (api_calls>0).
        io_cpu.set_reg(cpu::Gpr::Rax, static_cast<std::uint64_t>(code));
        io_cpu.rip = req.completion_va != 0 ? req.completion_va : req.entry_va;
        result.outcome = Outcome::Returned;
        result.return_value = static_cast<std::uint64_t>(code);
        result.final_rip = io_cpu.rip;
        result.cpu.state = io_cpu;
        return result;
    }
    if (WIFSIGNALED(status)) {
        const int signal = WTERMSIG(status);
        GuestFault fault = GuestFault::Internal;
        if (signal == SIGSEGV || signal == SIGBUS) fault = GuestFault::InvalidAccess;
        else if (signal == SIGILL) fault = GuestFault::InvalidInstruction;
        else if (signal == SIGFPE) fault = GuestFault::DivideError;
        else if (signal == SIGKILL) fault = GuestFault::GuestTerminated;
        return fail(fault, "native guest child terminated by host signal " +
                              std::to_string(signal) +
                              " (host fault address is not a guest VA)");
    }
    return fail(GuestFault::Internal, "native guest child exited in an unclassifiable state");
#else
    return fail(GuestFault::UnsupportedInstruction,
                "native-host execution is currently implemented only for x86-64 Linux GCC/Clang");
#endif
}

Result<std::uint64_t> NativeExecutionBackend::single_step(
    cpu::CpuState& io_cpu, const ExecutionRequest& req) {
    (void)io_cpu; (void)req;
    return Result<std::uint64_t>(RuntimeErrc::PlatformUnsupported,
                                 "native-host execution does not support single-step");
}
}  // namespace xbox2pc::rt::exec
