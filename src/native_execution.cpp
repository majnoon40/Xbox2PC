// native_execution.cpp — narrow x86-64 Linux native-host execution path.
#include "xbox2pc/execution_engine.hpp"
#include <array>
#include <cerrno>
#include <cstring>
#include <string>
#include <thread>
#if defined(__linux__) && defined(__x86_64__)
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
namespace xbox2pc::rt::exec {
NativeExecutionBackend::NativeExecutionBackend(std::chrono::milliseconds timeout)
    : timeout_(timeout) {
    if (timeout_.count() <= 0) timeout_ = std::chrono::milliseconds(1000);
}
Result<void> NativeExecutionBackend::bind_execution_context(
    std::uint64_t process_id, std::uint64_t thread_id, AddressSpace& space) {
    return bind_execution_context(process_id, thread_id, space, nullptr);
}
Result<void> NativeExecutionBackend::bind_execution_context(
    std::uint64_t process_id, std::uint64_t thread_id, AddressSpace& space,
    GuestThreadEnvironment* thread_environment) {
    (void)thread_environment;
    if (process_id == 0 || thread_id == 0)
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "native guest process and thread identities must be nonzero");
    space_ = &space;
    pid_ = process_id;
    tid_ = thread_id;
    return Result<void>::ok_result();
}
ExecutionResult NativeExecutionBackend::run(
    const ExecutionRequest& req, cpu::CpuState& io_cpu,
    const std::atomic<bool>& interrupted) {
    ExecutionResult result;
    result.cpu.state = io_cpu;
    result.final_rip = io_cpu.rip;
    auto fail = [&](GuestFault fault, std::string detail) {
        result.outcome = Outcome::Faulted;
        GuestException exception;
        exception.fault = fault;
        exception.rip = req.entry_va;
        exception.access = AccessType::Execute;
        exception.fault_address = 0;
        exception.process_id = pid_;
        exception.thread_id = tid_;
        exception.recoverability = Recoverability::Fatal;
        exception.detail = std::move(detail);
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
    if (!req.api_bindings.empty() || !req.api_binding_values.empty() ||
        req.control != nullptr)
        return fail(GuestFault::UnsupportedInstruction,
                    "native slice does not yet support imports or cooperative execution control");
    if (interrupted.load(std::memory_order_acquire)) {
        result.outcome = Outcome::Interrupted;
        return result;
    }
#if defined(__linux__) && defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    guest::GuestMemory memory(*space_);
    if (!memory.validate_exec(req.entry_va).ok())
        return fail(GuestFault::PermissionExec, "native entry is not executable guest memory");
    auto host_entry = space_->translate(req.entry_va);
    if (!host_entry.ok())
        return fail(GuestFault::InvalidAccess,
                    "native entry has no committed host backing: " + host_entry.error_string());
    int pipe_fds[2] = {-1, -1};
    if (::pipe(pipe_fds) != 0)
        return fail(GuestFault::Internal,
                    std::string("native result pipe creation failed: ") + std::strerror(errno));
    const pid_t child = ::fork();
    if (child < 0) {
        const int saved_errno = errno;
        ::close(pipe_fds[0]); ::close(pipe_fds[1]);
        return fail(GuestFault::Internal,
                    std::string("native child creation failed: ") + std::strerror(saved_errno));
    }
    if (child == 0) {
        ::close(pipe_fds[0]);
        using GuestEntry = std::uint64_t (__attribute__((ms_abi)) *)(
            std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
        const auto entry = reinterpret_cast<GuestEntry>(host_entry.value());
        const std::array<cpu::Gpr, 4> argument_registers = {
            cpu::Gpr::Rcx, cpu::Gpr::Rdx, cpu::Gpr::R8, cpu::Gpr::R9};
        std::array<std::uint64_t, 4> arguments{};
        for (std::size_t i = 0; i < req.entry_args.size(); ++i)
            arguments[i] = io_cpu.reg(argument_registers[i]);
        const std::uint64_t value = entry(
            arguments[0], arguments[1], arguments[2], arguments[3]);
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value);
        std::size_t written = 0;
        while (written < sizeof(value)) {
            const auto count = ::write(pipe_fds[1], bytes + written, sizeof(value) - written);
            if (count < 0) { if (errno == EINTR) continue; ::_exit(126); }
            if (count == 0) ::_exit(126);
            written += static_cast<std::size_t>(count);
        }
        ::_exit(0);
    }
    ::close(pipe_fds[1]);
    int status = 0;
    const auto deadline = std::chrono::steady_clock::now() + timeout_;
    bool reaped = false, timed_out = false, was_interrupted = false;
    while (!reaped) {
        // Observe completion before applying the deadline/cancellation. This
        // avoids classifying a child that just returned as timed out.
        const pid_t waited = ::waitpid(child, &status, WNOHANG);
        if (waited == child) { reaped = true; break; }
        if (waited < 0 && errno != EINTR) {
            const int saved_errno = errno;
            (void)::kill(child, SIGKILL);
            while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            ::close(pipe_fds[0]);
            return fail(GuestFault::Internal,
                        std::string("native child wait failed: ") + std::strerror(saved_errno));
        }
        if (interrupted.load(std::memory_order_acquire)) {
            was_interrupted = true;
            (void)::kill(child, SIGKILL);
        } else if (std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            (void)::kill(child, SIGKILL);
        }
        if (timed_out || was_interrupted) {
            while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            reaped = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (was_interrupted) { ::close(pipe_fds[0]); result.outcome = Outcome::Interrupted; return result; }
    if (timed_out) { ::close(pipe_fds[0]); return fail(GuestFault::BudgetExceeded, "native guest entry exceeded its child-process time limit"); }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        ::close(pipe_fds[0]);
        if (WIFSIGNALED(status)) {
            const int signal = WTERMSIG(status);
            GuestFault fault = GuestFault::Internal;
            if (signal == SIGSEGV || signal == SIGBUS) fault = GuestFault::InvalidAccess;
            else if (signal == SIGILL) fault = GuestFault::InvalidInstruction;
            else if (signal == SIGFPE) fault = GuestFault::DivideError;
            return fail(fault, "native guest child terminated by host signal " +
                              std::to_string(signal) + " (host fault address is not a guest VA)");
        }
        return fail(GuestFault::Internal, "native guest child exited without a successful result");
    }
    std::uint64_t return_value = 0;
    auto* output = reinterpret_cast<std::uint8_t*>(&return_value);
    std::size_t received = 0;
    while (received < sizeof(return_value)) {
        const auto count = ::read(pipe_fds[0], output + received, sizeof(return_value) - received);
        if (count < 0) {
            if (errno == EINTR) continue;
            const int saved_errno = errno; ::close(pipe_fds[0]);
            return fail(GuestFault::Internal,
                        std::string("native result read failed: ") + std::strerror(saved_errno));
        }
        if (count == 0) break;
        received += static_cast<std::size_t>(count);
    }
    ::close(pipe_fds[0]);
    if (received != sizeof(return_value))
        return fail(GuestFault::Internal, "native guest child returned no complete RAX result");
    io_cpu.set_reg(cpu::Gpr::Rax, req.entry_spec.ret == abi::CallSpec::ReturnKind::Void ? 0 : return_value);
    io_cpu.rip = req.completion_va != 0 ? req.completion_va : req.entry_va;
    result.outcome = Outcome::Returned;
    result.return_value = req.entry_spec.ret == abi::CallSpec::ReturnKind::Void ? 0 : return_value;
    result.final_rip = io_cpu.rip;
    result.cpu.state = io_cpu;
    result.instructions_executed = 0;
    return result;
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
