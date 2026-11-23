// xbox2pc/src/execution_engine.cpp — M8 deterministic backend + bridge.
//
// Sections:
//   1. names + config validation
//   2. the interpreter loop (documented instruction subset)
//   3. the marshalling bridge (ABI extract -> validate -> dispatch ->
//      write back)
//   4. plan_for_descriptor (documented-signature-driven plans)

#include "xbox2pc/execution_engine.hpp"
#include "xbox2pc/x86_interpreter.hpp"

#include <algorithm>
#include <cstring>

namespace xbox2pc::rt::exec {

using cpu::CpuState;
using cpu::Gpr;
using guest::GuestMemory;
namespace x86 = xbox2pc::rt::x86;

// ── 1. names + config ─────────────────────────────────────────────────────

const char* outcome_to_name(Outcome o) {
    switch (o) {
        case Outcome::Completed: return "completed";
        case Outcome::Returned: return "returned";
        case Outcome::Interrupted: return "interrupted";
        case Outcome::Terminated: return "terminated";
        case Outcome::Faulted: return "faulted";
    }
    return "?";
}

Result<void> ExecutionConfig::validate() const {
    if (max_stack_bytes == 0 || max_stack_bytes > (1ull << 30)) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "max_stack_bytes out of range");
    }
    if ((max_stack_bytes & 0xF) != 0) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "max_stack_bytes not 16-aligned");
    }
    if (max_contexts == 0 || max_contexts > 4096) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "max_contexts out of range");
    }
    if (max_tls_callbacks == 0 || max_tls_callbacks > 1024) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "max_tls_callbacks out of range");
    }
    if (max_dispatch_depth == 0 || max_dispatch_depth > 1024) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "max_dispatch_depth out of range");
    }
    if (max_guest_op_bytes == 0 ||
        max_guest_op_bytes > guest::kMaxGuestOpBytes) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "max_guest_op_bytes out of range");
    }
    if (max_diagnostic_bytes == 0 || max_diagnostic_bytes > 65536) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "max_diagnostic_bytes out of range");
    }
    return Result<void>::ok_result();
}

Result<ExecutionConfig> ExecutionConfig::default_validated() {
    ExecutionConfig cfg;
    auto r = cfg.validate();
    if (!r.ok()) return Result<ExecutionConfig>(r.errc(), r.context());
    return Result<ExecutionConfig>(cfg);
}

// ── 2. the interpreter ────────────────────────────────────────────────────

namespace {

// 64-bit GP register file index (0..15).
inline std::uint64_t rg(const CpuState& c, std::uint8_t r) {
    return c.gprs[r & 0xF];
}
inline void set_rg(CpuState& c, std::uint8_t r, std::uint64_t v) {
    c.gprs[r & 0xF] = v;
}

// ModRM decode for the subset: only [reg + disp8] and reg forms.
struct ModRM {
    std::uint8_t mod;   // 0: [reg], 1: reg, 2: [reg+disp8] — subset uses
                        // mod=2 (disp8) for memory and mod=3 for reg.
    std::uint8_t reg;  // reg field
    std::uint8_t rm;   // rm field
};
inline ModRM decode_modrm(std::uint8_t b) {
    return ModRM{static_cast<std::uint8_t>((b >> 6) & 3),
                 static_cast<std::uint8_t>((b >> 3) & 7),
                 static_cast<std::uint8_t>(b & 7)};
}

bool fault(GuestFault f, const CpuState& cpu, AccessType a,
           std::uint64_t addr, std::uint64_t pid, std::uint64_t tid,
           Recoverability rec, std::string detail,
           std::optional<GuestException>& out) {
    GuestException e;
    e.fault = f;
    e.rip = cpu.rip;
    e.access = a;
    e.fault_address = addr;
    e.process_id = pid;
    e.thread_id = tid;
    e.recoverability = rec;
    e.detail = std::move(detail);
    out = e;
    return false;
}

}  // namespace

struct DeterministicBackend::Impl {
    std::uint32_t dispatch_depth = 0;
};

DeterministicBackend::DeterministicBackend(api::ApiRegistry& registry,
                                           ExecutionConfig cfg)
    : impl_(std::make_unique<Impl>()), registry_(registry), cfg_(cfg) {}

DeterministicBackend::~DeterministicBackend() = default;

// ── run ────────────────────────────────────────────────────────────────────

ExecutionResult DeterministicBackend::run(
    const ExecutionRequest& req, CpuState& io_cpu,
    const std::atomic<bool>& interrupted) {
    ExecutionResult res;
    res.cpu.state = io_cpu;
    if (mem_ == nullptr) {
        fault(GuestFault::InvalidState, io_cpu, AccessType::None, 0, pid_,
              tid_, Recoverability::Fatal, "engine has no bound guest memory",
              res.exception);
        res.outcome = Outcome::Faulted;
        return res;
    }
    const auto cfg_ok = cfg_.validate();
    if (!cfg_ok.ok()) {
        fault(GuestFault::InvalidState, io_cpu, AccessType::None, 0, pid_,
              tid_, Recoverability::Fatal, "engine config invalid",
              res.exception);
        res.outcome = Outcome::Faulted;
        return res;
    }
    const std::uint64_t stack_floor = req.stack_top_va >= req.stack_size
                                          ? req.stack_top_va - req.stack_size
                                          : 4096;
    GuestMemory& mem = *mem_;
    std::uint64_t budget = cfg_.max_instructions;
    std::uint64_t executed = 0;

    while (true) {
        // Cancellation is observable between instructions.
        if (interrupted.load()) {
            res.outcome = Outcome::Interrupted;
            break;
        }
        ++executed;   // this iteration executes exactly one instruction
        if (budget != 0 && executed > budget) {
            fault(GuestFault::BudgetExceeded, io_cpu, AccessType::None, 0,
                  pid_, tid_, Recoverability::Recoverable,
                  "instruction budget exhausted", res.exception);
            res.outcome = Outcome::Faulted;
            break;
        }

        const std::uint64_t rip = io_cpu.rip;

        // Imported-API entry: resolve the exact import identity captured
        // by ExecutionContext from the loader diagnostics, then marshal
        // through the same GuestMemory + ApiRegistry path used by tests.
        if (is_api_binding(rip)) {
            const auto matches = static_cast<std::size_t>(std::count_if(
                req.api_bindings.begin(), req.api_bindings.end(),
                [rip](const ApiBindingInfo& item) { return item.value == rip; }));
            const auto binding = std::find_if(
                req.api_bindings.begin(), req.api_bindings.end(),
                [rip](const ApiBindingInfo& item) { return item.value == rip; });
            if (matches != 1 || binding == req.api_bindings.end()) {
                fault(GuestFault::InvalidState, io_cpu, AccessType::None, rip,
                      pid_, tid_, Recoverability::Fatal,
                      matches == 0
                          ? "API binding has no matching resolved import identity"
                          : "API binding has ambiguous duplicate import identities",
                      res.exception);
                res.outcome = Outcome::Faulted;
                break;
            }

            const auto* descriptor = binding->by_ordinal
                ? registry_.find_ordinal(binding->library, binding->ordinal)
                : registry_.find(binding->library, binding->export_name);
            if (descriptor == nullptr) {
                fault(GuestFault::MarshalFailure, io_cpu, AccessType::None, rip,
                      pid_, tid_, Recoverability::Fatal,
                      "resolved API import no longer has a verified descriptor",
                      res.exception);
                res.outcome = Outcome::Faulted;
                break;
            }
            auto plan = plan_for_descriptor(*descriptor);
            if (!plan.ok()) {
                fault(GuestFault::MarshalFailure, io_cpu, AccessType::None, rip,
                      pid_, tid_, Recoverability::Fatal,
                      "API marshalling plan unavailable: " + plan.error_string(),
                      res.exception);
                res.outcome = Outcome::Faulted;
                break;
            }

            const auto rsp = rg(io_cpu, static_cast<std::uint8_t>(Gpr::Sp));
            auto return_address = mem.read_u64(rsp);
            if (!return_address.ok()) {
                fault(GuestFault::InvalidAccess, io_cpu, AccessType::Read, rsp,
                      pid_, tid_, Recoverability::Fatal,
                      "API call return address is unreadable",
                      res.exception);
                res.outcome = Outcome::Faulted;
                break;
            }
            const auto return_valid = mem.validate_exec(return_address.value());
            if (!return_valid.ok()) {
                const auto kind = return_valid.err == guest::GuestMemErrc::PermissionDenied
                    ? GuestFault::PermissionExec : GuestFault::InvalidAccess;
                fault(kind, io_cpu, AccessType::Execute, return_address.value(),
                      pid_, tid_, Recoverability::Fatal,
                      "API call return address is not executable",
                      res.exception);
                res.outcome = Outcome::Faulted;
                break;
            }

            const auto depth = impl_->dispatch_depth;
            ++impl_->dispatch_depth;
            auto dispatched = marshal_and_dispatch(
                io_cpu, mem, registry_, plan.value(), pid_, depth,
                cfg_.max_dispatch_depth, tid_);
            --impl_->dispatch_depth;
            if (!dispatched.ok()) {
                fault(GuestFault::MarshalFailure, io_cpu, AccessType::None, rip,
                      pid_, tid_, Recoverability::Fatal,
                      "API marshalling/dispatch failed: " + dispatched.error_string(),
                      res.exception);
                res.outcome = Outcome::Faulted;
                break;
            }
            if (!dispatched.value().dispatched || !dispatched.value().api_result.ok) {
                const auto detail = dispatched.value().api_result.error.empty()
                    ? std::string("API implementation rejected the call")
                    : dispatched.value().api_result.error;
                fault(GuestFault::MarshalFailure, io_cpu, AccessType::None, rip,
                      pid_, tid_, Recoverability::Fatal, detail, res.exception);
                res.outcome = Outcome::Faulted;
                break;
            }

            io_cpu.rip = return_address.value();
            ++res.api_calls;
            continue;
        }

        // Completion sentinel check happens on RET target (below).

        // ── M9 engine core: structured decode + semantics step ────────
        //
        // The M8 byte-at-a-time switch is replaced by the shared decoder
        // (xbox2pc_rt_x64_decoder) + the semantics engine
        // (xbox2pc_rt_x86_interpreter). The M8 contract is preserved:
        //   - budget / cancellation between instructions,
        //   - the completion sentinel on RET targets (Returned + RAX),
        //   - the stack floor for CALL/PUSH (checked before the step),
        //   - API-binding landing values enter the marshalling bridge.
        // Completion-sentinel pre-check: a RET (C3) at RIP would pop the
        // sentinel from the stack — the semantics layer would fault the
        // non-executable target, so the ENGINE handles the entry-return
        // contract itself: peek [RSP]; if it equals the completion VA,
        // execute the RET semantics (pop + optional imm16) and complete.
        if (req.completion_va != 0) {
            auto opcode_b = mem.read_u8(io_cpu.rip);
            if (opcode_b.ok() &&
                (opcode_b.value() == 0xC3 || opcode_b.value() == 0xC2)) {
                const std::uint64_t sp0 =
                    rg(io_cpu, static_cast<std::uint8_t>(Gpr::Sp));
                auto target = mem.read_u64(sp0);
                std::uint64_t extra = 0;
                if (opcode_b.value() == 0xC2) {
                    auto imm_lo = mem.read_u8(io_cpu.rip + 1);
                    auto imm_hi = mem.read_u8(io_cpu.rip + 2);
                    if (!imm_lo.ok() || !imm_hi.ok()) {
                        extra = ~0ull;  // incomplete RET imm16 must not complete
                    } else {
                        extra = static_cast<std::uint64_t>(imm_lo.value()) |
                                (static_cast<std::uint64_t>(imm_hi.value()) << 8);
                    }
                }
                if (target.ok() && target.value() == req.completion_va &&
                    extra <= 0xFFFFull && sp0 <= (~0ull) - (8 + extra)) {
                    io_cpu.set_reg(Gpr::Sp, sp0 + 8 + extra);
                    res.outcome = Outcome::Returned;
                    res.return_value =
                        rg(io_cpu, static_cast<std::uint8_t>(Gpr::Rax));
                    break;
                }
            }
        }

        x86::Interpreter sem(io_cpu, mem);
        auto step_res = sem.step_at_rip();
        if (!step_res.ok()) {
            const auto& f = step_res.fault();
            fault(f.fault, io_cpu, AccessType::Execute, f.fault_rip, pid_, tid_,
                  Recoverability::Recoverable,
                  "step: " + f.detail, res.exception);
            res.outcome = Outcome::Faulted;
            break;
        }
        // Post-step contract checks (stack floor + completion).
        const std::uint64_t sp = rg(io_cpu, static_cast<std::uint8_t>(Gpr::Sp));
        if (sp < stack_floor) {
            fault(GuestFault::StackOverflow, io_cpu, AccessType::Write, sp,
                  pid_, tid_, Recoverability::Fatal,
                  "RSP fell below the stack floor", res.exception);
            res.outcome = Outcome::Faulted;
            break;
        }
        if (io_cpu.rip == req.completion_va) {
            // Executing a RET to the completion sentinel: entry-return.
            // (The interpreter faults branch targets that are not
            // executable; the sentinel is a synthesized address, so the
            // engine checks the RIP BEFORE the next fetch.)
            res.outcome = Outcome::Returned;
            res.return_value = rg(io_cpu, static_cast<std::uint8_t>(Gpr::Rax));
            break;
        }

    }
    res.instructions_executed = executed;
    res.final_rip = io_cpu.rip;
    if (res.exception.has_value()) {
        res.exception->clamp_detail(cfg_.max_diagnostic_bytes);
    }
    res.cpu.state = io_cpu;
    return res;
}

Result<std::uint64_t> DeterministicBackend::single_step(
    CpuState& io_cpu, const ExecutionRequest& req) {
    // One instruction: run with a budget of 1; map the outcome.
    std::atomic<bool> stop{false};
    ExecutionConfig one = cfg_;
    one.max_instructions = 1;
    DeterministicBackend single(registry_, one);
    if (mem_ != nullptr) {
        // Reuse our bound memory? GuestMemory is stateless over the
        // space: bind the same space.
        single.bind_space(mem_->space());
    }
    single.bind_process(pid_, tid_);
    auto res = single.run(req, io_cpu, stop);
    if (res.outcome == Outcome::Returned) {
        // The one stepped instruction was a RET to the completion
        // sentinel: the documented single-step result for it is the
        // sentinel address itself (M8 behavior preserved).
        return Result<std::uint64_t>(req.completion_va != 0
                                          ? req.completion_va
                                          : res.final_rip);
    }
    if (res.outcome == Outcome::Faulted && res.exception.has_value()) {
        if (res.exception->fault == GuestFault::BudgetExceeded) {
            // The single-step budget IS the step: one instruction ran.
            return Result<std::uint64_t>(res.final_rip);
        }
        return Result<std::uint64_t>(RuntimeErrc::PlatformError,
                                      format_exception(*res.exception));
    }
    return Result<std::uint64_t>(res.final_rip);
}

// ── 3. the marshalling bridge ─────────────────────────────────────────────

Result<MarshalResult> marshal_and_dispatch(CpuState& io_cpu,
                                          GuestMemory& mem,
                                          api::ApiRegistry& registry,
                                          const MarshalPlan& plan,
                                          std::uint64_t pid,
                                          std::uint32_t depth,
                                          std::uint32_t max_depth,
                                          std::uint64_t tid) {
    using Ret = Result<MarshalResult>;
    if (depth >= max_depth) {
        return Ret(RuntimeErrc::OutOfResources,
                   "dispatch nesting depth " + std::to_string(depth) +
                       " at the limit");
    }
    // 1. Extract arguments per the ABI (reader closure over the
    // per-call context; no global mutable state).
    struct ReaderCtx { GuestMemory* m; };
    ReaderCtx rctx{&mem};
    abi::StackReader reader;
    reader.ctx = &rctx;
    reader.read64 = [](void* c, std::uint64_t va) -> Result<std::uint64_t> {
        auto* g = static_cast<ReaderCtx*>(c)->m;
        return g->read_u64(va);
    };
    const auto args = abi::extract_args(io_cpu, plan.call, reader);
    if (!args.ok()) {
        return Ret(RuntimeErrc::InvalidArgument,
                   "argument extraction: " + args.error_string());
    }
    // 2. Build the M7 ApiContext from the values (validated pointers).
    api::ApiContext ctx;
    ctx.process_id = pid;
    ctx.thread_id = tid;
    ctx.arg_count = 0;
    for (std::size_t i = 0; i < args.value().size() &&
                            i < api::ApiContext::kMaxArgs;
         ++i) {
        const auto& a = plan.call.args[i];
        const auto& v = args.value()[i];
        switch (a.kind) {
            case abi::ArgKind::Ptr: {
                // Pointer validation happens here (readable/writable as
                // per is_out); value passes through as the raw VA.
                const auto rng = mem.validate(v.ptr_va, std::max<std::uint64_t>(a.deref_size, 1),
                                              a.is_out, false);
                if (!rng.ok() && a.deref_size != 0) {
                    return Ret(RuntimeErrc::NotFound,
                               std::string("pointer arg ") +
                                   std::to_string(i) + " invalid: " +
                                   guest::guest_mem_errc_to_name(rng.err));
                }
                ctx.args[ctx.arg_count++] = v.ptr_va;
                break;
            }
            default:
                ctx.args[ctx.arg_count++] = v.int_v;
                break;
        }
    }

    // Decode explicitly planned, bounded guest pointer arrays through GuestMemory.
    for (const auto& array : plan.pointer_array_args) {
        if (array.pointer_arg >= args.value().size() ||
            array.count_arg >= ctx.arg_count || array.element_size != sizeof(std::uint64_t) ||
            array.max_count == 0 || array.max_count > 64) {
            return Ret(RuntimeErrc::InvalidArgument, "invalid pointer-array marshalling plan");
        }
        const auto count = ctx.args[array.count_arg];
        if (count == 0 || count > array.max_count) {
            return Ret(RuntimeErrc::InvalidArgument, "guest pointer-array count is outside the supported bound");
        }
        const auto ptr = args.value()[array.pointer_arg].ptr_va;
        const auto bytes = count * array.element_size;
        const auto valid = mem.validate(ptr, bytes, false, false);
        if (!valid.ok()) return Ret(RuntimeErrc::NotFound, "guest pointer array is not readable");
        auto& values = ctx.pointer_arrays[array.pointer_arg];
        values.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t i = 0; i < count; ++i) {
            if (i > (UINT64_MAX - ptr) / array.element_size)
                return Ret(RuntimeErrc::InvalidArgument, "guest pointer-array address overflow");
            auto value = mem.read_u64(ptr + i * array.element_size);
            if (!value.ok()) return Ret(RuntimeErrc::NotFound, "guest pointer-array element is unreadable");
            values.push_back(value.value());
        }
    }

    // 3. Dispatch through M7.
    api::ApiCallResult api_res =
        registry.dispatch(plan.library, plan.export_name, ctx);

    // 4. Convert into guest return state (RAX/XMM0, RSP pop) [MS-X64CC].
    {
        // String inputs were NOT consumed by M7's context model (its
        // dispatch takes typed slots) — the bridge's documented M8 model:
        // strings are validated at extraction (readability) only.
        abi::ReturnValue rv;
        switch (plan.call.ret) {
            case abi::CallSpec::ReturnKind::Void:
                rv.kind = abi::CallSpec::ReturnKind::Void;
                break;
            case abi::CallSpec::ReturnKind::Int:
            case abi::CallSpec::ReturnKind::Hidden:
                rv.kind = abi::CallSpec::ReturnKind::Int;
                rv.int_v = api_res.return_value;
                break;
            case abi::CallSpec::ReturnKind::F32:
            case abi::CallSpec::ReturnKind::F64:
                rv.kind = abi::CallSpec::ReturnKind::F64;
                std::memcpy(&rv.f64_v, &api_res.return_value, 8);
                break;
        }
        auto wr = abi::write_return(io_cpu, plan.call, rv);
        if (!wr.ok()) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "return marshalling: " + wr.error_string());
        }
        // Out buffers: write the implementation's out payload where the
        // plan declares an out argument. M9 fix: byte-granular write of
        // out_bytes[0, out_bytes_size) (bounded by the plan's deref_size);
        // when an implementation only models a u64 slot the old u64 path
        // remains. The write respects the documented deref size.
        if (api_res.has_out) {
            for (std::uint32_t idx : plan.out_buffer_args) {
                if (idx >= args.value().size()) continue;
                const auto& spec = plan.call.args[idx];
                if (!spec.is_out || spec.deref_size == 0) continue;
                const std::uint64_t dst = args.value()[idx].ptr_va;
                if (api_res.out_bytes_size != 0) {
                    const std::size_t n = static_cast<std::size_t>(
                        std::min<std::uint64_t>(api_res.out_bytes_size,
                                                spec.deref_size));
                    auto w = mem.write(dst, api_res.out_bytes.data(), n);
                    if (!w.ok()) {
                        return Ret(RuntimeErrc::PlatformError,
                                   "out buffer write: " + w.error_string());
                    }
                } else if (spec.deref_size >= 8) {
                    // Legacy u64 out slot (M8 behavior).
                    auto w = mem.write_u64(dst, api_res.out_value);
                    if (!w.ok()) {
                        return Ret(RuntimeErrc::PlatformError,
                                   "out buffer write: " + w.error_string());
                    }
                }
                break;   // one out payload per call in the M9 model
            }
        }
    }

    MarshalResult out;
    out.dispatched = true;
    out.api_result = api_res;
    out.depth_used = depth + 1;
    return Ret(out);
}

// ── 4. plan_for_descriptor ─────────────────────────────────────────────────

Result<MarshalPlan> plan_for_descriptor(const api::ApiDescriptor& d) {
    using Ret = Result<MarshalPlan>;
    MarshalPlan plan;
    plan.library = d.library;
    plan.export_name = d.export_name;
    // Plan the call from the DOCUMENTED signature (param kinds follow
    // the signature's parameter types for the explicitly whitelisted APIs; any
    // other API yields a typed error — never guessed).
    //
    // Built-in signatures and their marshalling kinds:
    //   XGameRuntimeInitialize()                       -> no args, HRESULT
    //   XGameRuntimeUninitialize()                     -> no args, void
    //   XGameRuntimeInitializeWithOptions(ptr)         -> ptr in, HRESULT
    //   XSystemGetDeviceType()                         -> no args, enum
    //   XSystemGetConsoleId(size_t, char*, size_t*)    -> int, ptr out, ptr out
    //   XSystemGetXboxLiveSandboxId(size_t, char*, size_t*) -> same
    //   XSystemGetAppSpecificDeviceId(size_t, char*, size_t*) -> same
    //   XSystemGetRuntimeInfo()                        -> no args, struct
    //   XThreadSetTimeSensitive(bool)                  -> int, HRESULT
    //   XThreadIsTimeSensitive()                      -> no args, bool
    //   XTaskQueueCreate(mode, mode, handle*)         -> int, int, ptr out
    //   XTaskQueueDispatch(queue, port, timeout)       -> int, int, int -> bool
    //   XTaskQueueCloseHandle(queue)                   -> int, void
    //   XTaskQueueTerminate(queue, bool, ptr, ptr)     -> int, int, ptr, ptr
    //   QueryPerformanceCounter(ptr)                   -> ptr out, BOOL
    //   QueryPerformanceFrequency(ptr)                 -> ptr out, BOOL
    //   WaitForMultipleObjects(count, handles, waitAll, timeout) -> wait-any subset
    const std::string id = d.export_name;
    auto int_arg = [&] { abi::ArgSpec a; a.kind = abi::ArgKind::Int; return a; };
    auto ptr_in = [&](std::uint64_t sz) {
        abi::ArgSpec a; a.kind = abi::ArgKind::Ptr; a.deref_size = sz; return a;
    };
    auto ptr_out = [&](std::uint64_t sz) {
        abi::ArgSpec a; a.kind = abi::ArgKind::Ptr; a.deref_size = sz;
        a.is_out = true; return a;
    };
    if (id == "XGameRuntimeInitialize") {
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "XGameRuntimeUninitialize") {
        plan.call.ret = abi::CallSpec::ReturnKind::Void;
    } else if (id == "XGameRuntimeInitializeWithOptions") {
        plan.call.args.push_back(ptr_in(64));
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "XSystemGetDeviceType") {
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "XSystemGetConsoleId" || id == "XSystemGetXboxLiveSandboxId" ||
               id == "XSystemGetAppSpecificDeviceId") {
        plan.call.args.push_back(int_arg());          // size
        plan.call.args.push_back(ptr_out(512));       // buffer out (string)
        plan.call.args.push_back(ptr_out(8));         // used out
        plan.out_buffer_args.push_back(1);
    } else if (id == "XSystemGetRuntimeInfo") {
        // Struct return by value in the documented ABI is RAX (<= 64 bits)
        // — the M7 impl packs two u32s; model as Int.
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "XThreadSetTimeSensitive") {
        plan.call.args.push_back(int_arg());
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "XThreadIsTimeSensitive") {
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "XTaskQueueCreate") {
        plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg());
        plan.call.args.push_back(ptr_out(8));
        plan.out_buffer_args.push_back(2);
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "XTaskQueueDispatch") {
        plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg());
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "XTaskQueueCloseHandle") {
        plan.call.args.push_back(int_arg());
        plan.call.ret = abi::CallSpec::ReturnKind::Void;
    } else if (id == "XTaskQueueTerminate") {
        plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg());
        plan.call.args.push_back(ptr_in(0));
        plan.call.args.push_back(ptr_in(0));
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "QueryPerformanceCounter" || id == "QueryPerformanceFrequency") {
        plan.call.args.push_back(ptr_out(8)); plan.out_buffer_args.push_back(0);
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "GetCurrentProcessId" || id == "GetCurrentThreadId") {
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "CreateMutexW") {
        plan.call.args.push_back(ptr_in(0)); plan.call.args.push_back(int_arg());
        plan.call.args.push_back(ptr_in(0)); plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "ReleaseMutex") {
        plan.call.args.push_back(int_arg()); plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "CreateSemaphoreW") {
        plan.call.args.push_back(ptr_in(0)); plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg()); plan.call.args.push_back(ptr_in(0));
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "ReleaseSemaphore") {
        plan.call.args.push_back(int_arg()); plan.call.args.push_back(int_arg());
        plan.call.args.push_back(ptr_out(4)); plan.out_buffer_args.push_back(2);
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "CreateEventW") {
        plan.call.args.push_back(ptr_in(0));
        plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg());
        plan.call.args.push_back(ptr_in(0));
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "SetEvent" || id == "ResetEvent" || id == "CloseHandle") {
        plan.call.args.push_back(int_arg());
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "WaitForSingleObject") {
        plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg());
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "XTaskQueueDuplicateHandle") {
        plan.call.args.push_back(int_arg()); // queueHandle
        plan.call.args.push_back(ptr_out(8)); // duplicatedHandle
        plan.out_buffer_args.push_back(1);
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "WaitForMultipleObjects") {
        plan.call.args.push_back(int_arg()); // nCount
        plan.call.args.push_back(ptr_in(0)); // lpHandles
        plan.call.args.push_back(int_arg()); // bWaitAll
        plan.call.args.push_back(int_arg()); // dwMilliseconds
        plan.pointer_array_args.push_back({1, 0, 64, 8});
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "VirtualQuery") {
        plan.call.args.push_back(ptr_in(0)); plan.call.args.push_back(ptr_out(48));
        plan.call.args.push_back(int_arg()); plan.out_buffer_args.push_back(1);
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "VirtualAlloc") {
        plan.call.args.push_back(ptr_in(0)); plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg()); plan.call.args.push_back(int_arg());
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "VirtualFree") {
        plan.call.args.push_back(int_arg()); plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg());
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else if (id == "VirtualProtect") {
        plan.call.args.push_back(int_arg()); plan.call.args.push_back(int_arg());
        plan.call.args.push_back(int_arg()); plan.call.args.push_back(ptr_out(4));
        plan.out_buffer_args.push_back(3);
        plan.call.ret = abi::CallSpec::ReturnKind::Int;
    } else {
        return Ret(RuntimeErrc::NotFound,
                   "no marshalling plan for " + d.library + "!" + id +
                       " (documented signature not planned; never guessed)");
    }
    const auto ok = abi::validate_call(plan.call);
    if (!ok.ok()) return Ret(ok.errc(), ok.context());
    return Ret(plan);
}

}  // namespace xbox2pc::rt::exec
