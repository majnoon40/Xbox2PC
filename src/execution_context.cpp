// xbox2pc/src/execution_context.cpp — M8 execution context lifecycle + M6
// integration + TLS callback scheduling implementation.

#include "xbox2pc/execution_context.hpp"

#include <cstring>
#include <unordered_set>

namespace xbox2pc::rt::exec {

using cpu::CpuState;
using cpu::Gpr;

// ── names ────────────────────────────────────────────────────────────────

const char* context_state_to_name(ContextState s) {
    switch (s) {
        case ContextState::Created: return "created";
        case ContextState::Initialized: return "initialized";
        case ContextState::Executing: return "executing";
        case ContextState::Stopped: return "stopped";
        case ContextState::Destroyed: return "destroyed";
    }
    return "?";
}

// ── context limiter ──────────────────────────────────────────────────────

namespace {
std::atomic<std::uint32_t> g_live_contexts{0};
constexpr std::uint32_t kHardContextCap = 4096;
}  // namespace

Result<void> ContextLimiter::acquire() {
    std::uint32_t now = g_live_contexts.fetch_add(1);
    if (now + 1 > kHardContextCap) {
        g_live_contexts.fetch_sub(1);
        return Result<void>(RuntimeErrc::OutOfResources,
                            "runtime-wide execution context cap reached");
    }
    return Result<void>::ok_result();
}

void ContextLimiter::release() { g_live_contexts.fetch_sub(1); }

std::uint32_t ContextLimiter::live() { return g_live_contexts.load(); }

// ── context lifecycle ────────────────────────────────────────────────────

ExecutionContext::ExecutionContext(std::uint64_t process_id,
                                   std::uint64_t thread_id,
                                   AddressSpace& space,
                                   api::ApiRegistry& api_reg,
                                   ExecutionConfig cfg, std::string name,
                                   std::shared_ptr<GuestProcessEnvironment> process_environment)
    : RuntimeObject(static_type_id()),
      process_id_(process_id),
      thread_id_(thread_id),
      space_(space),
      api_reg_(api_reg),
      cfg_(cfg),
      mem_(space),
      process_environment_(std::move(process_environment)),
      ctx_name_(std::move(name)) {}

ExecutionContext::ExecutionContext(RtThread& thread, AddressSpace& space,
                                   api::ApiRegistry& api_reg,
                                   ExecutionConfig cfg, std::string name,
                                   std::shared_ptr<GuestProcessEnvironment> process_environment)
    : ExecutionContext(thread.owner_process_id(), thread.thread_id(), space,
                       api_reg, cfg, std::move(name), std::move(process_environment)) {
    execution_control_ = thread.execution_control();
}

ExecutionContext::~ExecutionContext() {
    (void)destroy();
    // M9 fix (audit A3): initialize() acquires the limiter slot; the
    // destructor releases ONLY when the context actually counted (a
    // never-initialized context must not underflow the global counter).
    if (counted_) {
        ContextLimiter::release();
        counted_ = false;
    }
}

Result<void> ExecutionContext::initialize() {
    // M9 fix (audit A3): the limiter slot is acquired at initialization.
    auto slot = ContextLimiter::acquire();
    if (!slot.ok()) {
        return slot;
    }
    std::lock_guard lock(lock_);
    if (state_ == ContextState::Destroyed) {
        ContextLimiter::release();   // failed init: give the slot back
        return Result<void>(RuntimeErrc::InvalidState, "context destroyed");
    }
    if (process_id_ == 0 || thread_id_ == 0) {
        ContextLimiter::release();
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "execution context requires nonzero process and thread identities");
    }
    if (state_ != ContextState::Created) {
        ContextLimiter::release();   // failed init: give the slot back
        return Result<void>(RuntimeErrc::InvalidState,
                            std::string("initialize from state ") +
                                context_state_to_name(state_));
    }
    auto cfg_ok = cfg_.validate();
    if (!cfg_ok.ok()) {
        ContextLimiter::release();   // failed init: give the slot back
        return cfg_ok;
    }
    // Guest stack: an M4 region INSIDE the process space (RW, capped).
    // Auto-placed (first-fit above the image; M4's per-process base and
    // capacity make a fixed VA wrong). Top at the region's high end;
    // guard floor = top - size.
    auto r = space_.reserve_region_auto(cfg_.max_stack_bytes, "guest-stack");
    if (!r.ok()) {
        ContextLimiter::release();   // failed init: give the slot back
        return Result<void>(r.errc(),
                            std::string("stack reserve: ") + r.error_string());
    }
    const std::uint64_t stack_va = r.value();
    auto c = space_.commit_region(stack_va);
    if (!c.ok()) {
        (void)space_.release_region(stack_va);
        ContextLimiter::release();   // failed init: give the slot back
        return Result<void>(c.errc(),
                            std::string("stack commit: ") + c.error_string());
    }
    // Committed regions default RW (M4 discipline) — exactly the stack's
    // required protection; no W^X exception needed.
    stack_region_va_ = stack_va;
    // M11.3: materialize documented user-mode TEB/PEB fields and the
    // per-thread TLS vector in guest memory. This records a guest GS base;
    // host GS is configured only by the later native execution thunk.
    if (process_environment_ == nullptr) {
        process_environment_ = std::make_shared<GuestProcessEnvironment>(space_);
    }
    auto process_result = process_environment_->initialize(process_id_);
    if (!process_result.ok()) {
        (void)space_.release_region(stack_region_va_);
        stack_region_va_ = 0;
        ContextLimiter::release();
        return process_result;
    }
    auto environment = std::make_unique<GuestThreadEnvironment>(space_, *process_environment_);
    auto environment_result = environment->initialize(thread_id_);
    if (!environment_result.ok()) {
        (void)space_.release_region(stack_region_va_);
        stack_region_va_ = 0;
        ContextLimiter::release();
        return environment_result;
    }
    guest_environment_ = std::move(environment);
    info_.stack_top = stack_va + cfg_.max_stack_bytes - 64;   // usable top
    info_.stack_size = cfg_.max_stack_bytes;
    // Align the top 16 [MS-X64STACK].
    info_.stack_top &= ~0xFull;
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, info_.stack_top);
    state_ = ContextState::Initialized;
    counted_ = true;   // the destructor now releases this slot (M9 A3)
    info_.process_id = process_id_;
    info_.thread_id = thread_id_;
    return Result<void>::ok_result();
}

Result<ExecutionRequest> ExecutionContext::prepare_entry(
    const loader::LoadedImageObject& image, std::uint32_t tls_index,
    const std::vector<abi::ArgValue>& args, const abi::CallSpec& spec) {
    using Ret = Result<ExecutionRequest>;
    std::lock_guard lock(lock_);
    if (state_ == ContextState::Destroyed) {
        return Ret(RuntimeErrc::InvalidState, "context destroyed");
    }
    if (state_ == ContextState::Executing) {
        return Ret(RuntimeErrc::InvalidState, "context is executing");
    }
    if (!image.exec().prepared) {
        return Ret(RuntimeErrc::InvalidState,
                   "image is not Prepared (M6 requires Prepared state)");
    }
    const auto& exec = image.exec();
    if (process_environment_ != nullptr) {
        auto peb_image = process_environment_->set_image_base(exec.image_base);
        if (!peb_image.ok()) return Ret(peb_image.errc(), peb_image.context());
    }
    // Entry validation: inside the image extent + executable region.
    {
        auto v = validate_entry_point(exec, space_);
        if (!v.ok()) return Ret(v.errc(), v.context());
    }
    // Reset CPU per preparation; stack discipline [MS-X64STACK].
    // The ENTRY call's return address is the COMPLETION SENTINEL: the
    // engine's RET on the sentinel completes the run (documented
    // contract; prepare_call would otherwise capture the pre-call RIP —
    // zero at reset — as the resume target).
    cpu_.reset();
    cpu_.set_reg(Gpr::Sp, info_.stack_top);
    cpu_.rip = exec::kCompletionSentinel;   // prepare_call captures THIS
    // Argument preparation through the ABI with a writer bound to the
    // guest stack (validated RW through GuestMemory).
    struct W { guest::GuestMemory* m; };
    W wctx{&mem_};
    abi::StackWriter writer;
    writer.ctx = &wctx;
    writer.write = [](void* c, std::uint64_t va, const void* src,
                      std::size_t len) -> Result<void> {
        return static_cast<W*>(c)->m->write(va, src, len);
    };
    auto prep = abi::prepare_call(cpu_, exec.entry_va, spec, args, writer);
    if (!prep.ok()) return Ret(prep.errc(), prep.context());
    cpu_.rip = exec.entry_va;   // execution starts at the entry point
    // (tls_index association is recorded; the M7 TLS state rides the
    // process's threads, not this context.)
    ExecutionRequest req;
    req.entry_va = exec.entry_va;
    req.stack_top_va = info_.stack_top;
    req.stack_size = info_.stack_size;
    req.completion_va = exec::kCompletionSentinel;
    req.entry_args = args;
    req.entry_spec = spec;
    // Bind each resolved IAT import to its exact documented identity.
    // The loader diagnostics are authoritative; never infer an export from
    // a synthetic address or scan arbitrary image memory for address ranges.
    req.api_binding_values.clear();
    req.api_bindings.clear();
    std::unordered_set<std::uint64_t> seen_bindings;
    seen_bindings.reserve(image.diagnostics().imports.size());
    for (const auto& imported : image.diagnostics().imports) {
        if (imported.status != loader::ImportStatus::Resolved ||
            imported.value == 0) {
            continue;
        }
        // Non-synthetic resolved imports may be direct guest targets;
        // only the reserved API dispatch ranges require registry identity.
        if (!is_api_binding(imported.value)) continue;
        if (!seen_bindings.insert(imported.value).second) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "duplicate synthetic API binding value in loader diagnostics");
        }
        if (imported.lookup.dll.empty() ||
            (imported.lookup.by_ordinal && imported.lookup.ordinal == 0) ||
            (!imported.lookup.by_ordinal && imported.lookup.symbol.empty())) {
            return Ret(RuntimeErrc::InvalidArgument,
                       "resolved import has incomplete DLL/name-or-ordinal identity");
        }
        ApiBindingInfo binding;
        binding.value = imported.value;
        binding.library = imported.lookup.dll;
        binding.export_name = imported.lookup.symbol;
        binding.by_ordinal = imported.lookup.by_ordinal;
        binding.ordinal = imported.lookup.ordinal;
        req.api_binding_values.push_back(binding.value);
        req.api_bindings.push_back(std::move(binding));
    }
    info_.tls_index = tls_index;
    return Ret(req);
}

std::shared_ptr<ExecutionControl> ExecutionContext::execution_control() const {
    std::lock_guard lock(lock_);
    return execution_control_;
}

Result<void> ExecutionContext::bind_thread_control(
    std::shared_ptr<ExecutionControl> control) {
    if (control == nullptr) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "thread execution control must not be null");
    }
    std::lock_guard lock(lock_);
    if (state_ == ContextState::Destroyed || state_ == ContextState::Executing) {
        return Result<void>(RuntimeErrc::InvalidState,
                            "cannot bind thread control in the current context state");
    }
    execution_control_ = std::move(control);
    return Result<void>::ok_result();
}

Result<ExecutionResult> ExecutionContext::invoke(
    const ExecutionRequest& req, IExecutionEngine& engine,
    const std::atomic<bool>& interrupted) {
    using Ret = Result<ExecutionResult>;
    std::lock_guard lock(lock_);
    if (state_ == ContextState::Destroyed) {
        return Ret(RuntimeErrc::InvalidState, "context destroyed");
    }
    if (state_ == ContextState::Executing) {
        return Ret(RuntimeErrc::InvalidState, "context already executing");
    }
    if (state_ != ContextState::Initialized && state_ != ContextState::Stopped) {
        return Ret(RuntimeErrc::InvalidState,
                   std::string("invoke from state ") + context_state_to_name(state_));
    }
    // Engine must be bound to the same address space: verify through
    // the request's stack (a canary validate).
    {
        auto rng = mem_.validate(req.stack_top_va - 16, 16, true, false);
        if (!rng.ok()) {
            return Ret(RuntimeErrc::InvalidArgument,
                        "request stack not usable in this context's space");
        }
    }
    auto bound = engine.bind_execution_context(process_id_, thread_id_, space_);
    if (!bound.ok()) {
        return Ret(bound.errc(), "bind guest execution context: " + bound.error_string());
    }
    state_ = ContextState::Executing;
    ExecutionRequest controlled = req;
    if (execution_control_ != nullptr) controlled.control = execution_control_;
    auto res = engine.run(controlled, cpu_, interrupted);
    state_ = ContextState::Stopped;
    ++runs_;
    return Ret(res);
}

Result<std::uint64_t> ExecutionContext::step(const ExecutionRequest& req,
                                            IExecutionEngine& engine) {
    using Ret = Result<std::uint64_t>;
    std::lock_guard lock(lock_);
    if (state_ != ContextState::Initialized && state_ != ContextState::Stopped) {
        return Ret(RuntimeErrc::InvalidState,
                   std::string("step from state ") + context_state_to_name(state_));
    }
    if (!engine.supports_single_step()) {
        return Ret(RuntimeErrc::PlatformUnsupported, "engine cannot single-step");
    }
    auto bound = engine.bind_execution_context(process_id_, thread_id_, space_);
    if (!bound.ok()) {
        return Ret(bound.errc(), "bind guest execution context: " + bound.error_string());
    }
    ExecutionRequest controlled = req;
    if (execution_control_ != nullptr) controlled.control = execution_control_;
    return engine.single_step(cpu_, controlled);
}

Result<void> ExecutionContext::destroy() {
    std::lock_guard lock(lock_);
    if (state_ == ContextState::Destroyed) {
        return Result<void>::ok_result();   // idempotent
    }
    if (state_ == ContextState::Executing) {
        // A run holds the lock; destruction happens after it releases.
        return Result<void>(RuntimeErrc::InvalidState,
                            "cannot destroy while executing");
    }
    // TEB, PEB, TLS vector and TLS blocks are released before the stack.
    guest_environment_.reset();
    if (stack_region_va_ != 0) {
        auto r = space_.release_region(stack_region_va_);
        if (!r.ok()) {
            // Region already gone with the process: still destroy.
            (void)r;
        }
        stack_region_va_ = 0;
    }
    state_ = ContextState::Destroyed;
    return Result<void>::ok_result();
}

// ── M6 entry validation ──────────────────────────────────────────────────

Result<std::uint64_t> validate_entry_point(const loader::ExecDescription& exec,
                                            AddressSpace& space) {
    if (!exec.prepared) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidState,
                                     "image not prepared");
    }
    if (exec.entry_va == 0) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "entry VA is zero");
    }
    if (exec.image_size == 0) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument,
                                     "image size is zero");
    }
    // Inside the mapped image extent.
    if (exec.entry_va < exec.image_base ||
        exec.entry_va >= exec.image_base + exec.image_size) {
        return Result<std::uint64_t>(
            RuntimeErrc::InvalidArgument,
            "entry VA outside the mapped image extent");
    }
    // Executable region check (RX/Full).
    auto v = space.validate_access(exec.entry_va, false, true);
    if (!v.ok()) {
        return Result<std::uint64_t>(
            v.errc() == RuntimeErrc::NotFound
                ? RuntimeErrc::InvalidArgument
                : RuntimeErrc::PlatformError,
            "entry point not executable: " + v.error_string());
    }
    return Result<std::uint64_t>(exec.entry_va);
}

// ── TLS callback scheduling ──────────────────────────────────────────────

Result<TlsCallbackPlan> plan_tls_callbacks(guest::GuestMemory& mem,
                                          const loader::TlsInfo& tls,
                                          const ExecutionConfig& cfg) {
    using Ret = Result<TlsCallbackPlan>;
    TlsCallbackPlan plan;
    if (!tls.present) {
        plan.note = "no TLS directory";
        return Ret(plan);
    }
    if (tls.callback_count > cfg.max_tls_callbacks) {
        return Ret(RuntimeErrc::OutOfResources,
                   "callback count " + std::to_string(tls.callback_count) +
                       " above the limit " +
                       std::to_string(cfg.max_tls_callbacks));
    }
    if (tls.callbacks_va == 0) {
        if (tls.callback_count == 0) {
            plan.note = "no callbacks";
            return Ret(plan);
        }
        return Ret(RuntimeErrc::InvalidArgument,
                   "callback count nonzero with no array VA");
    }
    // Read the callback VA array from guest memory (each 8 bytes).
    for (std::uint32_t i = 0; i < tls.callback_count; ++i) {
        const std::uint64_t slot = tls.callbacks_va + static_cast<std::uint64_t>(i) * 8;
        auto va = mem.read_u64(slot);
        if (!va.ok()) {
            // Unreadable array slot: reject the ENTRY (not the plan).
            ++plan.rejected_count;
            continue;
        }
        if (va.value() == 0) {
            // Terminating NULL or padding: stop at the documented
            // array semantics (null entry = end).
            break;
        }
        TlsCallback cb;
        cb.va = va.value();
        cb.order = i;
        // Validate executable + mapped: the callback must live in an
        // RX region (mapped image .text).
        auto x = mem.validate_exec(cb.va);
        if (!x.ok()) {
            ++plan.rejected_count;
            continue;
        }
        plan.callbacks.push_back(cb);
    }
    plan.note = "validated " + std::to_string(plan.callbacks.size()) +
                " callbacks (" + std::to_string(plan.rejected_count) +
                " rejected)";
    return Ret(plan);
}

Result<TlsCallbackResult> execute_tls_callbacks(
    ExecutionContext& ctx, const TlsCallbackPlan& plan,
    IExecutionEngine& engine, std::uint64_t image_handle_va) {
    using Ret = Result<TlsCallbackResult>;
    TlsCallbackResult out;
    // Documented callback ABI: RCX=DllHandle, RDX=Reason
    // (DLL_PROCESS_ATTACH=1), R8=Reserved.
    auto bound = engine.bind_execution_context(ctx.info().process_id,
                                               ctx.info().thread_id,
                                               ctx.memory().space());
    if (!bound.ok()) {
        return Ret(bound.errc(), "bind TLS callback execution context: " +
                                     bound.error_string());
    }
    for (const auto& cb : plan.callbacks) {
        // Prepare the callback frame on the context's CPU state.
        CpuState call = ctx.cpu();
        call.set_reg(Gpr::Sp, ctx.info().stack_top);
        abi::CallSpec spec;
        spec.args.resize(3);
        spec.args[0].kind = abi::ArgKind::Int;
        spec.args[1].kind = abi::ArgKind::Int;
        spec.args[2].kind = abi::ArgKind::Int;
        spec.ret = abi::CallSpec::ReturnKind::Void;
        std::vector<abi::ArgValue> vals(3);
        vals[0].int_v = image_handle_va;
        vals[1].int_v = 1;   // DLL_PROCESS_ATTACH
        vals[2].int_v = 0;
        // Write the frame via the context's guest memory.
        struct W { guest::GuestMemory* m; };
        W wctx{&ctx.memory()};
        abi::StackWriter writer;
        writer.ctx = &wctx;
        writer.write = [](void* c, std::uint64_t va, const void* src,
                          std::size_t len) -> Result<void> {
            return static_cast<W*>(c)->m->write(va, src, len);
        };
        auto prep = abi::prepare_call(call, cb.va, spec, vals, writer);
        if (!prep.ok()) {
            ++out.failed;
            if (!out.first_failure.has_value()) {
                GuestException e;
                e.fault = GuestFault::MarshalFailure;
                e.rip = cb.va;
                e.process_id = ctx.info().process_id;
                e.thread_id = ctx.info().thread_id;
                e.recoverability = Recoverability::Recoverable;
                e.detail = "callback frame preparation: " + prep.error_string();
                out.first_failure = e;
            }
            continue;
        }
        ExecutionRequest req;
        req.entry_va = cb.va;
        req.stack_top_va = ctx.info().stack_top;
        req.stack_size = ctx.info().stack_size;
        req.completion_va = kCompletionSentinel;
        // TLS initialization runs on the owning guest thread and must
        // obey the same suspend/terminate gate as the entry point.
        req.control = ctx.execution_control();
        std::atomic<bool> stop{false};
        auto res = engine.run(req, call, stop);
        if (res.outcome == Outcome::Faulted) {
            ++out.failed;
            if (!out.first_failure.has_value() && res.exception.has_value()) {
                out.first_failure = res.exception;
            }
            continue;   // report + keep going: partial-init cleanup rule
        }
        ++out.executed;
    }
    return Ret(out);
}

}  // namespace xbox2pc::rt::exec
