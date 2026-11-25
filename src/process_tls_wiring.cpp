// process_tls_wiring.cpp — M11 Phase 2: ProcessManager TLS lifecycle
// hook definitions.
//
// These ProcessManager member functions live in rt_execution, not
// rt_procman: they call exec::TlsLifecycle::run (rt_execution), and the
// library layering keeps rt_procman below rt_execution (rt_loader ->
// rt_procman; rt_execution -> rt_api -> rt_loader). Defining them here
// keeps every link edge pointing upward.

#include "xbox2pc/process_management.hpp"

#include "xbox2pc/execution_context.hpp"

#include <utility>

namespace xbox2pc::rt {

// ── TLS lifecycle hooks (M11 Phase 2) ─────────────────────────────────

// Shared validation for the TLS hooks: process must exist and the
// context must belong to it.
Result<ManagedProcess*> ProcessManager::tls_hook_prelude(Handle process,
                                                         exec::ExecutionContext& ctx) {
    RefGuard guard;
    ManagedProcess* proc = find_locked(process, guard);
    if (proc == nullptr) {
        return Result<ManagedProcess*>(RuntimeErrc::InvalidHandle,
                                        "process not found");
    }
    if (ctx.info().process_id != proc->pid_value()) {
        return Result<ManagedProcess*>(
            RuntimeErrc::InvalidArgument,
            "execution context belongs to another process");
    }
    return Result<ManagedProcess*>(proc);
}

Result<exec::TlsCallbackResult> ProcessManager::run_tls_process_attach(
    Handle process, exec::ExecutionContext& ctx,
    exec::IExecutionEngine& engine) {
    auto pre = tls_hook_prelude(process, ctx);
    if (!pre.ok()) {
        return Result<exec::TlsCallbackResult>(pre.errc(), pre.context());
    }
    ManagedProcess* proc = pre.value();
    const ProcessState state = proc->state();
    if (state != ProcessState::Initializing && state != ProcessState::Created) {
        return Result<exec::TlsCallbackResult>(
            RuntimeErrc::InvalidState,
            "process attach requires an unstarted process");
    }
    return proc->tls_lifecycle().run(ctx, engine,
                                     exec::TlsCallbackReason::ProcessAttach);
}

Result<exec::TlsCallbackResult> ProcessManager::run_tls_thread_attach(
    Handle process, std::uint64_t thread_obj_id, exec::ExecutionContext& ctx,
    exec::IExecutionEngine& engine) {
    auto pre = tls_hook_prelude(process, ctx);
    if (!pre.ok()) {
        return Result<exec::TlsCallbackResult>(pre.errc(), pre.context());
    }
    ManagedProcess* proc = pre.value();
    if (proc->tls_thread_attached(thread_obj_id)) {
        return Result<exec::TlsCallbackResult>(
            RuntimeErrc::AlreadyExists, "thread already TLS-attached");
    }
    auto r = proc->tls_lifecycle().run(ctx, engine,
                                       exec::TlsCallbackReason::ThreadAttach);
    if (r.ok()) proc->set_tls_thread_attached(thread_obj_id, true);
    return r;
}

Result<exec::TlsCallbackResult> ProcessManager::run_tls_thread_detach(
    Handle process, std::uint64_t thread_obj_id, exec::ExecutionContext& ctx,
    exec::IExecutionEngine& engine) {
    auto pre = tls_hook_prelude(process, ctx);
    if (!pre.ok()) {
        return Result<exec::TlsCallbackResult>(pre.errc(), pre.context());
    }
    ManagedProcess* proc = pre.value();
    if (!proc->tls_thread_attached(thread_obj_id)) {
        return Result<exec::TlsCallbackResult>(
            RuntimeErrc::NotFound, "thread not TLS-attached");
    }
    auto r = proc->tls_lifecycle().run(ctx, engine,
                                       exec::TlsCallbackReason::ThreadDetach);
    if (r.ok()) proc->set_tls_thread_attached(thread_obj_id, false);
    return r;
}

Result<exec::TlsCallbackResult> ProcessManager::run_tls_process_detach(
    Handle process, exec::ExecutionContext& ctx,
    exec::IExecutionEngine& engine) {
    auto pre = tls_hook_prelude(process, ctx);
    if (!pre.ok()) {
        return Result<exec::TlsCallbackResult>(pre.errc(), pre.context());
    }
    ManagedProcess* proc = pre.value();
    return proc->tls_lifecycle().run(ctx, engine,
                                     exec::TlsCallbackReason::ProcessDetach);
}

void ProcessManager::set_tls_detach_runner(
    std::function<Result<exec::TlsCallbackResult>(Handle)> runner) {
    std::lock_guard lock(lock_);
    tls_detach_runner_ = std::move(runner);
}

}  // namespace xbox2pc::rt
