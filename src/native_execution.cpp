// M11.5.1 — deliberately narrow trusted native-host execution slice.
#include "xbox2pc/execution_engine.hpp"

#if defined(XBOX2PC_NATIVE_LINUX_X64)
#include <cstdint>
extern "C" std::uint64_t xbox2pc_native_call0(void* entry);
#endif

namespace xbox2pc::rt::exec {

bool NativeHostBackend::supported_on_host() {
#if defined(XBOX2PC_NATIVE_LINUX_X64)
    return true;
#else
    return false;
#endif
}

Result<void> NativeHostBackend::bind_execution_context(
    std::uint64_t process_id, std::uint64_t thread_id, AddressSpace& space) {
    if (process_id == 0 || thread_id == 0)
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "native backend requires nonzero guest identities");
    space_ = &space;
    process_id_ = process_id;
    thread_id_ = thread_id;
    return Result<void>::ok_result();
}

ExecutionResult NativeHostBackend::run(
    const ExecutionRequest& req, cpu::CpuState& io_cpu,
    const std::atomic<bool>& interrupted) {
    ExecutionResult result;
    result.cpu.state = io_cpu;
#if !defined(XBOX2PC_NATIVE_LINUX_X64)
    (void)req;
    (void)interrupted;
    result.outcome = Outcome::Faulted;
    GuestException exception;
    exception.fault = GuestFault::InvalidState;
    exception.process_id = process_id_;
    exception.thread_id = thread_id_;
    exception.recoverability = Recoverability::Fatal;
    exception.detail = "native host backend is supported only on Linux x86-64";
    result.exception = std::move(exception);
    return result;
#else
    auto reject = [&](GuestFault fault_kind, std::string detail) {
        GuestException exception;
        exception.fault = fault_kind;
        exception.rip = io_cpu.rip;
        exception.process_id = process_id_;
        exception.thread_id = thread_id_;
        exception.recoverability = Recoverability::Fatal;
        exception.detail = std::move(detail);
        result.exception = std::move(exception);
        result.outcome = Outcome::Faulted;
    };
    if (permission_ != NativeExecutionPermission::TrustedInProcess) {
        reject(GuestFault::InvalidState, "native execution permission not granted");
        return result;
    }
    if (space_ == nullptr || process_id_ == 0 || thread_id_ == 0) {
        reject(GuestFault::InvalidState, "native backend has no bound guest context");
        return result;
    }
    if (interrupted.load(std::memory_order_acquire)) {
        result.outcome = Outcome::Interrupted;
        return result;
    }
    if (req.entry_va == 0 || req.completion_va == 0) {
        reject(GuestFault::InvalidState, "native entry and completion sentinel are required");
        return result;
    }
    if (!req.api_bindings.empty() || !req.api_binding_values.empty()) {
        reject(GuestFault::InvalidState,
               "native leaf backend does not dispatch guest imports");
        return result;
    }
    auto executable = space_->validate_access(req.entry_va, false, true);
    if (!executable.ok()) {
        reject(GuestFault::PermissionExec,
               "native entry is not in an executable guest region");
        return result;
    }
    auto host_entry = space_->translate(req.entry_va);
    if (!host_entry.ok()) {
        reject(GuestFault::InvalidAccess,
               "native entry cannot be translated to the host mapping");
        return result;
    }

    // The thunk supplies the Windows x64-required 32-byte shadow area and
    // entry stack alignment. This first slice deliberately passes no args.
    const auto returned = xbox2pc_native_call0(host_entry.value());
    io_cpu.set_reg(cpu::Gpr::Rax, returned);
    io_cpu.rip = req.completion_va;
    result.outcome = Outcome::Returned;
    result.return_value = returned;
    result.final_rip = req.completion_va;
    result.cpu.state = io_cpu;
    // Native instructions are not counted by the interpreter's accounting.
    result.instructions_executed = 0;
    return result;
#endif
}

Result<std::uint64_t> NativeHostBackend::single_step(
    cpu::CpuState&, const ExecutionRequest&) {
    return Result<std::uint64_t>(RuntimeErrc::PlatformUnsupported,
                                 "native host backend does not support single-step");
}

}  // namespace xbox2pc::rt::exec
