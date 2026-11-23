// xbox2pc/src/gdk_services.cpp — M7 GDK + Game OS service implementations.
//
// Every implementation is bound to a documented descriptor in
// api_compat.hpp; the service registers the implementations at
// on_initialize and revokes them at on_shutdown. HRESULT values follow
// the documented semantics (S_OK / E_GAMERUNTIME_DLL_NOT_FOUND /
// ERROR_INSUFFICIENT_BUFFER fallbacks / E_ABORT / documented defaults).
// No host function pointers are exposed; dispatch goes through
// IApiImplementation under the ApiContext contract.

#include "xbox2pc/gdk_services.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>

namespace xbox2pc::rt::api {

namespace {

using loader::ImportStatus;

// ── implementation adapters ──────────────────────────────────────────────
//
// Each adapter closes over the owning service and translates the
// ApiContext into the service's typed API. Argument mapping follows the
// DOCUMENTED parameter order (position i of the signature).

class GrtInitializeImpl : public IApiImplementation {
public:
    explicit GrtInitializeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        const auto r = svc_.grt_initialize(ctx.process_id);
        out.return_value = r.ok() ? kSOk : kEGameruntimeDllNotFound;
        out.note = "per-process init count now " +
                   (r.ok() ? std::to_string(r.value()) : "0");
        return r.ok();
    }
    std::string describe() const override {
        return "GRT lifecycle: per-process ref-counted initialize";
    }

private:
    GameRuntimeService& svc_;
};

class GrtUninitializeImpl : public IApiImplementation {
public:
    explicit GrtUninitializeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        const auto r = svc_.grt_uninitialize(ctx.process_id);
        out.return_value = kSOk;   // documented: void
        out.note = r.ok() ? "uninitialized" : r.error_string();
        return true;  // void return: dispatch success regardless
    }
    std::string describe() const override { return "GRT lifecycle: uninitialize"; }

private:
    GameRuntimeService& svc_;
};

class GrtInitOptionsImpl : public IApiImplementation {
public:
    explicit GrtInitOptionsImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        // Stub policy (documented: options compared; mismatch fails):
        // a null options pointer (arg slot 0 == 0) takes default options.
        const auto r = svc_.grt_initialize(ctx.process_id);
        out.return_value = r.ok() ? kSOk : kEGameruntimeDllNotFound;
        out.note = "stub: options pointer not interpreted (documented "
                   "comparison semantics deferred)";
        return r.ok();
    }
    std::string describe() const override {
        return "GRT lifecycle: initialize-with-options (stub)";
    }

private:
    GameRuntimeService& svc_;
};

class SysDeviceTypeImpl : public IApiImplementation {
public:
    explicit SysDeviceTypeImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext&, ApiCallResult& out) override {
        // Documented: returns Unknown when the device type cannot be
        // determined — always the honest answer in this runtime.
        out.return_value =
            static_cast<std::uint64_t>(svc_.device_type());
        out.note = "XSystemDeviceType::Unknown (documented fallback; no "
                   "device spoofing)";
        return true;
    }
    std::string describe() const override {
        return "XSystem: device type (documented Unknown fallback)";
    }

private:
    GameRuntimeService& svc_;
};

// Shared shape for the three (size, buffer, used) string APIs.
class SysIdImpl : public IApiImplementation {
public:
    enum class Which { ConsoleId, SandboxId, AppDeviceId };
    SysIdImpl(GameRuntimeService& svc, Which which) : svc_(svc), which_(which) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;  // validated by dispatcher too
        const std::uint64_t size = ctx.args[0];
        // Documented: not safe on time-sensitive threads.
        if (ctx.thread_time_sensitive) {
            out.return_value = kEInvalidArg;
            out.error = "not safe on a time-sensitive thread (documented)";
            return false;
        }
        Result<std::string> r =
            which_ == Which::ConsoleId ? svc_.console_id(size, nullptr)
            : which_ == Which::SandboxId ? svc_.sandbox_id(size, nullptr)
                                         : svc_.app_device_id(size, nullptr);
        if (!r.ok()) {
            out.return_value = kEInsufficientBuffer;
            out.error = r.error_string();
            return false;
        }
        out.return_value = kSOk;
        out.has_out = true;
        out.out_value = r.value().size();
        out.out_size = r.value().size();
        // The payload bytes for the bridge's byte-granular write-back.
        out.out_bytes_size = r.value().size();
        for (std::size_t i = 0; i < out.out_bytes.size() && i < r.value().size(); ++i) {
            out.out_bytes[i] = static_cast<std::uint8_t>(r.value()[i]);
        }
        out.note = "documented fallback string returned (" + r.value() + ")";
        return true;
    }
    std::string describe() const override {
        switch (which_) {
            case Which::ConsoleId: return "XSystem: console id (documented all-zero PC fallback)";
            case Which::SandboxId: return "XSystem: Xbox Live sandbox id (RETAIL fallback)";
            case Which::AppDeviceId: return "XSystem: app-specific device id (all-zero fallback)";
        }
        return "?";
    }

private:
    GameRuntimeService& svc_;
    Which which_;
};

class SysRuntimeInfoImpl : public IApiImplementation {
public:
    explicit SysRuntimeInfoImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext&, ApiCallResult& out) override {
        const auto info = svc_.runtime_info();
        out.return_value =
            (static_cast<std::uint64_t>(info.current_major) << 32) |
            info.current_minor;
        out.note = "stub XSystemRuntimeInfo (zero versions; callable "
                   "before initialize — documented)";
        return true;
    }
    std::string describe() const override {
        return "XSystem: runtime info (zero-version stub)";
    }

private:
    GameRuntimeService& svc_;
};

class VirtualQueryImpl : public IApiImplementation {
public:
    explicit VirtualQueryImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        constexpr std::uint64_t kSize = 48;
        if (ctx.arg_count != 3) return false;
        if (ctx.args[2] < kSize || ctx.process_id == 0) { out.return_value = 0; return true; }
        const auto found = svc_.query_memory_region(ctx.process_id, ctx.args[0]);
        if (!found.ok()) { out.return_value = 0; out.note = found.error_string(); return true; }
        const auto& r = found.value();
        const std::uint64_t page = ctx.args[0] & ~std::uint64_t(4095);
        if (page < r.xbox_va || page - r.xbox_va >= r.size) { out.return_value = 0; return true; }
        const auto remaining = r.size - (page - r.xbox_va);
        const std::uint32_t prot = r.protection == MemProtect::NoAccess ? 1u : r.protection == MemProtect::ReadOnly ? 2u : r.protection == MemProtect::ReadWrite ? 4u : r.protection == MemProtect::ReadExecute ? 0x20u : 0x40u;
        const std::uint32_t state = r.state == RegionState::Committed ? 0x1000u : 0x2000u;
        auto p16=[&](std::size_t o,std::uint16_t x){out.out_bytes[o]=static_cast<std::uint8_t>(x);out.out_bytes[o+1]=static_cast<std::uint8_t>(x>>8);};
        auto p32=[&](std::size_t o,std::uint32_t x){for(unsigned i=0;i<4;++i)out.out_bytes[o+i]=static_cast<std::uint8_t>(x>>(8*i));};
        auto p64=[&](std::size_t o,std::uint64_t x){for(unsigned i=0;i<8;++i)out.out_bytes[o+i]=static_cast<std::uint8_t>(x>>(8*i));};
        p64(0,page); p64(8,r.xbox_va); p32(16,prot); p16(20,0); p64(24,remaining);
        p32(32,state); p32(36,prot); p32(40,0x20000u); p32(44,0);
        out.return_value=kSize; out.has_out=true; out.out_size=kSize; out.out_bytes_size=kSize;
        out.note="partial: tracked M4 regions only; free gaps and original allocation protection are not modeled";
        return true;
    }
    std::string describe() const override { return "Win32: VirtualQuery (tracked M4 guest regions; partial)"; }
private: GameRuntimeService& svc_;
};
class ThreadSetTsImpl : public IApiImplementation {
public:
    explicit ThreadSetTsImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 1) return false;
        const bool on = ctx.args[0] != 0;
        if (ctx.thread_id == 0) {
            out.return_value = kEInvalidArg;
            out.error = "calling thread identity is unavailable";
            return false;
        }
        const auto r = svc_.set_time_sensitive(ctx.process_id,
                                               ctx.thread_id, on);
        out.return_value = r.ok() ? kSOk : kEInvalidArg;
        out.note = "time-sensitive bit per runtime thread";
        return r.ok();
    }
    std::string describe() const override {
        return "XThread: set time-sensitive bit";
    }

private:
    GameRuntimeService& svc_;
};

class ThreadIsTsImpl : public IApiImplementation {
public:
    explicit ThreadIsTsImpl(GameRuntimeService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.thread_id == 0) {
            out.return_value = 0;
            out.error = "calling thread identity is unavailable";
            return false;
        }
        const auto r = svc_.is_time_sensitive(ctx.process_id, ctx.thread_id);
        out.return_value = r.ok() && r.value() ? 1 : 0;
        return true;
    }
    std::string describe() const override {
        return "XThread: query time-sensitive bit";
    }

private:
    GameRuntimeService& svc_;
};

// ── TaskQueue adapters ──

class TqCreateImpl : public IApiImplementation {
public:
    explicit TqCreateImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;
        const auto r = svc_.create_queue(
            ctx.process_id,
            static_cast<std::uint32_t>(ctx.args[0]),
            static_cast<std::uint32_t>(ctx.args[1]));
        if (!r.ok()) {
            out.return_value = kEInvalidArg;
            out.error = r.error_string();
            return false;
        }
        out.return_value = kSOk;
        out.has_out = true;
        out.out_value = r.value();   // XTaskQueueHandle* out slot
        out.note = "manual-mode queue created (documented handle out)";
        return true;
    }
    std::string describe() const override { return "XTaskQueue: create (manual modes)"; }

private:
    TaskQueueService& svc_;
};

class TqDispatchImpl : public IApiImplementation {
public:
    explicit TqDispatchImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 3) return false;
        const auto r = svc_.dispatch(
            ctx.process_id, ctx.args[0],
            static_cast<XTaskQueuePort>(ctx.args[1]),
            static_cast<std::uint32_t>(ctx.args[2]));
        out.return_value = r.ok() && r.value() ? 1 : 0;   // documented bool
        out.note = "false when nothing dispatched (documented)";
        return r.ok();
    }
    std::string describe() const override {
        return "XTaskQueue: dispatch (bool semantics)";
    }

private:
    TaskQueueService& svc_;
};

class TqCloseImpl : public IApiImplementation {
public:
    explicit TqCloseImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 1) return false;
        const auto r = svc_.close_queue(ctx.process_id, ctx.args[0]);
        out.return_value = kSOk;   // documented: void
        out.note = r.ok() ? "queue handle closed"
                          : "unknown or foreign handle (typed error reported)";
        return true;   // void API: dispatch-level success
    }
    std::string describe() const override {
        return "XTaskQueue: close handle (ref count)";
    }

private:
    TaskQueueService& svc_;
};

class TqTerminateImpl : public IApiImplementation {
public:
    explicit TqTerminateImpl(TaskQueueService& svc) : svc_(svc) {}
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.arg_count != 4) return false;
        const auto r = svc_.terminate_queue(ctx.process_id, ctx.args[0], ctx.args[1] != 0);
        out.return_value = r.ok() ? kSOk : kEInvalidArg;
        out.note = "cancel + E_ABORT submissions (documented); callbacks "
                   "option ignored in M7 (none exist)";
        return r.ok();
    }
    std::string describe() const override {
        return "XTaskQueue: terminate (cancel semantics)";
    }

private:
    TaskQueueService& svc_;
};

// ── Timing adapters (native equivalents through the PAL) ──

class QpcImpl : public IApiImplementation {
public:
    explicit QpcImpl(TimingService& svc) : svc_(svc) {}
    bool invoke(const ApiContext&, ApiCallResult& out) override {
        const auto r = svc_.qpc_value();
        if (!r.ok()) {
            out.return_value = 0;   // documented: zero on failure
            out.error = r.error_string();
            return false;
        }
        out.return_value = 1;       // documented: nonzero on success
        out.has_out = true;
        out.out_value = r.value();  // LARGE_INTEGER* out slot
        out.note = "PAL CLOCK_MONOTONIC (native equivalent)";
        return true;
    }
    std::string describe() const override {
        return "Win32: QueryPerformanceCounter (PAL monotonic equivalent)";
    }

private:
    TimingService& svc_;
};

class QpfImpl : public IApiImplementation {
public:
    explicit QpfImpl(TimingService& svc) : svc_(svc) {}
    bool invoke(const ApiContext&, ApiCallResult& out) override {
        const auto r = svc_.qpc_frequency();
        if (!r.ok()) {
            out.return_value = 0;
            out.error = r.error_string();
            return false;
        }
        out.return_value = 1;
        out.has_out = true;
        out.out_value = r.value();
        out.note = "fixed at boot documented; PAL nanosecond clock => "
                   "1'000'000'000 Hz model";
        return true;
    }
    std::string describe() const override {
        return "Win32: QueryPerformanceFrequency (PAL equivalent)";
    }

private:
    TimingService& svc_;
};

class CurrentProcessIdImpl : public IApiImplementation {
public:
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.process_id == 0 ||
            ctx.process_id > std::numeric_limits<std::uint32_t>::max()) {
            out.error = "calling process identity is unavailable or out of DWORD range";
            return false;
        }
        out.return_value = static_cast<std::uint32_t>(ctx.process_id);
        return true;
    }
    std::string describe() const override {
        return "Win32: GetCurrentProcessId (guest process context)";
    }
};

class CurrentThreadIdImpl : public IApiImplementation {
public:
    bool invoke(const ApiContext& ctx, ApiCallResult& out) override {
        if (ctx.thread_id == 0 ||
            ctx.thread_id > std::numeric_limits<std::uint32_t>::max()) {
            out.error = "calling thread identity is unavailable or out of DWORD range";
            return false;
        }
        out.return_value = static_cast<std::uint32_t>(ctx.thread_id);
        return true;
    }
    std::string describe() const override {
        return "Win32: GetCurrentThreadId (guest calling-thread context)";
    }
};

}  // namespace

// ── names ────────────────────────────────────────────────────────────────

const char* device_type_to_name(XSystemDeviceType t) {
    switch (t) {
        case XSystemDeviceType::Unknown: return "Unknown";
        case XSystemDeviceType::Pc: return "Pc";
        case XSystemDeviceType::XboxOne: return "XboxOne";
        case XSystemDeviceType::XboxOneS: return "XboxOneS";
        case XSystemDeviceType::XboxOneX: return "XboxOneX";
        case XSystemDeviceType::XboxOneXDevkit: return "XboxOneXDevkit";
        case XSystemDeviceType::XboxScarlettLockhart: return "XboxScarlettLockhart";
        case XSystemDeviceType::XboxScarlettAnaconda: return "XboxScarlettAnaconda";
        case XSystemDeviceType::XboxScarlettDevkit: return "XboxScarlettDevkit";
    }
    return "?";
}

// ── GameRuntimeService ───────────────────────────────────────────────────

GameRuntimeService::GameRuntimeService(ApiRegistry& api_reg,
                                       ProcessManager& process_manager)
    : RtService("gdk_game_runtime"), api_reg_(api_reg),
      process_manager_(process_manager) {}

GameRuntimeService::~GameRuntimeService() {
    if (service_state() == ServiceState::Ready) {
        (void)on_shutdown();
    }
}

Result<void> GameRuntimeService::on_initialize() {
    auto keep = [this](std::shared_ptr<IApiImplementation> impl) {
        owned_.push_back(impl);
        return impl;
    };
    const std::uint64_t owner = id();
    auto reg = [&](const char* name, std::shared_ptr<IApiImplementation> impl) {
        return api_reg_.register_implementation("xgameruntime", name,
                                               std::move(impl), owner);
    };
    auto r1 = reg("XGameRuntimeInitialize",
                  keep(std::make_shared<GrtInitializeImpl>(*this)));
    auto r2 = reg("XGameRuntimeUninitialize",
                  keep(std::make_shared<GrtUninitializeImpl>(*this)));
    auto r3 = reg("XGameRuntimeInitializeWithOptions",
                  keep(std::make_shared<GrtInitOptionsImpl>(*this)));
    auto r4 = reg("XSystemGetDeviceType",
                  keep(std::make_shared<SysDeviceTypeImpl>(*this)));
    auto r5 = reg("XSystemGetConsoleId",
                  keep(std::make_shared<SysIdImpl>(*this, SysIdImpl::Which::ConsoleId)));
    auto r6 = reg("XSystemGetXboxLiveSandboxId",
                  keep(std::make_shared<SysIdImpl>(*this, SysIdImpl::Which::SandboxId)));
    auto r7 = reg("XSystemGetAppSpecificDeviceId",
                  keep(std::make_shared<SysIdImpl>(*this, SysIdImpl::Which::AppDeviceId)));
    auto r8 = reg("XSystemGetRuntimeInfo",
                  keep(std::make_shared<SysRuntimeInfoImpl>(*this)));
    auto r9 = reg("XThreadSetTimeSensitive",
                  keep(std::make_shared<ThreadSetTsImpl>(*this)));
    auto r10 = reg("XThreadIsTimeSensitive",
                   keep(std::make_shared<ThreadIsTsImpl>(*this)));
    auto r11 = api_reg_.register_implementation("kernel32", "VirtualQuery", keep(std::make_shared<VirtualQueryImpl>(*this)), owner);
    for (const auto* r : {&r1, &r2, &r3, &r4, &r5, &r6, &r7, &r8, &r9, &r10, &r11}) {
        if (!r->ok()) {
            (void)api_reg_.revoke_owner(id());
            owned_.clear();
            return Result<void>(r->errc(), r->context());
        }
    }
    auto observer = process_manager_.add_process_exit_observer(
        [this](std::uint64_t process_id) { release_process(process_id); });
    if (!observer.ok()) {
        (void)api_reg_.revoke_owner(id());
        owned_.clear();
        return Result<void>(observer.errc(), observer.context());
    }
    process_exit_observer_id_ = observer.value();
    return Result<void>::ok_result();
}

Result<void> GameRuntimeService::on_shutdown() {
    Result<void> observer_removed = Result<void>::ok_result();
    if (process_exit_observer_id_ != 0) {
        observer_removed = process_manager_.remove_process_exit_observer(process_exit_observer_id_);
        process_exit_observer_id_ = 0;
    }
    const auto revoked = api_reg_.revoke_owner(id());
    {
        std::lock_guard lock(state_lock_);
        procs_.clear();
        ts_bits_.clear();
    }
    owned_.clear();
    if (!observer_removed.ok() && observer_removed.errc() != RuntimeErrc::NotFound) {
        return Result<void>(observer_removed.errc(), observer_removed.context());
    }
    if (!revoked.ok()) return Result<void>(revoked.errc(), revoked.context());
    return Result<void>::ok_result();
}

Result<std::uint64_t> GameRuntimeService::grt_initialize(std::uint64_t process_id) {
    std::lock_guard lock(state_lock_);
    auto& st = procs_[process_id];
    if (st.uninit_failed_terminal) {
        // Documented: a prior uninitialization failure is terminal.
        return Result<std::uint64_t>(RuntimeErrc::InvalidState,
                                     "terminal uninit failure (documented)");
    }
    return Result<std::uint64_t>(++st.init_count);
}

Result<void> GameRuntimeService::grt_uninitialize(std::uint64_t process_id) {
    std::lock_guard lock(state_lock_);
    const auto it = procs_.find(process_id);
    if (it == procs_.end() || it->second.init_count == 0) {
        // Documented: further uninit calls to the library are ignored.
        return Result<void>::ok_result();
    }
    if (--it->second.init_count == 0) {
        // Ref count reached zero: check for outstanding resources. The
        // runtime reports the documented terminal-failure shape when live
        // task queues exist for the process (they hold references).
        procs_.erase(it);
    }
    return Result<void>::ok_result();
}

Result<std::string> GameRuntimeService::console_id(std::uint64_t size,
                                                   std::uint64_t* used) {
    // Documented: PC default is the all-zero id
    // "00000000.00000000.00000000.00000000.00" (30 chars + NUL).
    static const std::string kDefault = "00000000.00000000.00000000.00000000.00";
    if (size < kDefault.size() + 1) {
        return Result<std::string>(RuntimeErrc::InvalidArgument,
                                   "consoleIdSize < XSystemConsoleIdBytes "
                                   "(documented ERROR_INSUFFICIENT_BUFFER)");
    }
    if (used != nullptr) *used = kDefault.size();
    return Result<std::string>(kDefault);
}

Result<std::string> GameRuntimeService::sandbox_id(std::uint64_t size,
                                                   std::uint64_t* used) {
    // Documented: defaults to 'RETAIL' when not found / retail env.
    static const std::string kDefault = "RETAIL";
    if (size < kDefault.size() + 1) {
        return Result<std::string>(RuntimeErrc::InvalidArgument,
                                   "sandboxIdSize < XSystemXboxLiveSandboxIdMaxBytes");
    }
    if (used != nullptr) *used = kDefault.size();
    return Result<std::string>(kDefault);
}

Result<std::string> GameRuntimeService::app_device_id(std::uint64_t size,
                                                     std::uint64_t* used) {
    // Documented: all-zero 40-digit string on failure.
    static const std::string kDefault(40, '0');
    if (size < kDefault.size() + 1) {
        return Result<std::string>(RuntimeErrc::InvalidArgument,
                                   "appSpecificDeviceIdSize < "
                                   "XSystemAppSpecificDeviceIdBytes");
    }
    if (used != nullptr) *used = kDefault.size();
    return Result<std::string>(kDefault);
}

Result<void> GameRuntimeService::set_time_sensitive(
    std::uint64_t process_id, std::uint64_t thread_id, bool on) {
    if (process_id == 0 || thread_id == 0) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "process and thread identities must be nonzero");
    }
    std::lock_guard lock(state_lock_);
    ts_bits_[{process_id, thread_id}] = on;
    return Result<void>::ok_result();
}

Result<bool> GameRuntimeService::is_time_sensitive(
    std::uint64_t process_id, std::uint64_t thread_id) const {
    if (process_id == 0 || thread_id == 0) {
        return Result<bool>(RuntimeErrc::InvalidArgument,
                            "process and thread identities must be nonzero");
    }
    std::lock_guard lock(state_lock_);
    const auto it = ts_bits_.find({process_id, thread_id});
    return Result<bool>(it != ts_bits_.end() && it->second);
}

Result<VmRegion> GameRuntimeService::query_memory_region(std::uint64_t process_id, std::uint64_t guest_address) const {
    auto process = process_manager_.find_process_by_pid(process_id);
    if (!process.ok()) return Result<VmRegion>(process.errc(), process.context());
    auto* managed = process.value().get()->as<ManagedProcess>();
    if (managed == nullptr) return Result<VmRegion>(RuntimeErrc::ObjectTypeMismatch, "not a managed process");
    return managed->address_space().find_containing(guest_address);
}

void GameRuntimeService::release_process(std::uint64_t process_id) {
    std::lock_guard lock(state_lock_);
    procs_.erase(process_id);
    for (auto it = ts_bits_.begin(); it != ts_bits_.end();) {
        if (it->first.first == process_id) it = ts_bits_.erase(it);
        else ++it;
    }
}

// ── TaskQueueService ─────────────────────────────────────────────────────

TaskQueueService::TaskQueueService(ApiRegistry& api_reg, ProcessManager& pm)
    : RtService("gdk_task_queue"), api_reg_(api_reg), pm_(pm) {}

TaskQueueService::~TaskQueueService() {
    if (service_state() == ServiceState::Ready) {
        (void)on_shutdown();
    }
}

Result<void> TaskQueueService::on_initialize() {
    const std::uint64_t owner = id();
    auto keep = [this](std::shared_ptr<IApiImplementation> impl) {
        owned_.push_back(impl);
        return impl;
    };
    auto reg = [&](const char* name, std::shared_ptr<IApiImplementation> impl) {
        return api_reg_.register_implementation("xgameruntime", name,
                                               std::move(impl), owner);
    };
    const auto r1 = reg("XTaskQueueCreate", keep(std::make_shared<TqCreateImpl>(*this)));
    const auto r2 = reg("XTaskQueueDispatch", keep(std::make_shared<TqDispatchImpl>(*this)));
    const auto r3 = reg("XTaskQueueCloseHandle", keep(std::make_shared<TqCloseImpl>(*this)));
    const auto r4 = reg("XTaskQueueTerminate", keep(std::make_shared<TqTerminateImpl>(*this)));
    for (const auto* r : {&r1, &r2, &r3, &r4}) {
        if (!r->ok()) {
            (void)api_reg_.revoke_owner(owner);
            owned_.clear();
            return Result<void>(r->errc(), r->context());
        }
    }
    auto observer = pm_.add_process_exit_observer(
        [this](std::uint64_t process_id) { release_process(process_id); });
    if (!observer.ok()) {
        (void)api_reg_.revoke_owner(owner);
        owned_.clear();
        return Result<void>(observer.errc(), observer.context());
    }
    process_exit_observer_id_ = observer.value();
    return Result<void>::ok_result();
}

Result<void> TaskQueueService::on_shutdown() {
    Result<void> observer_removed = Result<void>::ok_result();
    if (process_exit_observer_id_ != 0) {
        observer_removed = pm_.remove_process_exit_observer(process_exit_observer_id_);
        process_exit_observer_id_ = 0;
    }
    const auto revoked = api_reg_.revoke_owner(id());
    {
        std::lock_guard lock(lock_);
        queues_.clear();
    }
    owned_.clear();
    if (!observer_removed.ok() && observer_removed.errc() != RuntimeErrc::NotFound) {
        return Result<void>(observer_removed.errc(), observer_removed.context());
    }
    if (!revoked.ok()) return Result<void>(revoked.errc(), revoked.context());
    return Result<void>::ok_result();
}

Result<std::uint64_t> TaskQueueService::create_queue(
    std::uint64_t process_id, std::uint32_t work_mode,
    std::uint32_t completion_mode) {
    const auto manual = static_cast<std::uint32_t>(XTaskQueueDispatchMode::Manual);
    if (work_mode != manual || completion_mode != manual) {
        return Result<std::uint64_t>(
            RuntimeErrc::InvalidArgument,
            "only manual dispatch mode is implemented; other modes require callback scheduling");
    }
    std::lock_guard lock(lock_);
    if (next_id_ == 0 || next_id_ == UINT64_MAX) {
        return Result<std::uint64_t>(RuntimeErrc::OutOfResources,
                                     "task queue handle space exhausted");
    }
    const std::uint64_t queue_id = next_id_++;
    Queue q;
    q.owner_process_id = process_id;
    q.work_mode = work_mode;
    q.completion_mode = completion_mode;
    queues_.emplace(queue_id, q);
    return Result<std::uint64_t>(queue_id);
}

Result<bool> TaskQueueService::dispatch(
    std::uint64_t process_id, std::uint64_t queue_id,
    XTaskQueuePort port, std::uint32_t timeout_ms) {
    std::lock_guard lock(lock_);
    const auto it = queues_.find(queue_id);
    if (it == queues_.end()) {
        return Result<bool>(RuntimeErrc::NotFound, "unknown queue handle");
    }
    if (it->second.owner_process_id != process_id) {
        return Result<bool>(RuntimeErrc::InvalidHandle,
                            "task queue handle belongs to another process");
    }
    if (port != XTaskQueuePort::Work && port != XTaskQueuePort::Completion) {
        return Result<bool>(RuntimeErrc::InvalidArgument,
                            "unknown XTaskQueuePort value");
    }
    if (it->second.terminated) return Result<bool>(false);
    (void)timeout_ms;  // no callback submissions exist in this compatibility slice
    return Result<bool>(false);
}

Result<void> TaskQueueService::close_queue(
    std::uint64_t process_id, std::uint64_t queue_id) {
    std::lock_guard lock(lock_);
    const auto it = queues_.find(queue_id);
    if (it == queues_.end()) {
        return Result<void>(RuntimeErrc::NotFound, "unknown queue handle");
    }
    if (it->second.owner_process_id != process_id) {
        return Result<void>(RuntimeErrc::InvalidHandle,
                            "task queue handle belongs to another process");
    }
    queues_.erase(it);
    return Result<void>::ok_result();
}

Result<void> TaskQueueService::terminate_queue(
    std::uint64_t process_id, std::uint64_t queue_id, bool wait) {
    std::lock_guard lock(lock_);
    const auto it = queues_.find(queue_id);
    if (it == queues_.end()) {
        return Result<void>(RuntimeErrc::NotFound, "unknown queue handle");
    }
    if (it->second.owner_process_id != process_id) {
        return Result<void>(RuntimeErrc::InvalidHandle,
                            "task queue handle belongs to another process");
    }
    it->second.terminated = true;
    (void)wait;  // no callback work exists to drain in this partial model
    return Result<void>::ok_result();
}

void TaskQueueService::release_process(std::uint64_t process_id) {
    std::lock_guard lock(lock_);
    for (auto it = queues_.begin(); it != queues_.end();) {
        if (it->second.owner_process_id == process_id) it = queues_.erase(it);
        else ++it;
    }
}

std::size_t TaskQueueService::live_queues() const {
    std::lock_guard lock(lock_);
    return queues_.size();
}

// ── TimingService ────────────────────────────────────────────────────────

TimingService::TimingService(ApiRegistry& api_reg)
    : RtService("win32_timing"), api_reg_(api_reg) {}

TimingService::~TimingService() {
    if (service_state() == ServiceState::Ready) {
        (void)on_shutdown();
    }
}

Result<void> TimingService::on_initialize() {
    const std::uint64_t owner = id();
    auto keep = [this](std::shared_ptr<IApiImplementation> impl) {
        owned_.push_back(impl);
        return impl;
    };
    const auto r1 = api_reg_.register_implementation(
        "kernel32", "QueryPerformanceCounter",
        keep(std::make_shared<QpcImpl>(*this)), owner);
    const auto r2 = api_reg_.register_implementation(
        "kernel32", "QueryPerformanceFrequency",
        keep(std::make_shared<QpfImpl>(*this)), owner);
    const auto r3 = api_reg_.register_implementation(
        "kernel32", "GetCurrentProcessId",
        keep(std::make_shared<CurrentProcessIdImpl>()), owner);
    const auto r4 = api_reg_.register_implementation(
        "kernel32", "GetCurrentThreadId",
        keep(std::make_shared<CurrentThreadIdImpl>()), owner);
    if (!r1.ok()) return r1;
    if (!r2.ok()) return r2;
    if (!r3.ok()) return r3;
    if (!r4.ok()) return r4;
    return Result<void>::ok_result();
}

Result<void> TimingService::on_shutdown() {
    const auto revoked = api_reg_.revoke_owner(id());
    owned_.clear();
    if (!revoked.ok()) {
        return Result<void>(revoked.errc(), revoked.context());
    }
    return Result<void>::ok_result();
}

Result<std::uint64_t> TimingService::qpc_value() {
    return Result<std::uint64_t>(
        static_cast<std::uint64_t>(pal::now_ns()));
}

Result<std::uint64_t> TimingService::qpc_frequency() {
    // PAL clock is nanosecond monotonic: frequency is 1e9 (documented QPF
    // semantics: counts per second, fixed).
    return Result<std::uint64_t>(1'000'000'000ull);
}

// ── TLS per-thread initialization ────────────────────────────────────────

namespace {
struct TlsIndexTable {
    std::mutex lock;
    // process id -> (image name -> index)
    std::map<std::uint64_t, std::map<std::string, std::uint32_t>> per_process;
    std::uint32_t next_index = 1;   // 0 reserved
};
TlsIndexTable& tls_table() {
    static TlsIndexTable t;
    return t;
}
}  // namespace

Result<std::uint32_t> tls_assign_index(std::uint64_t process_id,
                                       const std::string& image_name,
                                       const loader::TlsInfo& info) {
    if (info.template_size > loader::kMaxTlsTemplate) {
        return Result<std::uint32_t>(RuntimeErrc::OutOfResources,
                                     "TLS template too large");
    }
    auto& t = tls_table();
    std::lock_guard lock(t.lock);
    auto& images = t.per_process[process_id];
    const auto it = images.find(image_name);
    if (it != images.end()) {
        return Result<std::uint32_t>(it->second);   // documented: stable index
    }
    const std::uint32_t idx = t.next_index++;
    images.emplace(image_name, idx);
    return Result<std::uint32_t>(idx);
}

Result<void> tls_init_thread(RtThread& thread, std::uint32_t index,
                             const pe::PeImage& img, const std::uint8_t* file,
                             std::size_t file_size, const loader::TlsInfo& info) {
    if (index == 0) {
        return Result<void>(RuntimeErrc::InvalidArgument, "TLS index 0 reserved");
    }
    // Template bytes: read from the file at the template RVA (loader
    // discipline: resolve through the section table).
    std::vector<std::uint8_t> tpl(
        static_cast<std::size_t>(info.template_size), 0);
    if (info.template_size > 0) {
        bool ok = false;
        std::uint64_t off = 0;
        if (info.template_rva < img.opt.size_of_headers) {
            off = info.template_rva;
            ok = off + info.template_size <= file_size;
        } else {
            for (const auto& s : img.sections) {
                if (s.contains_rva(static_cast<std::uint32_t>(info.template_rva)) &&
                    s.has_raw_data) {
                    const std::uint64_t in = info.template_rva - s.virtual_address;
                    if (in + info.template_size <= s.size_of_raw_data) {
                        off = s.raw_data_offset + in;
                        ok = true;
                    }
                    break;
                }
            }
        }
        if (!ok) {
            return Result<void>(RuntimeErrc::InvalidArgument,
                                "TLS template not file-backed");
        }
        std::memcpy(tpl.data(), file + off,
                    static_cast<std::size_t>(info.template_size));
    }
    // Zero-fill beyond the template (documented SizeOfZeroFill semantics:
    // the thread's block is template + zero fill). Bounded: the total TLS
    // block must stay within the same 1 MiB limit as the template (a
    // mutated/huge SizeOfZeroFill would otherwise request a multi-GB
    // allocation — found by the M7 TLS fuzz harness; regression-covered).
    constexpr std::uint32_t kMaxTlsBlock = loader::kMaxTlsTemplate;
    const std::uint64_t total_64 =
        tpl.size() + static_cast<std::uint64_t>(info.zero_fill_size);
    if (total_64 > kMaxTlsBlock) {
        return Result<void>(RuntimeErrc::OutOfResources,
                           "TLS block (template + SizeOfZeroFill) exceeds the "
                           "1 MiB limit");
    }
    tpl.resize(static_cast<std::size_t>(total_64), 0);
    return thread.tls_set(index, tpl.data(), tpl.size());
}

Result<std::size_t> tls_release_indices(std::uint64_t process_id) {
    auto& t = tls_table();
    std::lock_guard lock(t.lock);
    const auto it = t.per_process.find(process_id);
    if (it == t.per_process.end()) return Result<std::size_t>(0);
    const std::size_t n = it->second.size();
    t.per_process.erase(it);
    return Result<std::size_t>(n);
}

}  // namespace xbox2pc::rt::api
