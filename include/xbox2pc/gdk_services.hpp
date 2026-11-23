#pragma once
// xbox2pc/gdk_services.hpp — M7 GDK + Game OS compatibility services.
//
// Real RtService implementations of the documented GDK APIs in
// api_compat.hpp's descriptor table. Services register implementations
// into an ApiRegistry at initialize() and REVOKE them at shutdown (the
// registry never dangles). Per-process state (GDK runtime init count,
// time-sensitive bits, task-queue handles) lives on the service and is
// keyed by the M4 process id where the documented semantics are
// per-process (XGameRuntimeInitialize ref-counting is documented
// per-process: "each binary ... should call XGameRuntimeInitialize").
//
// Layering: gdk_services links rt_api (api_compat), rt_services (M3
// registry types), rt_procman/rt_thread (M4 thread state), rt_pal
// (host clock), pe_parser (delay-load decode helper types). It creates
// no managers of its own.

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/api_compat.hpp"
#include "xbox2pc/platform.hpp"
#include "xbox2pc/process_management.hpp"
#include "xbox2pc/service_registry.hpp"
#include "xbox2pc/thread_model.hpp"

namespace xbox2pc::rt::api {

// ── shared implementation helpers ──────────────────────────────────────────

// S_OK / documented HRESULT failure bits (from the GDK error codes doc
// pattern; the values below are the standard HRESULT layout).
inline constexpr std::uint64_t kSOk = 0x00000000ull;
inline constexpr std::uint64_t kEGameruntimeDllNotFound = 0x80073D0Full;
inline constexpr std::uint64_t kEAbort = 0x8000000ABull;  // E_ABORT raw
inline constexpr std::uint64_t kEInsufficientBuffer = 0x8007007Aull; // HRESULT_FROM_WIN32(122)
inline constexpr std::uint64_t kEInvalidArg = 0x80070057ull;

// XSystemDeviceType documented values (enum page, gdk-2610).
enum class XSystemDeviceType : std::uint32_t {
    Unknown = 0x00,
    Pc = 0x01,
    XboxOne = 0x02,
    XboxOneS = 0x03,
    XboxOneX = 0x04,
    XboxOneXDevkit = 0x05,
    XboxScarlettLockhart = 0x06,
    XboxScarlettAnaconda = 0x07,
    XboxScarlettDevkit = 0x08,
};
const char* device_type_to_name(XSystemDeviceType t);

// XTaskQueuePort documented enum values.
enum class XTaskQueuePort : std::uint32_t { Work = 0, Completion = 1 };
// XTaskQueueDispatchMode documented values (subset used).
enum class XTaskQueueDispatchMode : std::uint32_t {
    Unknown = 0,
    Immediate = 1,
    Manual = 2,
    ThreadPool = 3,
};

// ── GameRuntimeService (lifecycle + XSystem + XThread) ───────────────────

// Implements the documented lifecycle/system/thread APIs. Per-process
// state: the documented init/uninit ref-count pair, options mismatch
// marker, per-thread time-sensitive bits (M4 thread ids).
struct MemoryQuerySnapshot {
    std::uint64_t base = 0;
    std::uint64_t capacity = 0;
    std::uint64_t page_size = 0;
    std::vector<VmRegion> regions;
};

class GameRuntimeService : public RtService {
public:
    static const char* service_type_name() { return "gdk_game_runtime"; }

    GameRuntimeService(ApiRegistry& api_reg, ProcessManager& process_manager);
    ~GameRuntimeService() override;

    Result<void> on_initialize() override;   // registers implementations
    Result<void> on_shutdown() override;    // revokes them

    // ── documented API implementations (bound through IApiImplementation) ──
    // XGameRuntimeInitialize: ref-count per process (doc: each component
    // should call it; float to existing options).
    Result<std::uint64_t> grt_initialize(std::uint64_t process_id);
    // XGameRuntimeUninitialize: decrement; terminal-failure note documented.
    Result<void> grt_uninitialize(std::uint64_t process_id);
    // XSystemGetDeviceType: stub returning Unknown (documented fallback).
    XSystemDeviceType device_type() const { return XSystemDeviceType::Unknown; }
    // XSystemGetConsoleId / SandboxId / AppSpecificDeviceId: documented
    // all-zero / RETAIL / all-zero fallbacks with size validation.
    Result<std::string> console_id(std::uint64_t size, std::uint64_t* used);
    Result<std::string> sandbox_id(std::uint64_t size, std::uint64_t* used);
    Result<std::string> app_device_id(std::uint64_t size, std::uint64_t* used);
    // XSystemGetRuntimeInfo: stub struct (version zeros, documented shape).
    struct RuntimeInfo {
        std::uint32_t current_major = 0;
        std::uint32_t current_minor = 0;
    };
    RuntimeInfo runtime_info() const { return {}; }
    // XThread time-sensitive bits are scoped by (process, calling thread).
    Result<void> set_time_sensitive(std::uint64_t process_id,
                                    std::uint64_t thread_id, bool on);
    Result<bool> is_time_sensitive(std::uint64_t process_id,
                                   std::uint64_t thread_id) const;
    // Remove process-owned GDK state during M4 process teardown.
    void release_process(std::uint64_t process_id);
    Result<VmRegion> query_memory_region(std::uint64_t process_id, std::uint64_t guest_address) const;
    Result<MemoryQuerySnapshot> query_memory_snapshot(std::uint64_t process_id) const;

    // Registry back-reference (tests/introspection).
    ApiRegistry& registry() { return api_reg_; }

private:
    struct ProcState {
        std::uint64_t init_count = 0;
        bool uninit_failed_terminal = false;  // documented terminal state
    };
    ApiRegistry& api_reg_;
    ProcessManager& process_manager_;
    std::uint64_t process_exit_observer_id_ = 0;
    mutable std::mutex state_lock_;
    std::map<std::uint64_t, ProcState> procs_;
    std::map<std::pair<std::uint64_t, std::uint64_t>, bool> ts_bits_; // (pid, tid)
    std::vector<std::shared_ptr<IApiImplementation>> owned_;
};

// ── TaskQueueService (XTaskQueue) ─────────────────────────────────────────

// Process-owned manual-mode task queue handles. Empty dispatch returns
// false because guest callback submission/execution is not implemented;
// unsupported dispatch modes are rejected rather than simulated.
class TaskQueueService : public RtService {
public:
    static const char* service_type_name() { return "gdk_task_queue"; }

    explicit TaskQueueService(ApiRegistry& api_reg,
                               ProcessManager& pm);
    ~TaskQueueService() override;

    Result<void> on_initialize() override;
    Result<void> on_shutdown() override;

    // Queue handle ids (XTaskQueueHandle modeled as uint64 ids; the
    // runtime's own handle system is used for ownership).
    Result<std::uint64_t> create_queue(std::uint64_t process_id,
                                        std::uint32_t work_mode,
                                        std::uint32_t completion_mode);
    // Dispatch is currently an empty-queue model: it validates ownership
    // and port, then returns false because guest callback execution is not
    // implemented yet.
    Result<bool> dispatch(std::uint64_t process_id, std::uint64_t queue_id,
                          XTaskQueuePort port, std::uint32_t timeout_ms);
    Result<void> close_queue(std::uint64_t process_id, std::uint64_t queue_id);
    Result<void> terminate_queue(std::uint64_t process_id,
                                 std::uint64_t queue_id, bool wait);
    // Remove all queue handles owned by a process after successful exit.
    void release_process(std::uint64_t process_id);

    std::size_t live_queues() const;

private:
    struct Queue {
        std::uint64_t owner_process_id = 0;
        bool terminated = false;
        std::uint32_t work_mode = 0;
        std::uint32_t completion_mode = 0;
    };
    ApiRegistry& api_reg_;
    ProcessManager& pm_;
    mutable std::mutex lock_;
    std::map<std::uint64_t, Queue> queues_;
    std::uint64_t next_id_ = 1;
    std::uint64_t process_exit_observer_id_ = 0;
    std::vector<std::shared_ptr<IApiImplementation>> owned_;
};

// ── TimingService (QPC pair native equivalents) ─────────────────────────

class TimingService : public RtService {
public:
    static const char* service_type_name() { return "win32_timing"; }

    explicit TimingService(ApiRegistry& api_reg);
    ~TimingService() override;

    Result<void> on_initialize() override;
    Result<void> on_shutdown() override;

    // Documented semantics via the PAL (host CLOCK_MONOTONIC).
    Result<std::uint64_t> qpc_value();
    Result<std::uint64_t> qpc_frequency();

private:
    ApiRegistry& api_reg_;
    std::vector<std::shared_ptr<IApiImplementation>> owned_;
};

// ── TLS per-thread initialization ────────────────────────────────────────

// Materialize one image's TLS for a thread: copy the template into the
// thread's slot for the image's TLS index, zero-fill beyond it (documented
// SizeOfZeroFill semantics), tracking indices per (process, image-name).
// Thread death frees the slot (M4 thread model's tls_ map already dies
// with the thread object).
struct TlsModuleInfo {
    std::string image_name;
    std::uint32_t index = 0;
    std::uint64_t template_rva = 0;
    std::uint64_t template_size = 0;
    std::uint32_t zero_fill = 0;
    std::uint32_t callbacks = 0;   // counted, never executed (M6 rule)
};
Result<std::uint32_t> tls_assign_index(std::uint64_t process_id,
                                       const std::string& image_name,
                                       const loader::TlsInfo& info);
Result<void> tls_init_thread(RtThread& thread, std::uint32_t index,
                             const pe::PeImage& img, const std::uint8_t* file,
                             std::size_t file_size, const loader::TlsInfo& info);
Result<std::size_t> tls_release_indices(std::uint64_t process_id);

}  // namespace xbox2pc::rt::api
