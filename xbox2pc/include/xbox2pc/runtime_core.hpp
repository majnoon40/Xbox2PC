#pragma once
// xbox2pc/runtime_core.hpp — M3 RuntimeCore facade.
//
// The single entry point that owns and sequences the runtime subsystems
// (docs/architecture.md §initialization):
//
//   Construction:
//     RuntimeCore()
//       - captures PAL backend info
//       - installs the global object manager (for per-process handle tables)
//   initialize():
//       1. ServiceRegistry: register PlatformInfoService (built-in, no deps)
//       2. service_registry.initialize_all()  (topological; cycles/missing
//          dependencies reported as typed errors, never ignored)
//     After initialize(): runtime is Running.
//   shutdown():
//       1. service_registry.shutdown_all()  (exact reverse init order)
//       2. destroy all objects LIFO via the object manager
//       3. uninstalls the global manager
//     After shutdown(): state is Shutdown; using the core returns
//     NotInitialized errors (never undefined behavior).
//
// Facade exposes the subsystems for component tests and the CLI; layers do
// NOT reach into each other's internals (no circular deps: object manager
// and handle tables form the bottom; sync/thread/process objects sit above
// them; the service registry sits above those; the facade owns all).

#include <memory>
#include <string>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/service_registry.hpp"
#include "xbox2pc/thread_model.hpp"

namespace xbox2pc::rt {

enum class RuntimeState { Created, Running, Shutdown, Failed };

const char* runtime_state_to_name(RuntimeState s);

class RuntimeCore {
public:
    RuntimeCore();
    ~RuntimeCore();  // shutdown() if still running (never silently leaks)

    RuntimeCore(const RuntimeCore&) = delete;
    RuntimeCore& operator=(const RuntimeCore&) = delete;

    // ── lifecycle ──
    Result<void> initialize();
    Result<void> shutdown();

    RuntimeState state() const { return state_; }
    std::string state_name() const { return runtime_state_to_name(state_); }

    // ── subsystem access ──
    ObjectManager& objects() { return objects_; }
    const ObjectManager& objects() const { return objects_; }
    ServiceRegistry& services() { return services_; }
    const ServiceRegistry& services() const { return services_; }

    // ── convenience creators (each registers + returns a handle) ──
    // All refuse when the runtime is not Running (typed errors, no UB).
    Result<Handle> create_event(bool auto_reset, bool initially_set,
                                std::string name);
    Result<Handle> create_mutex(std::string name);
    Result<Handle> create_semaphore(std::int64_t initial, std::int64_t max,
                                    std::string name);
    Result<Handle> create_memory_region(std::uint64_t size, bool commit,
                                        std::string name);

    // Process creation: registers the process object + installs its module
    // descriptor (M1/M2 metadata) via initialize() on RtProcess.
    Result<Handle> create_process(const std::string& image_name);
    Result<Handle> create_thread(RtThread::ThreadMain main, void* arg,
                                 std::string name);

    // ── summary (CLI runtime-info) ──
    struct Summary {
        std::string state;
        std::string pal_backend;
        std::string pal_clock;
        std::uint64_t page_size;
        std::size_t object_count;
        std::size_t service_count;
        std::size_t handle_count;
        bool services_initialized;
    };
    Summary summary() const;

private:
    RuntimeState state_ = RuntimeState::Created;
    ObjectManager objects_;
    ServiceRegistry services_;
    pal::PalInfo pal_info_;
};

}  // namespace xbox2pc::rt
