#pragma once
// xbox2pc/service_registry.hpp — M3 runtime service registry.
//
// Design (docs/service-registry.md):
//   - Services are named runtime objects (TypeId::RuntimeService) with:
//     unique id (name), type-safe registration (typed factories),
//     declared dependencies, lifecycle (Registered -> Initializing ->
//     Ready -> Shutdown -> Destroyed), and explicit init/shutdown ordering.
//   - Initialization order: topological (dependencies first); missing
//     dependencies are reported per-service; cycles are detected and
//     reported as a whole (CircularDependency).
//   - Shutdown order: exact reverse of successful initialization.
//   - Type safety: services implement RtService; typed lookup returns the
//     concrete subclass pointer after a dynamic type-name check.
//   - Future subsystems (graphics, audio, input, storage, networking,
//     GDK compatibility, game runtime) will register HERE; M3 ships the
//     registry + a minimal PlatformInfoService only (no fake subsystems).

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/handle_manager.hpp"

namespace xbox2pc::rt {

// ── service lifecycle states ──────────────────────────────────────────────
enum class ServiceState {
    Registered,   // declared, not yet initialized
    Initializing, // on_initialize() running
    Ready,        // usable
    ShuttingDown, // on_shutdown() running
    Shutdown,     // stopped, still registered
    Failed,       // init or shutdown error
};

const char* service_state_to_name(ServiceState s);

// ── base service ──────────────────────────────────────────────────────────
class RtService : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtService, RuntimeService)

    explicit RtService(std::string service_name);
    ~RtService() override = default;

    const std::string& service_name() const { return service_; }

    // Dependencies (names) this service declares at registration.
    const std::vector<std::string>& dependencies() const { return deps_; }
    void declare_dependency(const std::string& name) { deps_.push_back(name); }

    // Lifecycle hooks (registry drives the state machine and ordering).
    virtual Result<void> on_initialize() { return Result<void>::ok_result(); }
    virtual Result<void> on_shutdown() { return Result<void>::ok_result(); }

    ServiceState service_state() const { return service_state_; }
    void set_service_state(ServiceState s) { service_state_ = s; }

    // Last error recorded by the registry (init/shutdown failures).
    const std::string& last_error() const { return last_error_; }
    void record_error(std::string e) { last_error_ = std::move(e); }

private:
    const std::string service_;
    std::vector<std::string> deps_;
    ServiceState service_state_ = ServiceState::Registered;
    std::string last_error_;
};

// ── registry ───────────────────────────────────────────────────────────────
class ServiceRegistry {
public:
    ServiceRegistry();
    ~ServiceRegistry();

    ServiceRegistry(const ServiceRegistry&) = delete;
    ServiceRegistry& operator=(const ServiceRegistry&) = delete;

    // ── registration (type-safe: RtService subclasses only) ──
    // Registers a constructed service + its declared dependencies.
    // Duplicates and empty names return typed errors.
    Result<std::uint64_t> register_service(std::unique_ptr<RtService> svc);

    // Declares a service that does not exist yet (forward declaration for
    // cycles/optional pairs). Resolved at init; unresolved -> MissingDependency.
    Result<void> declare_service_name(const std::string& name);

    // ── dependency analysis (before init; also used by tests/CLI) ──
    // Topological order of all registered services; cycles reported as an
    // error result listing the cycle members.
    Result<std::vector<std::string>> initialization_order() const;

    // Missing dependencies across all services (name -> missing dep).
    std::vector<std::pair<std::string, std::string>> missing_dependencies() const;

    // ── lifecycle ──
    // Initializes every service in dependency order; on failure the failing
    // service (and everything depending on it) reports Failed and the
    // already-initialized services are shut down in reverse order.
    Result<void> initialize_all();
    // Shuts down in exact reverse of initialization order (idempotent).
    Result<void> shutdown_all();

    // ── lookup ──
    Result<RefGuard> find(const std::string& name) const;

    // Typed lookup: dynamic_type_name must match T::service_type_name().
    template <typename T>
    Result<T*> find_typed(const std::string& name) const {
        auto r = find(name);
        if (!r.ok()) return Result<T*>(r.errc(), r.context());
        RefGuard& g = r.value();
        if (g.get() == nullptr) {
            return Result<T*>(RuntimeErrc::ObjectDestroyed, "service destroyed");
        }
        auto* svc = g.get()->as<RtService>();
        if (svc == nullptr) {
            return Result<T*>(RuntimeErrc::ObjectTypeMismatch, "not a service");
        }
        T* typed = dynamic_cast<T*>(svc);
        if (typed == nullptr) {
            return Result<T*>(RuntimeErrc::ObjectTypeMismatch,
                              "service type mismatch for '" + name + "'");
        }
        return Result<T*>(typed);
    }

    // ── introspection ──
    struct ServiceInfo {
        std::string name;
        std::uint64_t object_id;
        ServiceState state;
        std::vector<std::string> dependencies;
        std::string last_error;
    };
    std::vector<ServiceInfo> list_services() const;
    std::size_t service_count() const;

    // Whether initialize_all has run successfully.
    bool initialized() const { return initialized_; }

    // Object manager backing service objects (each registry owns one; the
    // runtime facade may share a manager — see runtime_core.hpp).
    ObjectManager& object_manager() { return objects_; }

    // Full teardown (shutdown_all + destroy objects).
    Result<void> destroy_all();

    // Name -> object id (Entry::object_id, with a safe fallback scan).
    std::uint64_t entry_object_id(const std::string& name) const;

private:
    struct Entry {
        std::vector<std::string> deps;
        std::uint64_t object_id = 0;   // manager-assigned id
        bool forward_declared = false;  // name declared, no instance yet
    };

    mutable std::mutex lock_;
    std::map<std::string, Entry> services_;
    std::vector<std::string> init_order_;   // successful init order (reverse = shutdown)
    bool initialized_ = false;
    ObjectManager objects_;
};

// ── minimal built-in services (no fake subsystems) ────────────────────────
//
// PlatformInfoService exposes the PAL backend facts — the ONLY built-in
// service; future graphics/audio/... register themselves later.
class PlatformInfoService : public RtService {
public:
    explicit PlatformInfoService(std::string pal_backend,
                                 std::uint64_t page_size,
                                 std::string clock_desc);
    static const char* service_type_name() { return "platform_info"; }

    // PAL facts (captured at runtime construction).
    const std::string& pal_backend() const { return backend_; }
    std::uint64_t page_size() const { return page_; }
    const std::string& clock_desc() const { return clock_; }

private:
    const std::string backend_;
    const std::uint64_t page_;
    const std::string clock_;
};

}  // namespace xbox2pc::rt
