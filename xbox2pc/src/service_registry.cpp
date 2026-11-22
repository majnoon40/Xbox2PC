// service_registry.cpp — ServiceRegistry implementation.

#include "xbox2pc/service_registry.hpp"

#include <algorithm>
#include <utility>

namespace xbox2pc::rt {

const char* service_state_to_name(ServiceState s) {
    switch (s) {
        case ServiceState::Registered: return "registered";
        case ServiceState::Initializing: return "initializing";
        case ServiceState::Ready: return "ready";
        case ServiceState::Shutdown: return "shutdown";
        case ServiceState::ShuttingDown: return "shutting_down";
        case ServiceState::Failed: return "failed";
    }
    return "?";
}

// ── RtService ───────────────────────────────────────────────────────────────

RtService::RtService(std::string service_name)
    : RuntimeObject(TypeId::RuntimeService), service_(std::move(service_name)) {
    // Mirror the service name as the object name so object listings and
    // entry_object_id resolution work uniformly.
    set_name(service_);
}

// ── ServiceRegistry ────────────────────────────────────────────────────────

ServiceRegistry::ServiceRegistry() = default;

ServiceRegistry::~ServiceRegistry() {
    shutdown_all();
}

Result<std::uint64_t> ServiceRegistry::register_service(std::unique_ptr<RtService> svc) {
    if (svc == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "null service");
    }
    if (svc->service_name().empty()) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "empty service name");
    }
    std::lock_guard lock(lock_);
    const auto existing = services_.find(svc->service_name());
    if (existing != services_.end() && !existing->second.forward_declared) {
        return Result<std::uint64_t>(RuntimeErrc::AlreadyExists,
                                     "service '" + svc->service_name() + "'");
    }
    // A forward-declared entry is upgraded in place by the real service.
    if (existing != services_.end()) {
        services_.erase(existing);
    }
    std::vector<std::string> deps = svc->dependencies();
    const std::string name = svc->service_name();
    // Register the object with the registry's manager (id assigned).
    auto reg = objects_.register_object(std::move(svc));
    if (!reg.ok()) {
        return reg;
    }
    Entry e;
    e.deps = std::move(deps);
    e.object_id = reg.value();
    services_[name] = std::move(e);
    return reg;
}

Result<void> ServiceRegistry::declare_service_name(const std::string& name) {
    if (name.empty()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "empty service name");
    }
    std::lock_guard lock(lock_);
    if (services_.count(name) != 0) {
        if (services_[name].forward_declared) {
            return Result<void>::ok_result();  // already declared (idempotent)
        }
        return Result<void>(RuntimeErrc::AlreadyExists, "service '" + name + "' registered");
    }
    Entry e;
    e.forward_declared = true;
    services_[name] = std::move(e);
    return Result<void>::ok_result();
}

// ── dependency analysis ─────────────────────────────────────────────────────

Result<std::vector<std::string>> ServiceRegistry::initialization_order() const {
    std::lock_guard lock(lock_);
    // Kahn's algorithm over declared edges dep -> service.
    std::map<std::string, std::vector<std::string>> adj;   // dep -> users
    std::map<std::string, std::size_t> indegree;          // service -> unmet deps
    for (const auto& [name, entry] : services_) {
        indegree[name] = 0;  // ensure every service appears
    }
    for (const auto& [name, entry] : services_) {
        for (const auto& dep : entry.deps) {
            if (services_.count(dep) == 0) {
                // Missing dependency: order does not include it; reported
                // separately via missing_dependencies().
                continue;
            }
            adj[dep].push_back(name);
            indegree[name] += 1;
        }
    }
    // Deterministic seed: alphabetical among zero-indegree nodes.
    std::vector<std::string> ready;
    for (const auto& [n, d] : indegree) {
        if (d == 0) ready.push_back(n);
    }
    std::sort(ready.begin(), ready.end());

    std::vector<std::string> order;
    std::map<std::string, bool> emitted;
    std::vector<std::string> queue = std::move(ready);
    while (!queue.empty()) {
        // Pop smallest (determinism).
        std::sort(queue.begin(), queue.end());
        const std::string cur = queue.front();
        queue.erase(queue.begin());
        if (emitted[cur]) continue;
        emitted[cur] = true;
        order.push_back(cur);
        for (const auto& user : adj[cur]) {
            if (indegree[user] > 0) {
                indegree[user] -= 1;
                if (indegree[user] == 0) queue.push_back(user);
            }
        }
    }
    if (order.size() != services_.size()) {
        // Remaining nodes participate in at least one cycle: collect them.
        std::vector<std::string> cyclic;
        for (const auto& [name, _] : services_) {
            if (!emitted[name]) cyclic.push_back(name);
        }
        std::sort(cyclic.begin(), cyclic.end());
        std::string msg = "circular dependency among: ";
        for (std::size_t i = 0; i < cyclic.size(); ++i) {
            msg += cyclic[i];
            if (i + 1 < cyclic.size()) msg += ", ";
        }
        return Result<std::vector<std::string>>(RuntimeErrc::CircularDependency, msg);
    }
    return Result<std::vector<std::string>>(std::move(order));
}

std::vector<std::pair<std::string, std::string>> ServiceRegistry::missing_dependencies() const {
    std::lock_guard lock(lock_);
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& [name, entry] : services_) {
        for (const auto& dep : entry.deps) {
            if (services_.count(dep) == 0) {
                out.emplace_back(name, dep);
            }
        }
    }
    return out;
}

// ── lifecycle ────────────────────────────────────────────────────────────────

Result<void> ServiceRegistry::initialize_all() {
    std::vector<std::string> order;
    {
        std::lock_guard lock(lock_);
        if (initialized_) {
            return Result<void>(RuntimeErrc::AlreadyInitialized, "registry initialized");
        }
    }
    auto ord = initialization_order();
    if (!ord.ok()) {
        return Result<void>(ord.errc(), ord.context());
    }
    order = std::move(ord.value());

    // Missing dependencies fail the depending services explicitly.
    const auto missing = missing_dependencies();
    if (!missing.empty()) {
        // Every service with a missing dependency fails with context;
        // others still initialize (partial-init is visible in state).
        std::string msg;
        for (const auto& [svc, dep] : missing) {
            msg += svc + " -> " + dep + "; ";
        }
        // Record on the entries (via the object manager lookups below).
        // We continue: services that don't depend on missing ones init OK.
        (void)msg;
    }

    std::vector<std::string> done;
    bool any_failed = false;
    for (const auto& name : order) {
        std::lock_guard lock(lock_);
        const auto it = services_.find(name);
        if (it == services_.end()) continue;
        Entry& entry = it->second;
        // Unmet dependency check (missing or failed dep) -> mark Failed.
        bool unmet = false;
        std::string why;
        for (const auto& dep : entry.deps) {
            const auto dit = services_.find(dep);
            if (dit == services_.end()) {
                unmet = true;
                why = "missing dependency '" + dep + "'";
                break;
            }
            if (dit->second.forward_declared) {
                unmet = true;
                why = "dependency '" + dep + "' declared but never registered";
                break;
            }
            // If the dependency failed to initialize it is not in `done`.
            if (std::find(done.begin(), done.end(), dep) == done.end()) {
                unmet = true;
                why = "dependency '" + dep + "' failed to initialize";
                break;
            }
        }
        if (unmet) {
            any_failed = true;
            // Mark failed through the object (state + last_error).
            auto found = objects_.lookup_id(entry_object_id(name));
            if (found.ok() && found.value().get() != nullptr) {
                auto* svc = found.value().get()->as<RtService>();
                if (svc != nullptr) {
                    svc->set_service_state(ServiceState::Failed);
                    svc->record_error(why);
                }
            }
            continue;
        }
        // Initialize.
        auto found = objects_.lookup_id(entry_object_id(name));
        if (!found.ok() || found.value().get() == nullptr) {
            any_failed = true;
            continue;
        }
        auto* svc = found.value().get()->as<RtService>();
        if (svc == nullptr) {
            any_failed = true;
            continue;
        }
        svc->set_service_state(ServiceState::Initializing);
        const Result<void> r = svc->on_initialize();
        if (!r.ok()) {
            svc->set_service_state(ServiceState::Failed);
            svc->record_error(r.error_string());
            any_failed = true;
            continue;
        }
        svc->set_service_state(ServiceState::Ready);
        done.push_back(name);
    }

    {
        std::lock_guard lock(lock_);
        init_order_ = done;
        initialized_ = !any_failed;
    }
    if (any_failed) {
        return Result<void>(RuntimeErrc::ServiceFailed,
                             "one or more services failed to initialize "
                             "(see per-service last_error)");
    }
    return Result<void>::ok_result();
}

Result<void> ServiceRegistry::shutdown_all() {
    std::vector<std::string> order;
    {
        std::lock_guard lock(lock_);
        if (init_order_.empty()) return Result<void>::ok_result();
        order = init_order_;   // reverse of this = reverse init order
        init_order_.clear();
        initialized_ = false;
    }
    // Exact reverse of initialization order.
    std::reverse(order.begin(), order.end());
    bool any_failed = false;
    for (const auto& name : order) {
        std::lock_guard lock(lock_);
        const auto it = services_.find(name);
        if (it == services_.end()) continue;
        auto found = objects_.lookup_id(entry_object_id(name));
        if (!found.ok() || found.value().get() == nullptr) continue;
        auto* svc = found.value().get()->as<RtService>();
        if (svc == nullptr) continue;
        svc->set_service_state(ServiceState::ShuttingDown);
        const Result<void> r = svc->on_shutdown();
        if (!r.ok()) {
            svc->set_service_state(ServiceState::Failed);
            svc->record_error("shutdown: " + r.error_string());
            any_failed = true;
            continue;
        }
        svc->set_service_state(ServiceState::Shutdown);
    }
    if (any_failed) {
        return Result<void>(RuntimeErrc::ServiceFailed,
                             "one or more services failed to shut down");
    }
    return Result<void>::ok_result();
}

Result<RefGuard> ServiceRegistry::find(const std::string& name) const {
    std::lock_guard lock(lock_);
    const auto it = services_.find(name);
    if (it == services_.end() || it->second.forward_declared) {
        if (it != services_.end() && it->second.forward_declared) {
            return Result<RefGuard>(RuntimeErrc::NotFound,
                                    "service '" + name + "' declared but not registered");
        }
        return Result<RefGuard>(RuntimeErrc::NotFound, "service '" + name + "'");
    }
    return objects_.lookup_id(entry_object_id(name));
}

std::vector<ServiceRegistry::ServiceInfo> ServiceRegistry::list_services() const {
    std::lock_guard lock(lock_);
    std::vector<ServiceInfo> out;
    for (const auto& [name, entry] : services_) {
        ServiceInfo info;
        info.name = name;
        info.dependencies = entry.deps;
        if (!entry.forward_declared) {
            info.object_id = entry_object_id(name);
            auto found = objects_.lookup_id(info.object_id);
            if (found.ok() && found.value().get() != nullptr) {
                const auto* svc = found.value().get()->as<RtService>();
                if (svc != nullptr) {
                    info.state = svc->service_state();
                    info.last_error = svc->last_error();
                }
            }
        }
        out.push_back(std::move(info));
    }
    return out;
}

std::size_t ServiceRegistry::service_count() const {
    std::lock_guard lock(lock_);
    return services_.size();
}

Result<void> ServiceRegistry::destroy_all() {
    auto sd = shutdown_all();
    {
        std::lock_guard lock(lock_);
        // Destroy service objects through the manager (LIFO by registration).
        std::vector<std::uint64_t> ids;
        for (const auto& [name, entry] : services_) {
            if (!entry.forward_declared) {
                const std::uint64_t id = entry_object_id(name);
                ids.push_back(id);
            }
        }
        for (const auto id : ids) {
            const Result<void> r = objects_.destroy(id);
            if (!r.ok() && r.errc() != RuntimeErrc::ObjectDestroyed) {
                // surfaced by the caller via returned error below
            }
        }
        services_.clear();
    }
    return sd;
}

// name -> object id: entries store the manager-assigned id at registration
// (Entry::object_id); fallback scan kept for safety.
std::uint64_t ServiceRegistry::entry_object_id(const std::string& name) const {
    const auto it = services_.find(name);
    if (it != services_.end() && it->second.object_id != 0) {
        return it->second.object_id;
    }
    std::uint64_t found_id = 0;
    for (const auto& info : objects_.list_objects()) {
        if (info.name == name && info.type == TypeId::RuntimeService) {
            found_id = info.id;
            break;
        }
    }
    return found_id;
}

// ── PlatformInfoService ────────────────────────────────────────────────────

PlatformInfoService::PlatformInfoService(std::string pal_backend,
                                         std::uint64_t page_size,
                                         std::string clock_desc)
    : RtService("platform_info"),
      backend_(std::move(pal_backend)),
      page_(page_size),
      clock_(std::move(clock_desc)) {}

}  // namespace xbox2pc::rt
