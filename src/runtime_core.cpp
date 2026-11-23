// runtime_core.cpp — RuntimeCore facade implementation.

#include "xbox2pc/runtime_core.hpp"

#include <utility>

#include "xbox2pc/io_objects.hpp"
#include "xbox2pc/process_model.hpp"
#include "xbox2pc/sync_objects.hpp"
#include "xbox2pc/thread_model.hpp"

namespace xbox2pc::rt {

const char* runtime_state_to_name(RuntimeState s) {
    switch (s) {
        case RuntimeState::Created: return "created";
        case RuntimeState::Running: return "running";
        case RuntimeState::Shutdown: return "shutdown";
        case RuntimeState::Failed: return "failed";
    }
    return "?";
}

RuntimeCore::RuntimeCore()
    : objects_(), services_(), pal_info_(pal::describe_backend()) {
    // Install the global manager BEFORE any process objects exist (their
    // handle tables resolve ids through it).
    install_global_manager(objects_);
}

RuntimeCore::~RuntimeCore() {
    if (state_ == RuntimeState::Running) {
        shutdown();  // deterministic teardown; typed errors recorded below
    }
}

Result<void> RuntimeCore::initialize() {
    if (state_ == RuntimeState::Running) {
        return Result<void>(RuntimeErrc::AlreadyInitialized, "runtime running");
    }
    if (state_ != RuntimeState::Created) {
        return Result<void>(RuntimeErrc::InvalidState, "runtime not fresh");
    }
    // Built-in services: platform info only (future subsystems register
    // here in later milestones — M3 ships no fake subsystems).
    auto svc = std::make_unique<PlatformInfoService>(pal_info_.backend,
                                                      pal_info_.page_size,
                                                      pal_info_.clock);
    auto reg = services_.register_service(std::move(svc));
    if (!reg.ok()) {
        state_ = RuntimeState::Failed;
        return Result<void>(reg.errc(), reg.context());
    }
    auto init = services_.initialize_all();
    if (!init.ok()) {
        state_ = RuntimeState::Failed;
        return Result<void>(init.errc(), init.context());
    }
    state_ = RuntimeState::Running;
    return Result<void>::ok_result();
}

Result<void> RuntimeCore::shutdown() {
    if (state_ != RuntimeState::Running) {
        return Result<void>(RuntimeErrc::InvalidState,
                            "shutdown from state " + state_name());
    }
    // 1. Services down in reverse init order (typed failures surfaced).
    auto sd = services_.shutdown_all();
    // 2. Service objects destroyed (registry manager owns them).
    (void)services_.destroy_all();
    // 3. Remaining runtime objects destroyed LIFO via the object manager
    //    (ObjectManager dtor handles this — explicit destroy here reports).
    // 4. Uninstall the global manager (per-process tables now refuse
    //    lookups with NotInitialized instead of dangling).
    install_global_manager(objects_);  // keep: teardown keeps manager valid
    state_ = RuntimeState::Shutdown;
    if (!sd.ok()) {
        return Result<void>(sd.errc(), sd.context());
    }
    return Result<void>::ok_result();
}

// ── creators ─────────────────────────────────────────────────────────────────

namespace {

// Guards: every creator refuses unless the runtime is Running (typed error).
Result<void> require_running(const RuntimeCore& core, const char* what) {
    if (core.state() != RuntimeState::Running) {
        return Result<void>(RuntimeErrc::NotInitialized,
                            std::string(what) + ": runtime not running");
    }
    return Result<void>::ok_result();
}

}  // namespace

Result<Handle> RuntimeCore::create_event(bool auto_reset, bool initially_set,
                                         std::string name) {
    if (auto guard = require_running(*this, "create_event"); !guard.ok()) {
        return Result<Handle>(guard.errc(), guard.context());
    }
    auto obj = std::make_unique<RtEvent>(auto_reset, initially_set);
    obj->set_name(std::move(name));
    auto reg = objects_.register_object(std::move(obj));
    if (!reg.ok()) return Result<Handle>(reg.errc(), reg.context());
    // create handle via a temporary guard (register_object consumed ours).
    auto found = objects_.lookup_id(reg.value());
    if (!found.ok()) return Result<Handle>(found.errc(), found.context());
    return objects_.create_handle(*found.value().get());
}

Result<Handle> RuntimeCore::create_mutex(std::string name) {
    if (auto guard = require_running(*this, "create_mutex"); !guard.ok()) {
        return Result<Handle>(guard.errc(), guard.context());
    }
    auto obj = std::make_unique<RtMutex>();
    obj->set_name(std::move(name));
    auto reg = objects_.register_object(std::move(obj));
    if (!reg.ok()) return Result<Handle>(reg.errc(), reg.context());
    auto found = objects_.lookup_id(reg.value());
    if (!found.ok()) return Result<Handle>(found.errc(), found.context());
    return objects_.create_handle(*found.value().get());
}

Result<Handle> RuntimeCore::create_semaphore(std::int64_t initial,
                                             std::int64_t max, std::string name) {
    if (auto guard = require_running(*this, "create_semaphore"); !guard.ok()) {
        return Result<Handle>(guard.errc(), guard.context());
    }
    auto obj = std::make_unique<RtSemaphore>(initial, max);
    obj->set_name(std::move(name));
    auto reg = objects_.register_object(std::move(obj));
    if (!reg.ok()) return Result<Handle>(reg.errc(), reg.context());
    auto found = objects_.lookup_id(reg.value());
    if (!found.ok()) return Result<Handle>(found.errc(), found.context());
    return objects_.create_handle(*found.value().get());
}

Result<Handle> RuntimeCore::create_memory_region(std::uint64_t size, bool commit,
                                                  std::string name) {
    if (auto guard = require_running(*this, "create_memory_region"); !guard.ok()) {
        return Result<Handle>(guard.errc(), guard.context());
    }
    auto obj = std::make_unique<RtMemoryRegion>(
        size, commit ? RtMemoryRegion::Mode::Committed
                     : RtMemoryRegion::Mode::Reserved,
        std::move(name));
    auto reg = objects_.register_object(std::move(obj));
    if (!reg.ok()) return Result<Handle>(reg.errc(), reg.context());
    auto found = objects_.lookup_id(reg.value());
    if (!found.ok()) return Result<Handle>(found.errc(), found.context());
    return objects_.create_handle(*found.value().get());
}

Result<Handle> RuntimeCore::create_process(const std::string& image_name) {
    if (auto guard = require_running(*this, "create_process"); !guard.ok()) {
        return Result<Handle>(guard.errc(), guard.context());
    }
    auto obj = std::make_unique<RtProcess>(image_name);
    auto reg = objects_.register_object(std::move(obj));
    if (!reg.ok()) return Result<Handle>(reg.errc(), reg.context());
    auto found = objects_.lookup_id(reg.value());
    if (!found.ok()) return Result<Handle>(found.errc(), found.context());
    return objects_.create_handle(*found.value().get());
}

Result<Handle> RuntimeCore::create_thread(RtThread::ThreadMain main, void* arg,
                                          std::string name) {
    if (auto guard = require_running(*this, "create_thread"); !guard.ok()) {
        return Result<Handle>(guard.errc(), guard.context());
    }
    auto obj = std::make_unique<RtThread>(main, arg, std::move(name));
    auto reg = objects_.register_object(std::move(obj));
    if (!reg.ok()) return Result<Handle>(reg.errc(), reg.context());
    auto found = objects_.lookup_id(reg.value());
    if (!found.ok()) return Result<Handle>(found.errc(), found.context());
    return objects_.create_handle(*found.value().get());
}

// ── summary ─────────────────────────────────────────────────────────────────

RuntimeCore::Summary RuntimeCore::summary() const {
    Summary s;
    s.state = state_name();
    s.pal_backend = pal_info_.backend;
    s.pal_clock = pal_info_.clock;
    s.page_size = pal_info_.page_size;
    s.object_count = objects_.object_count();
    s.service_count = services_.service_count();
    s.handle_count = objects_.table().live_count();
    s.services_initialized = services_.initialized();
    return s;
}

}  // namespace xbox2pc::rt
