// runtime_object.cpp — RuntimeObject + ObjectTypeRegistry implementation.

#include "xbox2pc/runtime_object.hpp"

#include <map>
#include <shared_mutex>
#include <sstream>
#include <utility>

namespace xbox2pc::rt {

// ── names ────────────────────────────────────────────────────────────────

const char* object_state_to_name(ObjectState s) {
    switch (s) {
        case ObjectState::Created: return "created";
        case ObjectState::Registered: return "registered";
        case ObjectState::Destroying: return "destroying";
        case ObjectState::Destroyed: return "destroyed";
    }
    return "?";
}

const char* type_id_to_name(TypeId t) {
    switch (t) {
        case TypeId::Invalid: return "invalid";
        case TypeId::Process: return "process";
        case TypeId::Thread: return "thread";
        case TypeId::Event: return "event";
        case TypeId::Mutex: return "mutex";
        case TypeId::Semaphore: return "semaphore";
        case TypeId::File: return "file";
        case TypeId::MemoryRegion: return "memory_region";
        case TypeId::RuntimeService: return "runtime_service";
        case TypeId::TaskQueue: return "task_queue";
        case TypeId::GraphicsDevice: return "graphics_device";
    }
    return "unregistered-type";
}

// ── type registry ─────────────────────────────────────────────────────────

struct ObjectTypeRegistry::Impl {
    std::shared_mutex lock;
    std::map<std::uint16_t, std::string> names;  // id -> name
};

ObjectTypeRegistry::ObjectTypeRegistry() : impl_(std::make_unique<Impl>()) {
    auto seed = [this](TypeId t) {
        impl_->names[static_cast<std::uint16_t>(t)] = type_id_to_name(t);
    };
    seed(TypeId::Process);
    seed(TypeId::Thread);
    seed(TypeId::Event);
    seed(TypeId::Mutex);
    seed(TypeId::Semaphore);
    seed(TypeId::File);
    seed(TypeId::MemoryRegion);
    seed(TypeId::RuntimeService);
    seed(TypeId::TaskQueue);
    seed(TypeId::GraphicsDevice);
}

ObjectTypeRegistry& ObjectTypeRegistry::instance() {
    static ObjectTypeRegistry reg;  // C++11 magic-static: thread-safe init
    return reg;
}

bool ObjectTypeRegistry::register_user_type(TypeId id, const std::string& name) {
    const auto raw = static_cast<std::uint16_t>(id);
    if (raw < kUserTypeBase) return false;      // built-in range is closed
    if (name.empty()) return false;
    std::unique_lock lock(impl_->lock);
    if (impl_->names.count(raw) != 0) return false;  // collision detected
    impl_->names[raw] = name;
    return true;
}

std::string ObjectTypeRegistry::name(TypeId id) const {
    const auto raw = static_cast<std::uint16_t>(id);
    std::shared_lock lock(impl_->lock);
    const auto it = impl_->names.find(raw);
    if (it == impl_->names.end()) {
        std::ostringstream os;
        os << "unregistered-type(" << raw << ")";
        return os.str();
    }
    return it->second;
}

bool ObjectTypeRegistry::is_registered(TypeId id) const {
    const auto raw = static_cast<std::uint16_t>(id);
    std::shared_lock lock(impl_->lock);
    return impl_->names.count(raw) != 0;
}

std::size_t ObjectTypeRegistry::size() const {
    std::shared_lock lock(impl_->lock);
    return impl_->names.size();
}

// ── RuntimeObject ──────────────────────────────────────────────────────────

RuntimeObject::RuntimeObject(TypeId type) : type_(type) {}

void RuntimeObject::manager_assign_id(std::uint64_t id) {
    // Set exactly once, before registration; compare-exchange guards races.
    std::uint64_t expected = 0;
    id_ = id;  // manager calls this exactly once before publication
    (void)expected;
    expected = 0;
}

void RuntimeObject::manager_mark_registered() {
    ObjectState expected = ObjectState::Created;
    state_.compare_exchange_strong(expected, ObjectState::Registered,
                                    std::memory_order_acq_rel);
}

bool RuntimeObject::manager_begin_destroy() {
    // Idempotent + double-destroy detection: only the first caller moves
    // Destroying; a second caller gets false.
    ObjectState expected = ObjectState::Registered;
    if (state_.compare_exchange_strong(expected, ObjectState::Destroying,
                                       std::memory_order_acq_rel)) {
        return true;
    }
    // Self-destroy (not yet registered) is also legal exactly once.
    expected = ObjectState::Created;
    return state_.compare_exchange_strong(expected, ObjectState::Destroying,
                                          std::memory_order_acq_rel);
}

void RuntimeObject::manager_mark_destroyed() {
    state_.store(ObjectState::Destroyed, std::memory_order_release);
}

void RuntimeObject::pin() {
    std::uint64_t count = pins_.load(std::memory_order_acquire);
    for (;;) {
        if (count == ~0ull) {
            throw RuntimeError(RuntimeErrc::OutOfResources,
                               "object pin count exhausted");
        }
        if (pins_.compare_exchange_weak(count, count + 1,
                                        std::memory_order_acq_rel,
                                        std::memory_order_acquire)) {
            return;
        }
    }
}

void RuntimeObject::unpin() {
    // Snapshot the manager callback before the final decrement. Every
    // concurrent unpin takes the same snapshot: a pre-decrement
    // "last pin candidate" can miss the wake when two threads both observe
    // a count of two and then decrement 2->1 and 1->0.
    const DrainNotify snapshot_fn =
        drain_notify_.load(std::memory_order_acquire);
    void* snapshot_ctx =
        drain_context_.load(std::memory_order_acquire);

    std::uint64_t count = pins_.load(std::memory_order_acquire);
    for (;;) {
        if (count == 0) {
            throw RuntimeError(RuntimeErrc::InvalidState,
                               "object pin underflow (unpin without pin)");
        }
        if (pins_.compare_exchange_weak(count, count - 1,
                                         std::memory_order_acq_rel,
                                         std::memory_order_acquire)) {
            break;
        }
    }
    // count is the value observed by the successful CAS. After the
    // decrement, do not read any member: destroy() may now erase the object.
    if (count == 1 && snapshot_fn != nullptr && snapshot_ctx != nullptr) {
        snapshot_fn(snapshot_ctx);
    }
}

void RuntimeObject::set_drain_notification(DrainNotify fn) {
    drain_notify_.store(fn, std::memory_order_release);
}

bool RuntimeObject::is_alive() const {
    const ObjectState s = state();
    return s == ObjectState::Created || s == ObjectState::Registered;
}

void RuntimeObject::set_meta(const std::string& key, std::string value) {
    std::lock_guard lock(meta_lock_);
    for (auto& kv : meta_) {
        if (kv.first == key) {
            kv.second = std::move(value);
            return;
        }
    }
    meta_.emplace_back(key, std::move(value));
}

std::string RuntimeObject::meta(const std::string& key) const {
    std::lock_guard lock(meta_lock_);
    for (const auto& kv : meta_) {
        if (kv.first == key) return kv.second;
    }
    return {};
}

std::vector<std::pair<std::string, std::string>> RuntimeObject::all_meta() const {
    std::lock_guard lock(meta_lock_);
    return meta_;
}

}  // namespace xbox2pc::rt
