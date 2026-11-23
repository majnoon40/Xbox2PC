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

void RuntimeObject::pin() { pins_.fetch_add(1, std::memory_order_acq_rel); }

void RuntimeObject::unpin() {
    // M4 use-after-free fix (2 rounds, see docs/runtime-object-model.md):
    // after the pin decrement a concurrent destroy() may erase+delete the
    // object, so EVERYTHING the wake path needs is snapshotted BEFORE the
    // decrement, and the callback receives the snapshot (never `this`):
    //   1. candidate-last-pin check + state + fn + context (all reads);
    //   2. the decrement itself (the object's final legal touch);
    //   3. fn(context) — touches only the manager, never this object.
    const bool last_pin_candidate = pins_.load(std::memory_order_acquire) == 1;
    const ObjectState snapshot_state = state_.load(std::memory_order_acquire);
    const bool firing = last_pin_candidate && snapshot_state == ObjectState::Destroying;
    const DrainNotify snapshot_fn =
        firing ? drain_notify_.load(std::memory_order_acquire) : nullptr;
    void* snapshot_ctx =
        firing ? drain_context_.load(std::memory_order_acquire) : nullptr;
    const std::uint64_t prev =
        pins_.fetch_sub(1, std::memory_order_acq_rel);
    if (prev == 0) {
        // Underflow: a bug — never silently continue.
        throw RuntimeError(RuntimeErrc::InvalidState,
                           "object pin underflow (unpin without pin)");
    }
    if (prev == 1 && snapshot_fn != nullptr && snapshot_ctx != nullptr) {
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
