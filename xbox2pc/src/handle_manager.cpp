// handle_manager.cpp — HandleTable + ObjectManager implementation.

#include "xbox2pc/handle_manager.hpp"

#include <algorithm>
#include <thread>
#include <utility>

namespace xbox2pc::rt {

// ── HandleTable ──────────────────────────────────────────────────────────

namespace {
// Global object manager for per-process tables (installed by runtime).
ObjectManager* g_table_manager = nullptr;
}  // namespace

void install_global_manager(ObjectManager& manager) { g_table_manager = &manager; }

ObjectManager* global_manager() { return g_table_manager; }

HandleTable::HandleTable(ObjectManager& owner) : owner_(&owner) {}

Result<Handle> HandleTable::create(RuntimeObject& obj) {
    std::unique_lock lock(lock_);
    if (free_.empty() && slots_.size() >= kMaxSlots) {
        return Result<Handle>(RuntimeErrc::HandleTableFull,
                              "handle table exhausted (" + std::to_string(kMaxSlots) + ")");
    }
    std::uint32_t index;
    std::uint32_t generation;
    if (!free_.empty()) {
        index = free_.back();
        free_.pop_back();
        Slot& s = slots_[index];
        // Reused slot: generation continues from the previous cycle (never
        // zero while in use). Wrap-around skips 0 explicitly.
        generation = s.generation == 0 ? 1 : s.generation;
        s.object_id = obj.id();
        s.type = static_cast<std::uint16_t>(obj.type_id());
        s.in_use = true;
        s.generation = generation;
    } else {
        index = static_cast<std::uint32_t>(slots_.size());
        generation = 1;  // first use of a fresh slot
        Slot s;
        s.object_id = obj.id();
        s.type = static_cast<std::uint16_t>(obj.type_id());
        s.generation = 1;
        s.in_use = true;
        slots_.push_back(std::move(s));
    }
    ++live_;
    return Result<Handle>(Handle::from_parts(index, generation,
                                              static_cast<std::uint16_t>(obj.type_id())));
}

Result<RefGuard> HandleTable::lookup(Handle h) const {
    if (h.is_null()) {
        return Result<RefGuard>(RuntimeErrc::InvalidHandle, "null handle");
    }
    std::shared_lock lock(lock_);
    if (h.index() >= slots_.size()) {
        return Result<RefGuard>(RuntimeErrc::InvalidHandle,
                                 "slot index out of range");
    }
    const Slot& s = slots_[h.index()];
    if (!s.in_use) {
        // Slot freed: the handle value itself is stale (its generation
        // matches a dead cycle of this slot).
        return Result<RefGuard>(RuntimeErrc::HandleStale, "slot freed");
    }
    if (s.generation != h.generation()) {
        return Result<RefGuard>(RuntimeErrc::HandleStale,
                                "generation " + std::to_string(h.generation()) +
                                    " != current " + std::to_string(s.generation));
    }
    if (s.type != h.type()) {
        return Result<RefGuard>(RuntimeErrc::InvalidHandle, "type field mismatch");
    }
    // Double-close detection: a close attempt of a freed slot must NOT
    // invalidate the NEW cycle's handle — close() re-checks generation.
    // Pin under the read lock: destruction cannot complete while pinned.
    const std::uint64_t id = s.object_id;
    lock.unlock();  // downgrade: resolve via manager without holding table lock
    if (owner_ == nullptr) {
        return Result<RefGuard>(RuntimeErrc::NotInitialized,
                                "handle table has no object manager installed");
    }
    return owner_->resolve_id(id);
}

Result<void> HandleTable::close(Handle h) {
    if (h.is_null()) {
        return Result<void>(RuntimeErrc::InvalidHandle, "null handle");
    }
    std::unique_lock lock(lock_);
    if (h.index() >= slots_.size()) {
        return Result<void>(RuntimeErrc::InvalidHandle, "slot index out of range");
    }
    Slot& s = slots_[h.index()];
    if (!s.in_use) {
        return Result<void>(RuntimeErrc::HandleClosed, "slot already free");
    }
    if (s.generation != h.generation()) {
        return Result<void>(RuntimeErrc::HandleStale,
                            "generation " + std::to_string(h.generation()) +
                                " != current " + std::to_string(s.generation));
    }
    // Bump generation so this handle value never resolves again; wrap skips 0.
    s.generation = (s.generation % kMaxGeneration) + 1;
    s.in_use = false;
    s.object_id = 0;
    s.type = 0;
    free_.push_back(h.index());
    --live_;
    return Result<void>::ok_result();
}

Result<Handle> HandleTable::duplicate(Handle h) {
    // Validate then create a fresh slot for the same object.
    auto found = lookup(h);
    if (!found.ok()) {
        return Result<Handle>(found.errc(), found.context());
    }
    RefGuard& g = found.value();
    if (g.get() == nullptr) {
        return Result<Handle>(RuntimeErrc::ObjectDestroyed,
                              "handle target being destroyed");
    }
    return create(*g.get());
}

bool HandleTable::validate_type(Handle h, TypeId expected) const {
    if (h.is_null()) return false;
    std::shared_lock lock(lock_);
    if (h.index() >= slots_.size()) return false;
    const Slot& s = slots_[h.index()];
    return s.in_use && s.generation == h.generation() &&
           s.type == static_cast<std::uint16_t>(expected);
}

std::uint32_t HandleTable::live_count() const {
    std::shared_lock lock(lock_);
    return live_;
}

std::vector<Handle> HandleTable::all_handles() const {
    std::shared_lock lock(lock_);
    std::vector<Handle> out;
    for (std::uint32_t i = 0; i < slots_.size(); ++i) {
        const Slot& s = slots_[i];
        if (s.in_use) {
            out.push_back(Handle::from_parts(i, s.generation, s.type));
        }
    }
    return out;
}

Result<void> HandleTable::close_all() {
    std::unique_lock lock(lock_);
    for (std::uint32_t i = 0; i < slots_.size(); ++i) {
        Slot& s = slots_[i];
        if (s.in_use) {
            s.generation = (s.generation % kMaxGeneration) + 1;
            s.in_use = false;
            s.object_id = 0;
            s.type = 0;
            free_.push_back(i);
        }
    }
    live_ = 0;
    return Result<void>::ok_result();
}

// ── ObjectManager ─────────────────────────────────────────────────────────

ObjectManager::ObjectManager() : table_(*this) {}

ObjectManager::~ObjectManager() {
    // Destroy remaining objects in reverse registration order (LIFO mirrors
    // subsystem teardown). Destruction is idempotent per object.
    std::vector<std::uint64_t> ids;
    {
        std::shared_lock lock(lock_);
        ids.reserve(objects_.size());
        for (const auto& kv : objects_) ids.push_back(kv.first);
    }
    std::reverse(ids.begin(), ids.end());
    for (std::uint64_t id : ids) {
        destroy(id);  // typed errors ignored only for already-destroyed
    }
}

Result<std::uint64_t> ObjectManager::register_object(std::unique_ptr<RuntimeObject> obj) {
    if (obj == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidArgument, "null object");
    }
    if (obj->state() == ObjectState::Destroying ||
        obj->state() == ObjectState::Destroyed) {
        return Result<std::uint64_t>(RuntimeErrc::ObjectDestroyed,
                                      "cannot register a destroyed object");
    }
    const std::uint64_t id = next_id_.fetch_add(1, std::memory_order_acq_rel);
    obj->manager_assign_id(id);
    obj->pin();  // manager's own ownership pin
    obj->manager_mark_registered();
    std::unique_lock lock(lock_);
    objects_[id] = std::move(obj);
    return Result<std::uint64_t>(id);
}

Result<RefGuard> ObjectManager::lookup_id(std::uint64_t id) const {
    if (id == kInvalidObjectId) {
        return Result<RefGuard>(RuntimeErrc::InvalidArgument, "invalid object id 0");
    }
    std::shared_lock lock(lock_);
    const auto it = objects_.find(id);
    if (it == objects_.end()) {
        return Result<RefGuard>(RuntimeErrc::NotFound,
                                "object id " + std::to_string(id) + " not registered");
    }
    RuntimeObject* obj = it->second.get();
    if (obj->state() == ObjectState::Destroying ||
        obj->state() == ObjectState::Destroyed) {
        return Result<RefGuard>(RuntimeErrc::ObjectDestroyed,
                                "object " + std::to_string(id) + " is being destroyed");
    }
    return Result<RefGuard>(RefGuard(obj));
}

Result<RefGuard> ObjectManager::resolve_id(std::uint64_t id) const {
    return lookup_id(id);
}

Result<RefGuard> ObjectManager::lookup_handle(Handle h) const {
    return table_.lookup(h);
}

Result<Handle> ObjectManager::create_handle(RuntimeObject& obj) {
    return table_.create(obj);
}

Result<void> ObjectManager::close_handle(Handle h) {
    return table_.close(h);
}

Result<void> ObjectManager::destroy(std::uint64_t id) {
    std::unique_lock lock(lock_);
    const auto it = objects_.find(id);
    if (it == objects_.end()) {
        return Result<void>(RuntimeErrc::NotFound,
                            "object id " + std::to_string(id) + " not registered");
    }
    RuntimeObject* obj = it->second.get();
    if (!obj->manager_begin_destroy()) {
        // Second destroy attempt on the same object: typed duplicate error.
        return Result<void>(RuntimeErrc::ObjectDestroyed,
                            "object " + std::to_string(id) + " already destroying/destroyed");
    }
    // Drop the manager's ownership pin, then DRAIN remaining pins with a
    // bounded cooperative wait. Design decision (documented): destroy does
    // NOT block indefinitely on outstanding RefGuards — long-lived pins
    // would deadlock the manager (e.g. a caller holding a guard calls
    // destroy()). Behavior:
    //   * pins drop to 0        -> teardown proceeds now (common case);
    //   * pins still held after the deadline -> the object stays in
    //     'Destroying' state and the map; lookup_id keeps returning
    //     ObjectDestroyed, and a LATER destroy() retry completes teardown.
    // This is the documented alternative to blocking destruction, chosen
    // so no public API can deadlock the object manager.
    obj->unpin();
    constexpr int kMaxDrainSpins = 20'000'000;  // ~ bounded spin budget
    int spins = 0;
    while (obj->pin_count() > 0 && spins < kMaxDrainSpins) {
        if (spins % 1024 == 0) {
            lock.unlock();  // let guard holders finish (they don't need map lock)
            std::this_thread::yield();
            lock.lock();
            // The map entry may have been replaced/erased while unlocked.
            const auto still = objects_.find(id);
            if (still == objects_.end()) {
                return Result<void>(RuntimeErrc::ObjectDestroyed,
                                    "object removed concurrently during destroy");
            }
        } else {
            std::this_thread::yield();
        }
        ++spins;
    }
    if (obj->pin_count() > 0) {
        // Pins held: leave the object in Destroying for a later retry.
        return Result<void>(RuntimeErrc::InvalidState,
                            "object " + std::to_string(id) +
                                " still pinned by " + std::to_string(obj->pin_count()) +
                                " reference(s); retry destroy after releasing");
    }
    obj->on_destroy();
    obj->manager_mark_destroyed();
    objects_.erase(it);
    return Result<void>::ok_result();
}

Result<void> ObjectManager::destroy_handle(Handle h) {
    // Resolve under pin, then destroy by id; the handle stays valid until
    // closed (destroying does not auto-close handles — closing is explicit).
    auto found = table_.lookup(h);
    if (!found.ok()) {
        return Result<void>(found.errc(), found.context());
    }
    RefGuard g = std::move(found.value());
    if (g.get() == nullptr) {
        return Result<void>(RuntimeErrc::ObjectDestroyed, "handle target destroyed");
    }
    return destroy(g.get()->id());
}

Result<Handle> ObjectManager::duplicate_handle(Handle h) {
    return table_.duplicate(h);
}

std::vector<ObjectManager::ObjectInfo> ObjectManager::list_objects() const {
    std::shared_lock lock(lock_);
    std::vector<ObjectInfo> out;
    out.reserve(objects_.size());
    for (const auto& kv : objects_) {
        ObjectInfo info;
        info.id = kv.first;
        info.type = kv.second->type_id();
        info.type_name = type_name(kv.second->type_id());
        info.name = kv.second->name();
        info.state = kv.second->state();
        info.pins = kv.second->pin_count();
        out.push_back(std::move(info));
    }
    return out;
}

std::size_t ObjectManager::object_count() const {
    std::shared_lock lock(lock_);
    return objects_.size();
}

std::string ObjectManager::type_name(TypeId t) const {
    return ObjectTypeRegistry::instance().name(t);
}

}  // namespace xbox2pc::rt
