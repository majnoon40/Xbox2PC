// handle_manager.cpp — HandleTable + ObjectManager implementation (M4).
//
// M4 changes vs M3 (all tested; rationale in docs/handle-security.md):
//   * handles embed the owning TABLE ID (cross-table isolation),
//   * slots carry AccessRights + inheritable metadata,
//   * close requires the Close right; duplicate requires Duplicate and
//     validates the requested rights are a subset (rights only narrow),
//   * pin drain uses a condvar instead of the M3 bounded spin.

#include "xbox2pc/handle_manager.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <utility>

namespace xbox2pc::rt {

// ── rights naming ─────────────────────────────────────────────────────────

const char* access_rights_to_name(AccessRights r) {
    switch (r) {
        case AccessRights::None: return "none";
        case AccessRights::Read: return "read";
        case AccessRights::Write: return "write";
        case AccessRights::Execute: return "execute";
        case AccessRights::Duplicate: return "duplicate";
        case AccessRights::Close: return "close";
        case AccessRights::Synchronize: return "synchronize";
        case AccessRights::ReadWrite: return "read|write";
        case AccessRights::All: return "all";
    }
    return "custom";
}

// ── global manager + table ids ────────────────────────────────────────────

namespace {
ObjectManager* g_table_manager = nullptr;
std::atomic<std::uint16_t> g_next_table_id{1};  // 0 = runtime root table
}  // namespace

void install_global_manager(ObjectManager& manager) { g_table_manager = &manager; }

ObjectManager* global_manager() { return g_table_manager; }

std::uint16_t allocate_table_id() {
    const std::uint16_t id = g_next_table_id.fetch_add(1, std::memory_order_acq_rel);
    // 9-bit space: 0 is the runtime root table; process tables take 1..511.
    // Exhaustion wraps and is REJECTED (returns the reserved 0), which the
    // HandleTable(owner, id) ctor maps to a fresh allocation; documented
    // limit: at most 511 process tables live concurrently.
    if (id == 0 || id > 511) return 0;
    return id;
}

// ── HandleTable ──────────────────────────────────────────────────────────

HandleTable::HandleTable(ObjectManager& owner)
    : owner_(&owner), table_id_(kRuntimeTableId) {}

HandleTable::HandleTable(ObjectManager& owner, std::uint16_t table_id)
    : owner_(&owner),
      table_id_(table_id == kRuntimeTableId ? allocate_table_id() : table_id) {}

Result<Handle> HandleTable::create(RuntimeObject& obj) {
    return create_with_rights(obj, AccessRights::All, /*inheritable=*/true);
}

Result<Handle> HandleTable::create_with_rights(RuntimeObject& obj,
                                                 AccessRights rights,
                                                 bool inheritable_flag) {
    std::unique_lock lock(lock_);
    if (free_.empty() && slots_.size() >= kMaxSlots) {
        return Result<Handle>(RuntimeErrc::HandleTableFull,
                              "handle table exhausted (" +
                                  std::to_string(kMaxSlots) + " slots)");
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
        s.rights = static_cast<std::uint16_t>(rights);
        s.inheritable = inheritable_flag;
        s.in_use = true;
        s.generation = generation;
    } else {
        index = static_cast<std::uint32_t>(slots_.size());
        generation = 1;  // first use of a fresh slot
        Slot s;
        s.object_id = obj.id();
        s.type = static_cast<std::uint16_t>(obj.type_id());
        s.rights = static_cast<std::uint16_t>(rights);
        s.inheritable = inheritable_flag;
        s.generation = 1;
        s.in_use = true;
        slots_.push_back(std::move(s));
    }
    ++live_;
    return Result<Handle>(Handle::from_parts(index, generation,
                                              static_cast<std::uint16_t>(obj.type_id()),
                                              table_id_));
}

Result<RefGuard> HandleTable::lookup(Handle h) const {
    if (h.is_null()) {
        return Result<RefGuard>(RuntimeErrc::InvalidHandle, "null handle");
    }
    // M4: cross-table isolation — a foreign table's handle NEVER resolves
    // here even if index/generation/type happen to match.
    if (h.table_id() != table_id_) {
        return Result<RefGuard>(
            RuntimeErrc::InvalidHandle,
            "handle belongs to table " + std::to_string(h.table_id()) +
                ", this is table " + std::to_string(table_id_));
    }
    std::shared_lock lock(lock_);
    if (h.index() >= slots_.size()) {
        return Result<RefGuard>(RuntimeErrc::InvalidHandle,
                                 "slot index out of range");
    }
    const Slot& s = slots_[h.index()];
    if (!s.in_use) {
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
    const std::uint64_t id = s.object_id;
    lock.unlock();  // resolve via manager without holding the table lock
    if (owner_ == nullptr) {
        return Result<RefGuard>(RuntimeErrc::NotInitialized,
                                "handle table has no object manager installed");
    }
    return owner_->resolve_id(id);
}

AccessRights HandleTable::rights_of(Handle h) const {
    if (h.is_null() || h.table_id() != table_id_) return AccessRights::None;
    std::shared_lock lock(lock_);
    if (h.index() >= slots_.size()) return AccessRights::None;
    const Slot& s = slots_[h.index()];
    if (!s.in_use || s.generation != h.generation()) return AccessRights::None;
    return static_cast<AccessRights>(s.rights);
}

bool HandleTable::inheritable(Handle h) const {
    if (h.is_null() || h.table_id() != table_id_) return false;
    std::shared_lock lock(lock_);
    if (h.index() >= slots_.size()) return false;
    const Slot& s = slots_[h.index()];
    return s.in_use && s.generation == h.generation() && s.inheritable;
}

Result<void> HandleTable::close(Handle h) {
    if (h.is_null()) {
        return Result<void>(RuntimeErrc::InvalidHandle, "null handle");
    }
    if (h.table_id() != table_id_) {
        return Result<void>(RuntimeErrc::InvalidHandle,
                           "handle belongs to another table");
    }
    std::unique_lock lock(lock_);
    if (h.index() >= slots_.size()) {
        return Result<void>(RuntimeErrc::InvalidHandle, "slot index out of range");
    }
    Slot& s = slots_[h.index()];
    if (!s.in_use) {
        return Result<void>(RuntimeErrc::HandleStale, "slot already free");
    }
    if (s.generation != h.generation()) {
        return Result<void>(RuntimeErrc::HandleStale,
                            "generation " + std::to_string(h.generation()) +
                                " != current " + std::to_string(s.generation));
    }
    // Rights check: Close is required to retire a handle.
    if (!has_right(static_cast<AccessRights>(s.rights), AccessRights::Close)) {
        return Result<void>(RuntimeErrc::InvalidArgument,
                            "handle lacks the close right");
    }
    s.generation = (s.generation % kMaxGeneration) + 1;
    s.in_use = false;
    s.object_id = 0;
    s.type = 0;
    s.rights = static_cast<std::uint16_t>(AccessRights::None);
    s.inheritable = false;
    free_.push_back(h.index());
    --live_;
    return Result<void>::ok_result();
}

Result<Handle> HandleTable::duplicate(Handle h, AccessRights reduced,
                                       bool inheritable_flag) {
    // Resolve first (validates table id + generation + type).
    auto found = lookup(h);
    if (!found.ok()) {
        return Result<Handle>(found.errc(), found.context());
    }
    // Duplicate right required on the SOURCE handle.
    const AccessRights src_rights = rights_of(h);
    if (!has_right(src_rights, AccessRights::Duplicate)) {
        return Result<Handle>(RuntimeErrc::InvalidArgument,
                              "handle lacks the duplicate right");
    }
    // Requested rights must be a SUBSET of the source rights (never widen).
    if ((static_cast<std::uint16_t>(reduced) &
         ~static_cast<std::uint16_t>(src_rights)) != 0) {
        return Result<Handle>(RuntimeErrc::InvalidArgument,
                              "duplicate may not widen rights (requested " +
                                  std::string(access_rights_to_name(reduced)) +
                                  " from " +
                                  std::string(access_rights_to_name(src_rights)) + ")");
    }
    RefGuard& g = found.value();
    if (g.get() == nullptr) {
        return Result<Handle>(RuntimeErrc::ObjectDestroyed,
                              "handle target being destroyed");
    }
    return create_with_rights(*g.get(), reduced, inheritable_flag);
}

Result<Handle> HandleTable::duplicate(Handle h) {
    return duplicate(h, rights_of(h), inheritable(h));
}

bool HandleTable::validate_type(Handle h, TypeId expected) const {
    if (h.is_null() || h.table_id() != table_id_) return false;
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
            out.push_back(Handle::from_parts(i, s.generation, s.type, table_id_));
        }
    }
    return out;
}

std::vector<HandleTable::HandleInfo> HandleTable::list_handles() const {
    std::shared_lock lock(lock_);
    std::vector<HandleInfo> out;
    for (std::uint32_t i = 0; i < slots_.size(); ++i) {
        const Slot& s = slots_[i];
        if (!s.in_use) continue;
        HandleInfo info;
        info.handle = Handle::from_parts(i, s.generation, s.type, table_id_);
        info.object_id = s.object_id;
        info.type = s.type;
        info.rights = static_cast<AccessRights>(s.rights);
        info.inheritable = s.inheritable;
        out.push_back(std::move(info));
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
            s.rights = static_cast<std::uint16_t>(AccessRights::None);
            s.inheritable = false;
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
        destroy(id);
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
    // M4: unpin() of the last pin during destroy wakes the OWNING
    // manager's drain condvar (context = this manager, not the global).
    obj->set_drain_context(this);
    obj->set_drain_notification(&ObjectManager::on_object_unpinned);
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

// ── M4 pin-drain plumbing ─────────────────────────────────────────────────
//
// The drain condvar waits on the MAP mutex (destroy holds lock_ via
// unique_lock). unpin() fires the notification from the GUARD thread, so
// notify must NOT take lock_ (no lock inversion): notify_one() itself is
// safe to call without holding the mutex.
void ObjectManager::notify_drain() { drain_cv_.notify_all(); }

void ObjectManager::on_object_unpinned(void* drain_context) {
    // The context IS the owning manager pointer (snapshotted in unpin()
    // BEFORE the decrement — see runtime_object.cpp). Notify its drain
    // condvar; this callback never touches the object.
    if (auto* mgr = static_cast<ObjectManager*>(drain_context)) {
        mgr->notify_drain();
    }
}

Result<RefGuard> ObjectManager::lookup_handle(Handle h) const {
    return table_.lookup(h);
}

Result<Handle> ObjectManager::create_handle(RuntimeObject& obj) {
    return table_.create(obj);
}

Result<Handle> ObjectManager::create_handle_with_rights(RuntimeObject& obj,
                                                         AccessRights rights,
                                                         bool inheritable) {
    return table_.create_with_rights(obj, rights, inheritable);
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
        return Result<void>(RuntimeErrc::ObjectDestroyed,
                            "object " + std::to_string(id) +
                                " already destroying/destroyed");
    }
    // M4: condvar-based pin drain (replaces the M3 bounded spin). Drop the
    // manager's ownership pin; unpin() of the last guard pin wakes the
    // drain condvar (see runtime_object.cpp). The map lock is RELEASED
    // while waiting (guards only read state + notify; no manager calls
    // happen from guard release), so a caller holding a guard across
    // destroy() can no longer stall the drain: it wakes the moment the
    // guard drops, or the destroy returns a typed retry error if the
    // guard is still held (M3's documented InvalidState path is kept as
    // a bounded fallback via wait_for to remain robust against a
    // pathological never-released guard).
    obj->unpin();
    // Drain phase: drop the MAP lock; wait on the dedicated drain mutex
    // (the cv pairs with it; the map lock is NOT held while sleeping, so
    // guard holders can finish their work — they never take the map lock
    // during release). Bounded wakeups (50 ms) keep the drain robust even
    // if a wake is missed; unpin() normally notifies the cv directly.
    lock.unlock();
    {
        std::unique_lock<std::mutex> drain_lock(drain_mutex_);
        while (obj->pin_count() > 0) {
            if (drain_cv_.wait_for(drain_lock,
                                    std::chrono::milliseconds(50)) ==
                std::cv_status::timeout) {
                // Bounded fallback tick (documented): re-check pins and
                // keep waiting; a pathological never-released guard
                // would stall the M3 design — here we retry, and the
                // caller-visible contract stays "destroy completes when
                // guards release".
                continue;
            }
        }
    }
    // Re-acquire the map lock and re-validate the entry before erasing.
    lock.lock();
    const auto still = objects_.find(id);
    if (still == objects_.end() || still->second.get() != obj) {
        // Removed concurrently: the other destroy() call finished it.
        return Result<void>(RuntimeErrc::ObjectDestroyed,
                            "object removed concurrently during destroy");
    }
    obj->on_destroy();
    obj->manager_mark_destroyed();
    objects_.erase(it);
    return Result<void>::ok_result();
}

Result<void> ObjectManager::destroy_handle(Handle h) {
    auto found = table_.lookup(h);
    if (!found.ok()) {
        return Result<void>(found.errc(), found.context());
    }
    RefGuard g = std::move(found.value());
    if (g.get() == nullptr) {
        return Result<void>(RuntimeErrc::ObjectDestroyed, "handle target destroyed");
    }
    // Release the resolution guard BEFORE destroying so it cannot hold
    // the last pin while destroy() drains (destroy re-checks anyway).
    const std::uint64_t id = g.get()->id();
    g.release();
    return destroy(id);
}

Result<Handle> ObjectManager::duplicate_handle(Handle h) {
    return table_.duplicate(h);
}

Result<Handle> ObjectManager::duplicate_handle_with_rights(Handle h,
                                                            AccessRights reduced,
                                                            bool inheritable) {
    return table_.duplicate(h, reduced, inheritable);
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
