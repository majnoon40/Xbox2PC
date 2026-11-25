#pragma once
// xbox2pc/handle_manager.hpp — M3 handle management + object manager.
//
// Design (docs/handle-management.md, docs/runtime-object-model.md):
//   1. Handles are opaque uint64 tokens. M11 layout (4-aligned):
//      [table:9][index:15][generation:29][type:9][tag:2=0]. The low two
//      bits are a reserved alignment tag (always zero), so every nonzero
//      handle is a multiple of four — the M11 guest-visible invariant.
//      The index picks a slot; the generation invalidates handles whose
//      slot was closed and reused (stale-handle protection). No raw pointer
//      or address is ever encoded in a handle.
//   2. The ObjectManager is the single owner of every RuntimeObject
//      (unique ownership). It registers, looks up (by id or handle), and
//      destroys objects exactly once. Access goes through `lookup_*` which
//      returns a RefGuard — a pin that keeps the object alive and nulls on
//      destroy — so use-after-destruction through handles returns a typed
//      error, never dangling memory.
//   3. The HandleManager owns per-table slots; processes each own a table
//      (Xbox-style per-process handle tables — architectural model,
//      documented as inferred, not reverse-engineered).
//   4. Duplication: duplicate(handle) issues a new handle to the same
//      object in the same table with an independent slot (closing one does
//      not invalidate the other). Cross-table duplication is via the
//      object manager (target process owns the object lifetime).
//   5. Concurrency: one RW lock for the table; slot mutation takes the
//      write lock. Lookups take a read lock then pin the object before
//      releasing it, so lookup-then-destroy races are closed.
//
// Error discipline: every failure returns a typed Result; nothing is
// silently dropped (see runtime_error.hpp).

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "xbox2pc/runtime_object.hpp"

namespace xbox2pc::rt {

class ObjectManager;

// Process-table id allocation (0 = runtime root table; 1..511 process
// tables; exhaustion returns the reserved 0 — documented 9-bit limit).
std::uint16_t allocate_table_id();

// ── handle representation ────────────────────────────────────────────────
//
// 64-bit layout (little-endian packing, value computed arithmetically):
//   bits 0..1   : reserved alignment tag, always zero (M11: every nonzero
//                 handle is a multiple of four, like Windows kernel
//                 HANDLE tag bits — misaligned values reject as invalid)
//   bits 2..10  : type id (9 bits, mirrors TypeId for cheap validation)
//   bits 11..39 : generation (29 bits, nonzero while slot in use)
//   bits 40..54 : slot index (15 bits, max 32K entries per table)
//   bits 55..63 : table id (9 bits, owning table — M4 hardening)
//
// M4 change (documented architectural fix): the owning TABLE ID is now
// encoded in the handle. In M3, two handles from different tables with
// the same slot index/generation/type produced the SAME raw value, so a
// handle passed to the wrong table could alias a foreign object. With the
// table id embedded, cross-table lookups fail with InvalidHandle (the
// table checks its own id first). Capacity per table drops 16M -> 32K
// entries, which exceeds every realistic M4 use (per-process tables hold
// at most thousands of objects; the limit is typed as HandleTableFull).
class Handle {
public:
    Handle() = default;
    constexpr std::uint64_t raw() const { return raw_; }
    static constexpr Handle from_raw(std::uint64_t raw) { Handle h; h.raw_ = raw; return h; }
    constexpr bool is_null() const { return raw_ == 0; }
    constexpr std::uint16_t type() const {
        return static_cast<std::uint16_t>((raw_ >> 2) & 0x1FF);
    }
    constexpr std::uint32_t generation() const {
        return static_cast<std::uint32_t>((raw_ >> 11) & 0x1FFFFFFF);
    }
    // M11 alignment tag: the low two bits, reserved zero. A nonzero
    // handle with a nonzero tag is a forged/misaligned value.
    constexpr std::uint16_t tag() const {
        return static_cast<std::uint16_t>(raw_ & 0x3);
    }
    constexpr std::uint32_t index() const {
        return static_cast<std::uint32_t>((raw_ >> 40) & 0x7FFF);
    }
    constexpr std::uint16_t table_id() const {
        return static_cast<std::uint16_t>(raw_ >> 55);
    }

    static constexpr Handle from_parts(std::uint32_t index, std::uint32_t gen,
                                       std::uint16_t type,
                                       std::uint16_t table_id) {
        Handle h;
        h.raw_ = (static_cast<std::uint64_t>(table_id & 0x1FF) << 55) |
                 (static_cast<std::uint64_t>(index & 0x7FFF) << 40) |
                 (static_cast<std::uint64_t>(gen & 0x1FFFFFFF) << 11) |
                 (static_cast<std::uint64_t>(type & 0x1FF) << 2);
        return h;
    }

    // Legacy 3-part form (M3 tests): table id 0 = the runtime's own table
    // keeps old encodings working where the table id is irrelevant.
    static constexpr Handle from_parts(std::uint32_t index, std::uint32_t gen,
                                       std::uint16_t type) {
        return from_parts(index, gen, type, 0);
    }

    constexpr bool operator==(const Handle& o) const { return raw_ == o.raw_; }
    constexpr bool operator!=(const Handle& o) const { return raw_ != o.raw_; }

private:
    explicit constexpr Handle(std::uint64_t raw) : raw_(raw) {}
    std::uint64_t raw_ = 0;
};

// ── access rights (M4) ───────────────────────────────────────────────────
//
// A capability mask on each handle: what the holder may DO with the
// object. Rights only ever NARROW on duplication (the lattice below);
// defaults grant everything but Synchronize is meaningful only for sync
// objects (checked at use, not stored per-object-type).
enum class AccessRights : std::uint16_t {
    None = 0,
    // Single rights (bitfield).
    Read = 1,
    Write = 2,
    Execute = 4,
    Duplicate = 8,
    Close = 16,
    Synchronize = 32,
    // Common bundles.
    ReadWrite = Read | Write,
    All = Read | Write | Execute | Duplicate | Close | Synchronize,
};

constexpr AccessRights operator|(AccessRights a, AccessRights b) {
    return static_cast<AccessRights>(static_cast<std::uint16_t>(a) |
                                      static_cast<std::uint16_t>(b));
}
constexpr AccessRights operator&(AccessRights a, AccessRights b) {
    return static_cast<AccessRights>(static_cast<std::uint16_t>(a) &
                                      static_cast<std::uint16_t>(b));
}
constexpr bool has_right(AccessRights have, AccessRights need) {
    return (static_cast<std::uint16_t>(have) &
            static_cast<std::uint16_t>(need)) ==
           static_cast<std::uint16_t>(need);
}
const char* access_rights_to_name(AccessRights r);  // "read|write|close"

// ── RefGuard ─────────────────────────────────────────────────────────────
//
// Pins a RuntimeObject while alive; nulls its pointer when the object begins
// destruction, making use-after-destruction a benign null check rather
// than UB. Non-copyable (the pin is uniquely owned); movable.
class RefGuard {
public:
    RefGuard() = default;
    explicit RefGuard(RuntimeObject* obj) : obj_(obj) {
        if (obj_ != nullptr) obj_->pin();
    }
    ~RefGuard() {
        if (obj_ != nullptr) {
            // Read the state BEFORE unpinning: the unpin below can drop the
            // LAST pin, after which a concurrent destroy() may free the
            // object — touching obj_ after unpin would be use-after-free.
            const ObjectState s = obj_->state();
            if (s != ObjectState::Destroyed) {
                obj_->unpin();
            }
        }
    }

    RefGuard(const RefGuard&) = delete;
    RefGuard& operator=(const RefGuard&) = delete;

    RefGuard(RefGuard&& o) noexcept : obj_(o.obj_) { o.obj_ = nullptr; }
    RefGuard& operator=(RefGuard&& o) noexcept {
        if (this != &o) {
            release();
            obj_ = o.obj_;
            o.obj_ = nullptr;
        }
        return *this;
    }

    RuntimeObject* get() const {
        if (obj_ == nullptr) return nullptr;
        // While this guard holds a pin, ObjectManager::destroy CANNOT free
        // the object (it drains pins before erasure), so the memory is
        // valid even in the Destroying state. Only the terminal Destroyed
        // state — reached after every guard released — nulls the pointer.
        return obj_->state() == ObjectState::Destroyed ? nullptr : obj_;
    }
    RuntimeObject* operator->() const { return get(); }
    explicit operator bool() const { return get() != nullptr; }

    // Typed view: type check + alive check.
    template <typename T>
    T* as() {
        RuntimeObject* o = get();
        return o != nullptr ? o->as<T>() : nullptr;
    }

    void release() {
        if (obj_ != nullptr) {
            // Same ordering rule as the destructor (see above).
            const ObjectState s = obj_->state();
            if (s != ObjectState::Destroyed) {
                obj_->unpin();
            }
        }
        obj_ = nullptr;
    }

private:
    RuntimeObject* obj_ = nullptr;
};

// ── handle table ─────────────────────────────────────────────────────────
//
// One table per process (plus the runtime's own table for process objects).
// Free lists make slot allocation O(1); generation bumps on close.
//
// M4 hardening: tables own a unique TABLE ID (0 = runtime root table);
// handles embed it, so a handle from table B cannot resolve in table A
// (cross-table isolation, typed InvalidHandle). Slots carry ACCESS RIGHTS
// + INHERITANCE metadata; duplication validates the Duplicate right and
// may reduce rights; closure requires the Close right.

class ObjectManager;  // fwd

class IGuestHandleCloser {
public:
    virtual ~IGuestHandleCloser() = default;
    virtual Result<void> close_guest_handle(std::uint64_t process_id,
                                            std::uint64_t raw_handle,
                                            RefGuard&& object_pin) = 0;
};

class HandleTable {
public:
    static constexpr std::uint32_t kMaxSlots = 1u << 15;   // 32K (M4 layout)
    // 29-bit generation field (M11 alignment layout): wrap skips zero so
    // an in-use slot never presents generation 0.
    static constexpr std::uint32_t kMaxGeneration = 0x1FFFFFFF;
    static constexpr std::uint16_t kRuntimeTableId = 0;

    // Runtime root table (id 0). Per-process tables get ids 1..511.
    explicit HandleTable(ObjectManager& owner);
    // Table with an explicit id (id 0 is reserved for the runtime table).
    HandleTable(ObjectManager& owner, std::uint16_t table_id);

    // Creates a handle with FULL rights (the creation grant).
    Result<Handle> create(RuntimeObject& obj);

    // Creates a handle with explicit rights (the creation grant can be
    // narrower than All; e.g. read-only views handed to other components).
    Result<Handle> create_with_rights(RuntimeObject& obj, AccessRights rights,
                                       bool inheritable);

    // Resolves a handle to a pinned object; validates table id, generation,
    // and type. Rights are NOT checked here (lookup is id resolution);
    // use rights_of() + has_right() at the operation site.
    Result<RefGuard> lookup(Handle h) const;

    // Rights of a live handle (None on any validation failure).
    AccessRights rights_of(Handle h) const;
    // Inheritance flag of a live handle.
    bool inheritable(Handle h) const;

    // Closes one handle: requires the Close right; frees the slot
    // (generation bump). Closing WITHOUT the right returns LockNotOwned-
    // style typed error (InvalidArgument).
    Result<void> close(Handle h);

    // Issues a NEW handle to the same object (independent slot). Requires
    // the Duplicate right on the source. The new handle's rights are
    // `reduced` (must be a SUBSET of the source rights — validated), and
    // its inheritable flag is caller-chosen but never widens the rights.
    Result<Handle> duplicate(Handle h, AccessRights reduced,
                              bool inheritable);
    // Full-rights duplicate (convenience; preserves source rights).
    Result<Handle> duplicate(Handle h);

    // Type validation helper used by typed close paths.
    bool validate_type(Handle h, TypeId expected) const;

    std::uint32_t live_count() const;
    std::uint32_t slot_capacity() const { return kMaxSlots; }
    std::uint16_t table_id() const { return table_id_; }

    // All live handles (CLI/diagnostics).
    std::vector<Handle> all_handles() const;

    // Close every live slot (process teardown) regardless of rights.
    Result<void> close_all();

    // Diagnostic listing entry (CLI handle-info).
    struct HandleInfo {
        Handle handle;
        std::uint64_t object_id;
        std::uint16_t type;
        std::string type_name;
        AccessRights rights;
        bool inheritable;
    };
    std::vector<HandleInfo> list_handles() const;

private:
    struct Slot {
        std::uint64_t object_id = 0;          // object manager id
        std::uint16_t type = 0;
        std::uint32_t generation = 0;        // 0 = free slot
        bool in_use = false;
        std::uint16_t rights = static_cast<std::uint16_t>(AccessRights::All);
        bool inheritable = true;
    };

    ObjectManager* owner_ = nullptr;   // installed by the runtime facade
    const std::uint16_t table_id_;
    mutable std::shared_mutex lock_;
    std::vector<Slot> slots_;                 // dense, grows
    std::vector<std::uint32_t> free_;        // free slot stack
    std::uint32_t live_ = 0;
};

// Installs the runtime's global object manager used by per-process handle
// tables for id resolution. Call once during runtime initialization.
void install_global_manager(ObjectManager& manager);

// Currently installed global manager (null before runtime initialization).
ObjectManager* global_manager();

// ── object manager ───────────────────────────────────────────────────────
//
// Single owner + registry of all runtime objects. Destruction drains pins
// before teardown (objects with outstanding RefGuards are destroyed only
// after their guards release — see destroy_locked).
class ObjectManager {
public:
    static constexpr std::uint64_t kInvalidObjectId = 0;

    ObjectManager();
    ~ObjectManager();

    ObjectManager(const ObjectManager&) = delete;
    ObjectManager& operator=(const ObjectManager&) = delete;

    // Registers an externally constructed object: assigns id, marks
    // registered, pins once for the manager's own ownership.
    Result<std::uint64_t> register_object(std::unique_ptr<RuntimeObject> obj);

    // Lookup by object id; pins via RefGuard.
    Result<RefGuard> lookup_id(std::uint64_t id) const;

    // Lookup by handle in the runtime table.
    Result<RefGuard> lookup_handle(Handle h) const;

    // Creates a handle for `obj` in the runtime handle table.
    Result<Handle> create_handle(RuntimeObject& obj);

    // Closes a runtime-table handle.
    Result<void> close_handle(Handle h);

    // Destroys an object by id exactly once; waits for pins to drain.
    // Destroying an already-destroyed id returns ObjectDestroyed (typed).
    Result<void> destroy(std::uint64_t id);

    // Convenience: destroy via handle.
    Result<void> destroy_handle(Handle h);

    // Duplicate a handle in the runtime table.
    Result<Handle> duplicate_handle(Handle h);

    // Type-checked lookup: returns nullptr-guard if type mismatches.
    template <typename T>
    Result<RefGuard> lookup_typed(Handle h, TypeId expect) {
        auto r = lookup_handle(h);
        if (!r.ok()) return Result<RefGuard>(r.errc(), r.context());
        if (r.value().get() == nullptr) {
            return Result<RefGuard>(RuntimeErrc::ObjectDestroyed, "handle target destroyed");
        }
        if (r.value().get()->type_id() != expect) {
            return Result<RefGuard>(RuntimeErrc::ObjectTypeMismatch,
                                    "expected " + type_name(expect) + ", got " +
                                        type_name(r.value().get()->type_id()));
        }
        return r;
    }

    // Stats / listing (CLI).
    struct ObjectInfo {
        std::uint64_t id;
        TypeId type;
        std::string type_name;
        std::string name;
        ObjectState state;
        std::uint64_t pins;
    };
    std::vector<ObjectInfo> list_objects() const;
    std::size_t object_count() const;
    std::string type_name(TypeId t) const;

    // Handle table owned by this manager (processes get their own).
    HandleTable& table() { return table_; }
    const HandleTable& table() const { return table_; }

    // For HandleTable back-reference resolution.
    Result<RefGuard> resolve_id(std::uint64_t id) const;

    // ── M4: rights-aware handle ops on the runtime table ──
    Result<Handle> create_handle_with_rights(RuntimeObject& obj,
                                               AccessRights rights,
                                               bool inheritable);
    Result<Handle> duplicate_handle_with_rights(Handle h, AccessRights reduced,
                                                 bool inheritable);

    // Pin-drain notification (called by RuntimeObject::unpin when the
    // object is mid-destroy; see runtime_object.cpp).
    void notify_drain();

    // Static entry installed on every registered object: receives the
    // snapshotted drain context (this manager) and notifies its drain
    // condvar — never touches the (possibly destroyed) object.
    static void on_object_unpinned(void* drain_context);

private:
    mutable std::shared_mutex lock_;
    std::unordered_map<std::uint64_t, std::unique_ptr<RuntimeObject>> objects_;
    std::atomic<std::uint64_t> next_id_{1};
    HandleTable table_;
    // M4: condvar-based pin drain (replaces the M3 bounded spin). Pairs
    // with drain_mutex_ (its OWN mutex — the map lock is released while
    // waiting, so guard releases never contend on the map lock).
    std::condition_variable drain_cv_;
    std::mutex drain_mutex_;
    friend class RuntimeObject;  // unpin() wake path touches nothing private
};

}  // namespace xbox2pc::rt
