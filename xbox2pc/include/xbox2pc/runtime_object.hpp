#pragma once
// xbox2pc/runtime_object.hpp — M3 runtime object model.
//
// Design (docs/runtime-object-model.md):
//   1. Every runtime object derives from RuntimeObject and is owned by an
//      ObjectManager (unique ownership, manager = lifetime root). Reference
//      counting exists as an *access* pin (RefGuard) so callers can keep an
//      object alive across calls without transferring ownership — the
//      documented alternative to raw shared_ptr everywhere.
//   2. Type safety: TypeId is a small typed enum + user types register in a
//      global ObjectTypeRegistry; casts go through object::as<T>() which
//      validates the type id and returns nullptr on mismatch. No void*
//      access from public interfaces.
//   3. Lifecycle: Created -> Registered -> [Ready] -> Destroying ->
//      Destroyed, with atomic state so concurrent readers observe either
//      "alive" or "destroyed", never a half state (use-after-destruction
//      protection: as<T>() on a destroyed object fails).
//   4. Destruction happens exactly once (manager-issued destroy call is
//      idempotent; double destruction is detected and reported).
//   5. Identifiers: stable uint64 object ids assigned by the manager; an
//      object's address is never used as its identity and never escapes
//      through the public interface.
//
// This is an architectural model of an Xbox-style runtime; it does NOT claim
// to reproduce undocumented Xbox kernel object internals (docs cite what is
// confirmed vs inferred).

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "xbox2pc/platform.hpp"
#include "xbox2pc/runtime_error.hpp"

namespace xbox2pc::rt {

// ── object types ───────────────────────────────────────────────────────────
//
// TypeId values 0..999 are built-in runtime types; extension subsystems
// (graphics, audio, ...) register custom types with base ids >= 1000 via the
// ObjectTypeRegistry so collisions cannot occur silently.
enum class TypeId : std::uint16_t {
    Invalid = 0,
    Process = 1,
    Thread = 2,
    Event = 3,
    Mutex = 4,
    Semaphore = 5,
    File = 6,
    MemoryRegion = 7,
    RuntimeService = 8,
    // built-in range ends at 999
};

inline constexpr std::uint16_t kUserTypeBase = 1000;

// ── lifecycle states ────────────────────────────────────────────────────────
enum class ObjectState {
    Created,      // constructed, not yet registered with a manager
    Registered,   // tracked by the manager, usable
    Destroying,   // destroy() began; new access is refused
    Destroyed,   // teardown complete; the shell remains until released
};

const char* object_state_to_name(ObjectState s);
const char* type_id_to_name(TypeId t);

// ── object type registry (extensible) ──────────────────────────────────────
//
// Maps TypeId -> name for diagnostics/CLI; user types register once.
class ObjectTypeRegistry {
public:
    static ObjectTypeRegistry& instance();

    // Registers a user type id; fails (returns false) on collision with an
    // existing id. Ids below kUserTypeBase cannot be registered (built-ins).
    bool register_user_type(TypeId id, const std::string& name);

    // Name for a type id; "unregistered-type(<id>)" when unknown.
    std::string name(TypeId id) const;

    bool is_registered(TypeId id) const;
    std::size_t size() const;

private:
    ObjectTypeRegistry();  // seeds built-in names

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ── base object ────────────────────────────────────────────────────────────
//
// Concurrency contract:
//   - `state()` and `type_id()`/`id()` are safe to call concurrently.
//   - transition to Destroying/Destroyed is manager-serialized.
//   - all other mutation happens through subclasses with their own locks
//     (synchronization primitives lock internally; process/thread state
//     transitions take the manager lock — see their headers).
class RuntimeObject {
public:
    RuntimeObject(TypeId type);
    virtual ~RuntimeObject() = default;

    TypeId type_id() const { return type_; }
    std::uint64_t id() const { return id_; }
    ObjectState state() const { return state_.load(std::memory_order_acquire); }
    const std::string& name() const { return name_; }
    void set_name(std::string n) { name_ = std::move(n); }

    // Metadata: arbitrary key/value pairs (e.g. source module, creation
    // origin). Not used for identity. Thread-safe (internal mutex).
    void set_meta(const std::string& key, std::string value);
    std::string meta(const std::string& key) const;      // "" when absent
    std::vector<std::pair<std::string, std::string>> all_meta() const;

    // Typed access helper: validates aliveness + registered type id +
    // C++ dynamic type. Nullptr unless the object IS a T.
    template <typename T>
    T* as();
    template <typename T>
    const T* as() const;

    // Lifecycle control (called by ObjectManager only).
    void manager_assign_id(std::uint64_t id);
    void manager_mark_registered();
    // Returns false when destruction already started elsewhere (double
    // destroy detection). Marks Destroying on success.
    bool manager_begin_destroy();
    void manager_mark_destroyed();

    // Refcount pin: incremented by RefGuard/ObjectManager while any caller
    // holds an access reference; destroy() waits for the pin to drop.
    // M4: unpin() notifies the drain condvar when the object is mid-destroy
    // so ObjectManager::destroy() wakes promptly (condvar pin drain; the
    // drain coordinator is installed by the manager at registration).
    void pin();
    void unpin();
    std::uint64_t pin_count() const { return pins_.load(std::memory_order_acquire); }

    // Validation: usable when registered (or created) and not destroying.
    bool is_alive() const;

protected:
    // Hook for subclass teardown before state Destroyed (manager calls
    // between begin_destroy and mark_destroyed while pins are drained).
    virtual void on_destroy() {}

    friend class ObjectManager;  // lifecycle control + on_destroy dispatch

private:
    const TypeId type_;
    std::uint64_t id_ = 0;
    std::atomic<ObjectState> state_{ObjectState::Created};
    std::atomic<std::uint64_t> pins_{0};
    std::string name_;
    mutable std::mutex meta_lock_;   // PAL mutex for metadata
    std::vector<std::pair<std::string, std::string>> meta_;

public:
    // ── M4 drain notification plumbing ──
    // Called by ObjectManager at registration: when unpin() drops the last
    // pin of a DESTROYING object, the notify fires. The callback receives
    // the SNAPSHOTTED context (the owning manager pointer), captured
    // BEFORE the pin decrement — after the decrement the object may be
    // destroyed concurrently, so the callback must not touch the object.
    using DrainNotify = void (*)(void* drain_context);
    void set_drain_notification(DrainNotify fn);
    DrainNotify drain_notification() const { return drain_notify_.load(std::memory_order_acquire); }
    void set_drain_context(void* ctx) { drain_context_.store(ctx, std::memory_order_release); }
    void* drain_context() const { return drain_context_.load(std::memory_order_acquire); }

private:
    std::atomic<DrainNotify> drain_notify_{nullptr};
    std::atomic<void*> drain_context_{nullptr};
};

template <typename T>
T* RuntimeObject::as() {
    static_assert(std::is_base_of_v<RuntimeObject, T>,
                  "as<T>() requires a RuntimeObject subclass");
    if (state() == ObjectState::Destroying || state() == ObjectState::Destroyed) {
        return nullptr;
    }
    // Double validation: the registered TypeId must match AND the C++
    // dynamic type must be T. The id alone is claimable by any subclass
    // (multiple wrapper classes share TypeId::Event, File...), so the
    // dynamic_cast guarantees a wrong-typed view is never handed out.
    if (type_ != T::static_type_id()) {
        return nullptr;
    }
    return dynamic_cast<T*>(this);  // nullptr when dynamic type differs
}

template <typename T>
const T* RuntimeObject::as() const {
    static_assert(std::is_base_of_v<RuntimeObject, T>,
                  "as<T>() requires a RuntimeObject subclass");
    if (state() == ObjectState::Destroying || state() == ObjectState::Destroyed) {
        return nullptr;
    }
    if (type_ != T::static_type_id()) {
        return nullptr;
    }
    return dynamic_cast<const T*>(this);
}

// Convenience macro giving subclasses a static TypeId for as<T>() checks.
#define XBOX2PC_RUNTIME_OBJECT_TYPE(cls, id)                     \
    static ::xbox2pc::rt::TypeId static_type_id() {             \
        return ::xbox2pc::rt::TypeId::id;                       \
    }

}  // namespace xbox2pc::rt
