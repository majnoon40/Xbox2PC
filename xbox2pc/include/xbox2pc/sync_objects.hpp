#pragma once
// xbox2pc/sync_objects.hpp — M3 synchronization model.
//
// Platform-independent runtime objects wrapping PAL primitives:
//   RtEvent, RtMutex, RtSemaphore, RtCondvar.
//
// Semantics (docs/process-thread-model.md §sync):
//   - Events: auto-reset (one waiter consumes) vs manual-reset (all waiters,
//     stays set until reset). set/reset/wait with timeout; wait returns
//     Timeout on deadline. Signaling is memory-ordering-safe.
//   - Mutexes: recursive NOT implied — plain ownership; unlock by non-owner
//     returns LockNotOwned. Destruction while a thread holds ownership is a
//     validated error path (destroy defers until unlocked: on_destroy waits
//     for ownership release — bounded by the PAL mutex).
//   - Semaphores: counting; release past max is an InvalidState error, not
//     silent saturation.
//   - Condvars: wait(pred)/wait_for_ns(pred) with the runtime mutex; lost
//     wakeups are prevented by the PAL cv invariants.
//
// These are host implementations of generic synchronization semantics; NO
// claim of Xbox kernel equivalence is made (the Xbox OS's own primitives
// are undocumented — see docs for confirmed-vs-inferred framing).

#include <chrono>
#include <memory>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/platform.hpp"

namespace xbox2pc::rt {

// ── event ──────────────────────────────────────────────────────────────────

class RtEvent : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtEvent, Event)

    RtEvent(bool auto_reset, bool initially_set);
    ~RtEvent() override;

    Result<void> set();
    Result<void> reset();
    bool is_set() const;

    // Ok / Timeout / typed errors. timeout_ns < 0 = infinite.
    Result<void> wait_ns(pal::MonotonicNs timeout_ns);

    // Milliseconds convenience.
    Result<void> wait_ms(std::int64_t ms) {
        return wait_ns(ms * 1'000'000LL);
    }
    Result<void> wait_infinite() { return wait_ns(pal::kInfiniteTimeout); }

    bool auto_reset() const { return auto_reset_; }

    pal::PalEvent& pal_event() { return *pal_; }  // testing/PAL integration

private:
    void on_destroy() override;  // wakes remaining waiters

    const bool auto_reset_;
    std::unique_ptr<pal::PalEvent> pal_;
};

// ── mutex ─────────────────────────────────────────────────────────────────

class RtMutex : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtMutex, Mutex)

    RtMutex();
    ~RtMutex() override;

    Result<void> lock();
    Result<void> unlock();
    Result<void> try_lock();

    // For condvar pairing (RtCondvar::wait uses this PAL mutex).
    pal::PalMutex& pal_mutex() { return *pal_; }

private:
    void on_destroy() override;

    std::unique_ptr<pal::PalMutex> pal_;
};

// ── semaphore ─────────────────────────────────────────────────────────────

class RtSemaphore : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtSemaphore, Semaphore)

    RtSemaphore(std::int64_t initial, std::int64_t max);
    ~RtSemaphore() override;

    Result<void> acquire();
    Result<void> try_acquire();
    Result<void> release(std::uint32_t count = 1);
    std::int64_t value() const;
    std::int64_t max() const { return max_; }

private:
    void on_destroy() override;  // release extra tokens so waiters wake

    std::unique_ptr<pal::PalSemaphore> pal_;
    const std::int64_t max_;
};

// ── condition variable ────────────────────────────────────────────────────

class RtCondvar : public RuntimeObject {
public:
    // NOTE: TypeId::Condvar is not a built-in; condvars register as
    // RuntimeService-classed objects via a user type id. For M3 the manager
    // treats them via their C++ type; the id below is a registered user type
    // (see sync_objects.cpp: kCondvarTypeId registration).
    static TypeId static_type_id();

    explicit RtCondvar(RtMutex& partner);
    ~RtCondvar() override;

    // Waits on the partner mutex; predicate loop guards spurious wakeups.
    Result<void> wait();
    Result<void> wait_for_ns(pal::MonotonicNs timeout_ns);
    Result<void> notify_one();
    Result<void> notify_all();

private:
    void on_destroy() override;  // broadcast so all waiters recheck + exit

    RtMutex& partner_;
    std::unique_ptr<pal::PalCondvar> pal_;
};

}  // namespace xbox2pc::rt
