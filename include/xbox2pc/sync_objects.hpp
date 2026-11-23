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

#include <atomic>
#include <chrono>\n#include <condition_variable>\n#include <functional>
#include <cstdint>
#include <memory>
#include <vector>

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


class RtGuestMutex : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtGuestMutex, Mutex)
    RtGuestMutex() : RuntimeObject(TypeId::Mutex) {}
    Result<bool> acquire(std::uint64_t guest_thread_id, pal::MonotonicNs timeout_ns,
                         const std::function<bool()>& cancelled = {});
    Result<void> release(std::uint64_t guest_thread_id);
    Result<void> abandon_owner(std::uint64_t guest_thread_id);
    void close();
    bool is_closed() const;
private:
    void on_destroy() override { close(); }
    mutable std::mutex lock_;
    std::condition_variable changed_;
    std::uint64_t owner_thread_id_ = 0;
    std::uint32_t recursion_ = 0;
    bool abandoned_ = false;
    bool closed_ = false;
};

class RtGuestSemaphore : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtGuestSemaphore, Semaphore)
    RtGuestSemaphore(std::int64_t initial_count, std::int64_t maximum_count);
    Result<void> acquire(pal::MonotonicNs timeout_ns,
                         const std::function<bool()>& cancelled = {});
    Result<void> try_acquire();
    Result<std::int64_t> release(std::uint32_t count = 1);
    std::int64_t value() const;
    std::int64_t max() const { return maximum_count_; }
    void close();
    bool is_closed() const;
private:
    void on_destroy() override { close(); }
    mutable std::mutex lock_;
    std::condition_variable changed_;
    std::int64_t count_ = 0;
    const std::int64_t maximum_count_;
    const bool valid_initialization_;
    bool closed_ = false;
};
\n// ── condition variable ────────────────────────────────────────────────────

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

// ── M4: cancellation-aware waiting + waiter tracking ──────────────────────

// IWaker: the interface a thread registers so request_stop() can break its
// current wait. Implemented by RtCancellableWait below.
class IWaker {
public:
    virtual ~IWaker() = default;
    virtual void wake_from_cancel() = 0;
};

// A cancellation-aware timed wait helper. The CALLING thread parks itself
// on a private event; the wait ends when (whichever comes first):
//   - the deadline passes           -> Timeout
//   - the condition functor sets    -> Ok (the functor polls a shared
//                                       predicate state each tick)
//   - request_stop() wakes it       -> ThreadTerminated (cancellation)
// Design: poll-based (tick granularity 2 ms) instead of hooked into every
// primitive — a deliberate simplicity/robustness trade documented in
// docs/thread-execution.md; no lost-wakeup class exists because the
// predicate is re-checked after every wake.
class RtCancellableWait : public IWaker {
public:
    RtCancellableWait() = default;
    ~RtCancellableWait() override = default;

    // Waits until `predicate()` returns true, the deadline, or
    // cancellation. Returns Ok / Timeout / ThreadTerminated.
    template <typename Pred>
    Result<void> wait_until(Pred predicate, pal::MonotonicNs timeout_ns) {
        if (predicate()) return Result<void>::ok_result();
        const pal::MonotonicNs deadline =
            timeout_ns < 0 ? INT64_MAX : pal::now_ns() + timeout_ns;
        for (;;) {
            if (predicate()) return Result<void>::ok_result();
            if (cancelled_.load(std::memory_order_acquire)) {
                return Result<void>(RuntimeErrc::ThreadTerminated,
                                     "wait cancelled by request_stop");
            }
            if (pal::now_ns() >= deadline) {
                return Result<void>(RuntimeErrc::Timeout, "wait deadline");
            }
            // Park with small ticks: 2 ms bounds both latency and CPU.
            (void)wake_ev_->wait_ns(2'000'000);
        }
    }

    void wake_from_cancel() override {
        cancelled_.store(true, std::memory_order_release);
        wake_ev_->set();
    }

private:
    std::unique_ptr<pal::PalEvent> wake_ev_{pal::make_event(false, /*auto_reset=*/true)};
    std::atomic<bool> cancelled_{false};
};

// ── M4: waiter tracking + wait-any / wait-all ─────────────────────────────
//
// WaitSet composes existing primitives WITHOUT changing their semantics:
//   wait_any : first successful primitive wait wins (index returned);
//              all are non-blocking candidates (poll + timed re-poll), so
//              no deadlock ordering issues can arise.
//   wait_all : every primitive must become ready within the deadline
//              (progressive acquisition with back-off; the set is NOT a
//              transaction — later candidates may release earlier ones'
//              effects only through their own semantics).
// Implemented over the primitives' OWN try/timed interfaces so the
// M3-tested semantics stay authoritative (documented deviation: polling
// granularity 2 ms).
class WaitSet {
public:
    // A candidate: what to wait on. Exactly one wait method is non-null.
    struct Candidate {
        RtEvent* event = nullptr;          // waits is_set
        RtSemaphore* semaphore = nullptr;  // waits acquire
        RtMutex* mutex = nullptr;          // waits lock
    };

    WaitSet() = default;

    void add_event(RtEvent& e) { candidates_.push_back(Candidate{&e, nullptr, nullptr}); }
    void add_semaphore(RtSemaphore& s) { candidates_.push_back(Candidate{nullptr, &s, nullptr}); }
    void add_mutex(RtMutex& m) { candidates_.push_back(Candidate{nullptr, nullptr, &m}); }
    std::size_t size() const { return candidates_.size(); }

    // Wait-any: returns the index of the FIRST candidate that becomes
    // ready within the deadline. Timeout when none.
    Result<std::size_t> wait_any(pal::MonotonicNs timeout_ns);
    // Wait-all: every candidate ready within the deadline (order: the
    // registration order). Acquired mutexes stay LOCKED on success (the
    // caller owns unlocking); on failure/timeout everything is released.
    Result<void> wait_all(pal::MonotonicNs timeout_ns);

private:
    // Probe ONE candidate without blocking. Returns Ok when it is (or
    // became) ready — side effects applied (semaphore acquired, mutex
    // locked, event consumed for auto-reset).
    Result<void> probe_ready(const Candidate& c);
    // Undo a probe (rollback on wait_all failure).
    void undo_probe(const Candidate& c);

    std::vector<Candidate> candidates_;
};

}  // namespace xbox2pc::rt
