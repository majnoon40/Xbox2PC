// sync_objects.cpp — runtime synchronization object implementations.

#include "xbox2pc/sync_objects.hpp"

#include <chrono>
#include <algorithm>
#include <climits>
#include <thread>
#include <utility>

namespace xbox2pc::rt {
namespace {

// Condvar user type id (>= kUserTypeBase; registered once at load).
constexpr TypeId kCondvarTypeId = static_cast<TypeId>(kUserTypeBase + 1);

// One-time registration; the registry instance is initialized before main
// via this static in a function called from every constructor (idempotent).
bool register_condvar_type() {
    static const bool ok =
        ObjectTypeRegistry::instance().register_user_type(kCondvarTypeId, "condvar");
    return ok;
}

}  // namespace

TypeId RtCondvar::static_type_id() { return kCondvarTypeId; }

// ── RtEvent ────────────────────────────────────────────────────────────────

RtEvent::RtEvent(bool auto_reset, bool initially_set)
    : RuntimeObject(TypeId::Event),
      auto_reset_(auto_reset),
      pal_(pal::make_event(initially_set, auto_reset)) {}

RtEvent::~RtEvent() = default;

Result<void> RtEvent::set() { return pal_->set(); }

Result<void> RtEvent::reset() { return pal_->reset(); }

bool RtEvent::is_set() const { return pal_->is_set(); }

Result<void> RtEvent::wait_ns(pal::MonotonicNs timeout_ns) {
    return pal_->wait_ns(timeout_ns);
}

void RtEvent::on_destroy() {
    // Destruction while waiting: wake everyone so no waiter blocks forever
    // on a destroyed object. PAL event dtor runs right after on_destroy.
    pal_->set();
}

// ── RtMutex ────────────────────────────────────────────────────────────────

RtMutex::RtMutex() : RuntimeObject(TypeId::Mutex), pal_(pal::make_mutex()) {}

RtMutex::~RtMutex() = default;

Result<void> RtMutex::lock() { return pal_->lock(); }

Result<void> RtMutex::unlock() { return pal_->unlock(); }

Result<void> RtMutex::try_lock() {
    if (pal_->try_lock()) {
        return Result<void>::ok_result();
    }
    return Result<void>(RuntimeErrc::Timeout, "try_lock: held elsewhere");
}

void RtMutex::on_destroy() {
    // Ownership state is tracked by the PAL mutex itself; pthread mutex
    // destruction of a locked mutex is UB, so if a destroy is attempted we
    // cannot detect ownership portably — we surface nothing silently here
    // and document that destroying a locked mutex is caller error (the PAL
    // backend keeps its own invariants; robust ownership tracking with
    // thread ids is a documented M4 item).
}

// ── RtSemaphore ─────────────────────────────────────────────────────────────

RtSemaphore::RtSemaphore(std::int64_t initial, std::int64_t max)
    : RuntimeObject(TypeId::Semaphore),
      pal_(pal::make_semaphore(initial, max)),
      max_(max) {}

RtSemaphore::~RtSemaphore() = default;

Result<void> RtSemaphore::acquire() { return pal_->acquire(); }

Result<void> RtSemaphore::try_acquire() { return pal_->try_acquire(); }

Result<void> RtSemaphore::release(std::uint32_t count) {
    return pal_->release(count);
}

std::int64_t RtSemaphore::value() const { return pal_->value(); }

void RtSemaphore::on_destroy() {
    // Wake blocked waiters so destroy() cannot hang on PAL internals.
    pal_->release(static_cast<std::uint32_t>(max_ > 0 ? max_ : 1));
}


namespace {
pal::MonotonicNs guest_wait_deadline(pal::MonotonicNs timeout_ns) {
    if (timeout_ns < 0) return INT64_MAX;
    const auto now = pal::now_ns();
    return timeout_ns > INT64_MAX - now ? INT64_MAX : now + timeout_ns;
}
bool guest_wait_cancelled(const std::function<bool()>& cancelled) {
    return cancelled && cancelled();
}
}  // namespace

Result<bool> RtGuestMutex::acquire(std::uint64_t tid, pal::MonotonicNs timeout_ns,
                                   const std::function<bool()>& cancelled) {
    if (tid == 0) return Result<bool>(RuntimeErrc::InvalidArgument, "guest mutex requires nonzero thread id");
    const auto deadline = guest_wait_deadline(timeout_ns);
    std::unique_lock guard(lock_);
    for (;;) {
        if (closed_) return Result<bool>(RuntimeErrc::ObjectDestroyed, "guest mutex is closed");
        if (guest_wait_cancelled(cancelled)) return Result<bool>(RuntimeErrc::ThreadTerminated, "guest mutex wait cancelled");
        if (owner_thread_id_ == tid) {
            if (recursion_ == UINT32_MAX) return Result<bool>(RuntimeErrc::OutOfResources, "guest mutex recursion count exhausted");
            ++recursion_;
            return Result<bool>(false);
        }
        if (owner_thread_id_ == 0) {
            owner_thread_id_ = tid;
            recursion_ = 1;
            const bool was_abandoned = abandoned_;
            abandoned_ = false;
            return Result<bool>(was_abandoned);
        }
        const auto now = pal::now_ns();
        if (timeout_ns == 0 || now >= deadline) return Result<bool>(RuntimeErrc::Timeout, "guest mutex wait deadline");
        const auto remaining = deadline == INT64_MAX ? pal::MonotonicNs(2'000'000)
            : std::min<pal::MonotonicNs>(2'000'000, deadline - now);
        changed_.wait_for(guard, std::chrono::nanoseconds(remaining));
    }
}
Result<void> RtGuestMutex::release(std::uint64_t tid) {
    if (tid == 0) return Result<void>(RuntimeErrc::InvalidArgument, "guest mutex release requires nonzero thread id");
    std::lock_guard guard(lock_);
    if (closed_) return Result<void>(RuntimeErrc::ObjectDestroyed, "guest mutex is closed");
    if (owner_thread_id_ != tid || recursion_ == 0) return Result<void>(RuntimeErrc::LockNotOwned, "guest thread does not own mutex");
    if (--recursion_ == 0) { owner_thread_id_ = 0; changed_.notify_all(); }
    return Result<void>::ok_result();
}
Result<void> RtGuestMutex::abandon_owner(std::uint64_t tid) {
    if (tid == 0) return Result<void>(RuntimeErrc::InvalidArgument, "abandon requires nonzero thread id");
    std::lock_guard guard(lock_);
    if (owner_thread_id_ != tid) return Result<void>(RuntimeErrc::LockNotOwned, "guest thread is not mutex owner");
    owner_thread_id_ = 0; recursion_ = 0; abandoned_ = true; changed_.notify_all();
    return Result<void>::ok_result();
}
void RtGuestMutex::close() {
    std::lock_guard guard(lock_);
    closed_ = true; owner_thread_id_ = 0; recursion_ = 0; changed_.notify_all();
}
bool RtGuestMutex::is_closed() const { std::lock_guard guard(lock_); return closed_; }

RtGuestSemaphore::RtGuestSemaphore(std::int64_t initial, std::int64_t maximum)
    : RuntimeObject(TypeId::Semaphore), count_(initial), maximum_count_(maximum),
      valid_initialization_(maximum > 0 && initial >= 0 && initial <= maximum) {}
Result<void> RtGuestSemaphore::acquire(pal::MonotonicNs timeout_ns,
                                       const std::function<bool()>& cancelled) {
    if (!valid_initialization_) return Result<void>(RuntimeErrc::InvalidArgument, "requires 0 <= initial <= maximum and maximum > 0");
    const auto deadline = guest_wait_deadline(timeout_ns);
    std::unique_lock guard(lock_);
    for (;;) {
        if (closed_) return Result<void>(RuntimeErrc::ObjectDestroyed, "guest semaphore is closed");
        if (guest_wait_cancelled(cancelled)) return Result<void>(RuntimeErrc::ThreadTerminated, "guest semaphore wait cancelled");
        if (count_ > 0) { --count_; return Result<void>::ok_result(); }
        const auto now = pal::now_ns();
        if (timeout_ns == 0 || now >= deadline) return Result<void>(RuntimeErrc::Timeout, "guest semaphore wait deadline");
        const auto remaining = deadline == INT64_MAX ? pal::MonotonicNs(2'000'000)
            : std::min<pal::MonotonicNs>(2'000'000, deadline - now);
        changed_.wait_for(guard, std::chrono::nanoseconds(remaining));
    }
}
Result<void> RtGuestSemaphore::try_acquire() { return acquire(0); }
Result<std::int64_t> RtGuestSemaphore::release(std::uint32_t count) {
    if (!valid_initialization_) return Result<std::int64_t>(RuntimeErrc::InvalidArgument, "invalid semaphore initialization");
    if (count == 0) return Result<std::int64_t>(RuntimeErrc::InvalidArgument, "release count must be nonzero");
    std::lock_guard guard(lock_);
    if (closed_) return Result<std::int64_t>(RuntimeErrc::ObjectDestroyed, "guest semaphore is closed");
    if (static_cast<std::int64_t>(count) > maximum_count_ - count_)
        return Result<std::int64_t>(RuntimeErrc::InvalidState, "release would exceed semaphore maximum");
    const auto previous = count_; count_ += static_cast<std::int64_t>(count); changed_.notify_all();
    return Result<std::int64_t>(previous);
}
std::int64_t RtGuestSemaphore::value() const { std::lock_guard guard(lock_); return count_; }
void RtGuestSemaphore::close() { std::lock_guard guard(lock_); closed_ = true; changed_.notify_all(); }
bool RtGuestSemaphore::is_closed() const { std::lock_guard guard(lock_); return closed_; }

// ── RtCondvar ──────────────────────────────────────────────────────────────

RtCondvar::RtCondvar(RtMutex& partner)
    : RuntimeObject(static_type_id()), partner_(partner) {
    register_condvar_type();
    pal_ = pal::make_condvar();
}

RtCondvar::~RtCondvar() = default;

Result<void> RtCondvar::wait() { return pal_->wait(partner_.pal_mutex()); }

Result<void> RtCondvar::wait_for_ns(pal::MonotonicNs timeout_ns) {
    return pal_->wait_for_ns(partner_.pal_mutex(), timeout_ns);
}

Result<void> RtCondvar::notify_one() { return pal_->notify_one(); }

Result<void> RtCondvar::notify_all() { return pal_->notify_all(); }

void RtCondvar::on_destroy() {
    // Broadcast so every waiter wakes, rechecks (object destroying) and
    // returns instead of blocking on a torn-down condvar.
    pal_->notify_all();
}

}  // namespace xbox2pc::rt

// ── M4: wake_waker (thread_model.cpp extern) ─────────────────────────────

namespace xbox2pc::rt {
void wake_waker(void* waker);
}  // namespace xbox2pc::rt

namespace xbox2pc::rt {

void wake_waker(void* waker) {
    if (auto* w = static_cast<IWaker*>(waker)) {
        w->wake_from_cancel();
    }
}

// ── M4: WaitSet ──────────────────────────────────────────────────────────

Result<void> WaitSet::probe_ready(const Candidate& c) {
    if (c.event != nullptr) {
        // Non-blocking readiness probe: a set event waits successfully
        // with timeout 0 (auto-reset events consume here — the caller got
        // the signal).
        return c.event->wait_ns(0);
    }
    if (c.semaphore != nullptr) {
        return c.semaphore->try_acquire();
    }
    if (c.mutex != nullptr) {
        return c.mutex->try_lock();
    }
    return Result<void>(RuntimeErrc::InvalidArgument, "empty candidate");
}

void WaitSet::undo_probe(const Candidate& c) {
    if (c.mutex != nullptr) {
        (void)c.mutex->unlock();
    } else if (c.semaphore != nullptr) {
        (void)c.semaphore->release();
    }
    // Events: an auto-reset consume cannot be "un-signaled"; wait_all
    // failure after an event consume is documented (the signal was
    // delivered; the overall wait failed). Rare and non-destructive.
}

Result<std::size_t> WaitSet::wait_any(pal::MonotonicNs timeout_ns) {
    if (candidates_.empty()) {
        return Result<std::size_t>(RuntimeErrc::InvalidArgument, "empty set");
    }
    const pal::MonotonicNs deadline =
        timeout_ns < 0 ? INT64_MAX : pal::now_ns() + timeout_ns;
    for (;;) {
        for (std::size_t i = 0; i < candidates_.size(); ++i) {
            if (probe_ready(candidates_[i]).ok()) {
                return Result<std::size_t>(i);
            }
        }
        if (pal::now_ns() >= deadline) {
            return Result<std::size_t>(RuntimeErrc::Timeout, "no candidate ready");
        }
        // 2 ms poll tick (documented granularity).
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

Result<void> WaitSet::wait_all(pal::MonotonicNs timeout_ns) {
    if (candidates_.empty()) {
        return Result<void>(RuntimeErrc::InvalidArgument, "empty set");
    }
    const pal::MonotonicNs deadline =
        timeout_ns < 0 ? INT64_MAX : pal::now_ns() + timeout_ns;
    std::vector<bool> acquired(candidates_.size(), false);
    std::size_t acquired_count = 0;
    for (;;) {
        for (std::size_t i = 0; i < candidates_.size(); ++i) {
            if (!acquired[i] && probe_ready(candidates_[i]).ok()) {
                acquired[i] = true;
                ++acquired_count;
            }
        }
        if (acquired_count == candidates_.size()) {
            return Result<void>::ok_result();  // caller owns the effects
        }
        if (pal::now_ns() >= deadline) {
            // Roll back everything acquired so far.
            for (std::size_t i = 0; i < candidates_.size(); ++i) {
                if (acquired[i]) undo_probe(candidates_[i]);
            }
            return Result<void>(RuntimeErrc::Timeout, "wait_all deadline");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

}  // namespace xbox2pc::rt
