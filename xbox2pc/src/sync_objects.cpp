// sync_objects.cpp — runtime synchronization object implementations.

#include "xbox2pc/sync_objects.hpp"

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
