// thread_model.cpp — RtThread implementation.

#include "xbox2pc/thread_model.hpp"
#include "xbox2pc/sync_objects.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <utility>

namespace xbox2pc::rt {
namespace {

// Process-wide thread id counter (ids are never zero; 0 is reserved as
// "invalid" for error messages).
std::atomic<std::uint64_t> g_next_thread_id{1};

// ── validated transition table ──────────────────────────────────────────
//
// Legal transitions (architectural model; NOT extracted from Xbox docs —
// documented as inferred in docs/process-thread-model.md):
//   Created  -> Ready (start), Failed
//   Ready    -> Running, Suspended, Failed, Terminated
//   Running  -> Blocked, Suspended, Terminated, Failed, Ready (yield-like)
//   Blocked  -> Running, Terminated, Failed
//   Suspended-> Ready, Terminated, Failed
//   Terminated/Failed are terminal.
constexpr bool kTransitions[7][7] = {
    // to:      Created Ready Running Blocked Suspended Term Failed
    /* Created */ {false, true, false, false, false, false, true},
    /* Ready */ {false, false, true, false, true, true, true},
    /* Running */ {false, true, false, true, true, true, true},
    /* Blocked */ {false, false, true, false, true, true, true},
    /* Suspended */ {false, true, false, false, false, true, true},
    /* Terminated */ {false, false, false, false, false, true, false},
    /* Failed */ {false, false, false, false, false, false, true},
};

int state_index(ThreadState s) {
    switch (s) {
        case ThreadState::Created: return 0;
        case ThreadState::Ready: return 1;
        case ThreadState::Running: return 2;
        case ThreadState::Blocked: return 3;
        case ThreadState::Suspended: return 4;
        case ThreadState::Terminated: return 5;
        case ThreadState::Failed: return 6;
    }
    return 6;
}

}  // namespace

void CooperativeExecutionGate::request_suspend() {
    std::lock_guard guard(mutex_);
    if (!cancelled_.load(std::memory_order_acquire)) suspend_requested_ = true;
}

void CooperativeExecutionGate::resume() {
    {
        std::lock_guard guard(mutex_);
        suspend_requested_ = false;
    }
    changed_.notify_all();
}

void CooperativeExecutionGate::cancel() {
    cancelled_.store(true, std::memory_order_release);
    changed_.notify_all();
}

bool CooperativeExecutionGate::is_suspend_requested() const {
    std::lock_guard guard(mutex_);
    return suspend_requested_;
}

bool CooperativeExecutionGate::is_parked() const {
    return parked_.load(std::memory_order_acquire);
}

bool CooperativeExecutionGate::checkpoint(const std::atomic<bool>& interrupted) {
    std::unique_lock guard(mutex_);
    if (!suspend_requested_) {
        return !cancelled_.load(std::memory_order_acquire) &&
               !interrupted.load(std::memory_order_acquire);
    }
    parked_.store(true, std::memory_order_release);
    while (suspend_requested_ &&
           !cancelled_.load(std::memory_order_acquire) &&
           !interrupted.load(std::memory_order_acquire)) {
        changed_.wait_for(guard, std::chrono::milliseconds(2));
    }
    parked_.store(false, std::memory_order_release);
    return !cancelled_.load(std::memory_order_acquire) &&
           !interrupted.load(std::memory_order_acquire);
}

bool thread_transition_valid(ThreadState from, ThreadState to) {
    return kTransitions[state_index(from)][state_index(to)];
}

const char* thread_state_to_name(ThreadState s) {
    switch (s) {
        case ThreadState::Created: return "created";
        case ThreadState::Ready: return "ready";
        case ThreadState::Running: return "running";
        case ThreadState::Blocked: return "blocked";
        case ThreadState::Suspended: return "suspended";
        case ThreadState::Terminated: return "terminated";
        case ThreadState::Failed: return "failed";
    }
    return "?";
}

const char* thread_priority_to_name(ThreadPriority p) {
    switch (p) {
        case ThreadPriority::Idle: return "idle";
        case ThreadPriority::Low: return "low";
        case ThreadPriority::Normal: return "normal";
        case ThreadPriority::High: return "high";
        case ThreadPriority::Critical: return "critical";
    }
    return "?";
}

std::uint64_t RtThread::next_thread_id() {
    return g_next_thread_id.fetch_add(1, std::memory_order_acq_rel);
}

// ── construction / teardown ───────────────────────────────────────────────

RtThread::RtThread(ThreadMain main, void* arg, std::string name)
    : RuntimeObject(TypeId::Thread),
      thread_id_(next_thread_id()),
      main_(main),
      arg_(arg),
      name_(std::move(name)),
      execution_control_(std::make_shared<CooperativeExecutionGate>()) {}

RtThread::~RtThread() = default;

void RtThread::on_destroy() {
    // A live trampoline still holds a raw pointer to this object, so it
    // must finish before the object can be erased. Detaching after a timeout
    // is unsafe: the host thread may still dereference this object.
    if (host_ == nullptr) return;
    if (!exited_.load(std::memory_order_acquire)) {
        stop_flag_.store(true, std::memory_order_release);
        host_->request_stop();
        execution_control_->cancel();
    }
    while (!trampoline_done_.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    if (!host_joined_) {
        const auto joined = host_->join();
        if (!joined.ok()) set_meta("join-error", joined.context());
    }
}

// ── lifecycle ──────────────────────────────────────────────────────────────

Result<void> RtThread::start() {
    std::lock_guard lock(transition_lock_);
    const ThreadState cur = state_.load(std::memory_order_acquire);
    if (cur != ThreadState::Created) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "start() from " + std::string(thread_state_to_name(cur)));
    }
    if (!is_alive()) {
        return Result<void>(RuntimeErrc::ObjectDestroyed,
                            "start() on a destroying thread object");
    }
    if (stop_flag_.load(std::memory_order_acquire)) {
        return Result<void>(RuntimeErrc::ProcessTerminated,
                            "thread start cancelled by process shutdown");
    }
    host_ = pal::make_host_thread();
    if (host_ == nullptr) {
        return Result<void>(RuntimeErrc::OutOfResources,
                            "host thread allocation failed");
    }
    // Publish Ready before spawning. A fast trampoline must not be
    // overwritten back to Ready after it has already entered Running.
    state_.store(ThreadState::Ready, std::memory_order_release);
    const auto spawned = host_->start(&RtThread::pal_trampoline, this);
    if (!spawned.ok()) {
        state_.store(ThreadState::Failed, std::memory_order_release);
        host_.reset();
        return Result<void>(spawned.errc(), spawned.context());
    }
    return Result<void>::ok_result();
}

void* RtThread::pal_trampoline(void* self_ptr) {
    auto* self = static_cast<RtThread*>(self_ptr);
    self->state_.store(ThreadState::Running, std::memory_order_release);
    void* code = nullptr;
    try {
        code = self->main_(*self, self->arg_);
    } catch (const std::exception& e) {
        self->fail(std::string("thread exception: ") + e.what());
        abandon_guest_mutexes_for_thread(self->thread_id());
        self->exit_code_.store(kExceptionExitCode, std::memory_order_release);
        self->exited_.store(true, std::memory_order_release);
        self->trampoline_done_.store(true, std::memory_order_release);
        return reinterpret_cast<void*>(kExceptionExitCode);
    } catch (...) {
        self->fail("thread exception: unknown type");
        abandon_guest_mutexes_for_thread(self->thread_id());
        self->exit_code_.store(kExceptionExitCode, std::memory_order_release);
        self->exited_.store(true, std::memory_order_release);
        self->trampoline_done_.store(true, std::memory_order_release);
        return reinterpret_cast<void*>(kExceptionExitCode);
    }
    abandon_guest_mutexes_for_thread(self->thread_id());
    const std::uint64_t ec = reinterpret_cast<std::uint64_t>(code);
    self->exit_code_.store(ec, std::memory_order_release);
    self->exited_.store(true, std::memory_order_release);
    self->state_.store(ThreadState::Terminated, std::memory_order_release);
    // Final object access: on_destroy waits for this before erasing self.
    self->trampoline_done_.store(true, std::memory_order_release);
    return code;
}

Result<void> RtThread::suspend() {
    std::lock_guard transition_guard(transition_lock_);
    const ThreadState cur = state_.load(std::memory_order_acquire);
    const ThreadState to = ThreadState::Suspended;
    if (!thread_transition_valid(cur, to)) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "suspend() from " + std::string(thread_state_to_name(cur)));
    }
    execution_control_->request_suspend();
    state_.store(to, std::memory_order_release);
    return Result<void>::ok_result();
}

Result<void> RtThread::resume() {
    std::lock_guard transition_guard(transition_lock_);
    const ThreadState cur = state_.load(std::memory_order_acquire);
    const ThreadState to = ThreadState::Ready;
    if (!thread_transition_valid(cur, to)) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "resume() from " + std::string(thread_state_to_name(cur)));
    }
    execution_control_->resume();
    state_.store(to, std::memory_order_release);
    return Result<void>::ok_result();
}

bool RtThread::suspension_point() {
    const bool allowed = execution_control_->checkpoint(stop_flag_);
    if (!allowed) return false;
    const auto current = state_.load(std::memory_order_acquire);
    if (current == ThreadState::Suspended || current == ThreadState::Ready) {
        state_.store(ThreadState::Running, std::memory_order_release);
    }
    return true;
}

Result<void> RtThread::block_note() {
    // Called from inside sync waits: Running -> Blocked.
    std::lock_guard lock(transition_lock_);
    const ThreadState cur = state_.load(std::memory_order_acquire);
    const ThreadState to = ThreadState::Blocked;
    if (!thread_transition_valid(cur, to)) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "block_note() from " + std::string(thread_state_to_name(cur)));
    }
    state_.store(to, std::memory_order_release);
    return Result<void>::ok_result();
}

Result<void> RtThread::unblock_note() {
    std::lock_guard lock(transition_lock_);
    const ThreadState cur = state_.load(std::memory_order_acquire);
    const ThreadState to = ThreadState::Running;
    if (!thread_transition_valid(cur, to)) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "unblock_note() from " + std::string(thread_state_to_name(cur)));
    }
    state_.store(to, std::memory_order_release);
    return Result<void>::ok_result();
}

Result<void> RtThread::terminate(std::uint64_t exit_code) {
    {
        std::lock_guard lock(transition_lock_);
        const ThreadState cur = state_.load(std::memory_order_acquire);
        const ThreadState to = ThreadState::Terminated;
        if (!thread_transition_valid(cur, to)) {
            return Result<void>(RuntimeErrc::InvalidTransition,
                                "terminate() from " +
                                    std::string(thread_state_to_name(cur)));
        }
        // Terminated -> Terminated is legal (idempotent) per the table.
        state_.store(to, std::memory_order_release);
    }
    stop_flag_.store(true, std::memory_order_release);
    execution_control_->cancel();
    if (host_ != nullptr) host_->request_stop();
    exit_code_.store(exit_code, std::memory_order_release);
    exited_.store(true, std::memory_order_release);
    return Result<void>::ok_result();
}

Result<void> RtThread::fail(std::string reason) {
    {
        std::lock_guard lock(transition_lock_);
        const ThreadState cur = state_.load(std::memory_order_acquire);
        const ThreadState to = ThreadState::Failed;
        if (!thread_transition_valid(cur, to)) {
            return Result<void>(RuntimeErrc::InvalidTransition,
                                "fail() from " + std::string(thread_state_to_name(cur)));
        }
        state_.store(to, std::memory_order_release);
        fail_reason_ = std::move(reason);
    }
    if (host_ != nullptr) {
        stop_flag_.store(true, std::memory_order_release);
        host_->request_stop();
    }
    execution_control_->cancel();
    return Result<void>::ok_result();
}

Result<std::uint64_t> RtThread::join_ns(pal::MonotonicNs timeout_ns) {
    if (host_ == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidState, "thread not started");
    }
    // M4 join-self: comparing the CALLING thread against the host thread
    // must use PAL identity (the host id); comparing runtime ids would miss
    // a thread joining itself since the caller IS this object.
    const pal::HostThread self_id = pal::current_thread();
    const pal::HostThread host_id = host_->id();
    if (self_id.id != 0 && host_id.id != 0 && self_id.id == host_id.id) {
        return Result<std::uint64_t>(RuntimeErrc::ThreadTerminated,
                                     "join-self: a thread cannot join itself");
    }
    // Completed (already host-joined or exited+joined): return recorded code.
    // NOTE: host_joined_ is claimed BEFORE the host join completes (the
    // claimant sets it under the lock, then blocks in pthread_join), so a
    // concurrent joiner arriving here MUST wait for exited_ — the exit
    // code is only valid once the thread actually finished.
    {
        std::unique_lock lock(transition_lock_);
        if (host_joined_) {
            lock.unlock();
            while (!exited_.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            return Result<std::uint64_t>(exit_code_.load(std::memory_order_acquire));
        }
    }
    if (timeout_ns == pal::kInfiniteTimeout) {
        // Exactly one caller performs the host join; concurrent joiners
        // poll the exited flag (they never touch the host thread).
        bool performed_join = false;
        {
            std::lock_guard lock(transition_lock_);
            if (!host_joined_) {
                performed_join = true;
                host_joined_ = true;
            }
        }
        if (performed_join) {
            const auto joined = host_->join();
            if (!joined.ok()) {
                std::lock_guard lock(transition_lock_);
                host_joined_ = false;  // failed join: allow retry
                return Result<std::uint64_t>(joined.errc(), joined.context());
            }
            // The host join can return BEFORE the trampoline's final
            // exit-code store becomes visible (no ordering guarantee
            // between pthread exit and our atomic). Spin on exited_ (set
            // with release in the trampoline's last step) so the code read
            // below is the real one.
            while (!exited_.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            return Result<std::uint64_t>(exit_code_.load(std::memory_order_acquire));
        }
        // Concurrent joiner: wait for the exit flag (bounded poll; the
        // exiting thread sets it before returning from the trampoline).
        while (!exited_.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        return Result<std::uint64_t>(exit_code_.load(std::memory_order_acquire));
    }
    // Bounded wait: poll exited_ until the deadline, then one join.
    const pal::MonotonicNs deadline = pal::now_ns() + timeout_ns;
    while (pal::now_ns() < deadline) {
        if (exited_.load(std::memory_order_acquire)) {
            std::lock_guard lock(transition_lock_);
            if (!host_joined_) {
                host_joined_ = true;
                const auto joined = host_->join();  // returns immediately
                if (!joined.ok()) {
                    host_joined_ = false;
                    return Result<std::uint64_t>(joined.errc(), joined.context());
                }
            }
            return Result<std::uint64_t>(exit_code_.load(std::memory_order_acquire));
        }
        std::this_thread::yield();
    }
    return Result<std::uint64_t>(RuntimeErrc::Timeout, "join_ns deadline");
}

bool RtThread::joinable() const {
    if (host_ == nullptr) return false;
    const ThreadState s = state_.load(std::memory_order_acquire);
    return s != ThreadState::Created;
}

std::uint64_t RtThread::exit_code() const {
    return exit_code_.load(std::memory_order_acquire);
}

std::string RtThread::fail_reason() const {
    std::lock_guard lock(transition_lock_);
    return fail_reason_;
}

void RtThread::request_stop() {
    stop_flag_.store(true, std::memory_order_release);
    if (host_ != nullptr) host_->request_stop();
    execution_control_->cancel();
    // M4: wake the thread's cancellation-aware wait (registered waker).
    wake_for_cancellation();
}

Result<void> RtThread::set_name(const std::string& name) {
    {
        std::lock_guard lock(transition_lock_);
        name_ = name;
    }
    if (host_ == nullptr) {
        return Result<void>(RuntimeErrc::InvalidState, "thread not started");
    }
    return host_->set_name(name);
}

void RtThread::register_cancellation_waker(void* waker) {
    cancellation_waker_.store(waker, std::memory_order_release);
}

void RtThread::unregister_cancellation_waker() {
    cancellation_waker_.store(nullptr, std::memory_order_release);
}

void RtThread::wake_for_cancellation() {
    // The waker is an IWaker* (sync_objects.hpp); its wake_from_cancel()
    // breaks the thread's wait so it can observe the stop flag. Declared
    // out-of-line in the sync layer to keep thread_model.cpp independent.
    if (void* w = cancellation_waker_.load(std::memory_order_acquire)) {
        extern void wake_waker(void* waker);
        wake_waker(w);
    }
}

bool RtThread::stop_requested() const {
    return stop_flag_.load(std::memory_order_acquire);
}

void RtThread::set_priority(ThreadPriority p) { sched_.priority = p; }

// ── TLS ────────────────────────────────────────────────────────────────────
//
// Slot map is guarded by transition_lock_ (all callers are the owning thread
// or lifecycle control paths). Copying len bytes with bounds checks.

Result<void> RtThread::tls_set(std::uint64_t key, const void* data, std::size_t len) {
    if (key == 0) {
        return Result<void>(RuntimeErrc::InvalidArgument, "TLS key 0 reserved");
    }
    if (len > 0 && data == nullptr) {
        return Result<void>(RuntimeErrc::InvalidArgument, "null TLS payload");
    }
    std::lock_guard lock(transition_lock_);
    std::vector<std::uint8_t>& slot = tls_[key];
    slot.assign(static_cast<const std::uint8_t*>(data),
                static_cast<const std::uint8_t*>(data) + len);
    return Result<void>::ok_result();
}

Result<std::vector<std::uint8_t>> RtThread::tls_get(std::uint64_t key) const {
    if (key == 0) {
        return Result<std::vector<std::uint8_t>>(RuntimeErrc::InvalidArgument,
                                                "TLS key 0 reserved");
    }
    std::lock_guard lock(transition_lock_);
    const auto it = tls_.find(key);
    if (it == tls_.end()) {
        return Result<std::vector<std::uint8_t>>(RuntimeErrc::NotFound,
                                                 "TLS key not set");
    }
    return Result<std::vector<std::uint8_t>>(it->second);
}

Result<std::size_t> RtThread::tls_size() const {
    std::lock_guard lock(transition_lock_);
    return Result<std::size_t>(tls_.size());
}

}  // namespace xbox2pc::rt
