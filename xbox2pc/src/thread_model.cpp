// thread_model.cpp — RtThread implementation.

#include "xbox2pc/thread_model.hpp"

#include <atomic>
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
    /* Blocked */ {false, false, true, false, false, true, true},
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
      name_(std::move(name)) {}

RtThread::~RtThread() = default;

void RtThread::on_destroy() {
    // If the host thread never started, nothing to do. If it ran and was
    // never joined, detach so the host never keeps a zombie. If it is still
    // running, request a cooperative stop — M3 never kills host threads
    // (documented safety rule).
    if (host_ != nullptr) {
        if (!exited_.load(std::memory_order_acquire)) {
            stop_flag_.store(true);
            host_->request_stop();
            host_->detach();
        }
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
    host_ = pal::make_host_thread();
    const auto spawned = host_->start(&RtThread::pal_trampoline, this);
    if (!spawned.ok()) {
        return Result<void>(spawned.errc(), spawned.context());
    }
    // Created -> Ready: host thread spawned, trampoline gate handles the
    // visibility of `this`.
    state_.store(ThreadState::Ready, std::memory_order_release);
    return Result<void>::ok_result();
}

void* RtThread::pal_trampoline(void* self_ptr) {
    auto* self = static_cast<RtThread*>(self_ptr);
    self->state_.store(ThreadState::Running, std::memory_order_release);
    void* code = self->main_(*self, self->arg_);
    const std::uint64_t ec = reinterpret_cast<std::uint64_t>(code);
    self->exit_code_.store(ec, std::memory_order_release);
    self->exited_.store(true, std::memory_order_release);
    self->state_.store(ThreadState::Terminated, std::memory_order_release);
    return code;
}

Result<void> RtThread::suspend() {
    std::lock_guard lock(transition_lock_);
    const ThreadState cur = state_.load(std::memory_order_acquire);
    const ThreadState to = ThreadState::Suspended;
    if (!thread_transition_valid(cur, to)) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "suspend() from " + std::string(thread_state_to_name(cur)));
    }
    // Cooperative: set the flag; the thread observes it at safe points.
    stop_flag_.store(true, std::memory_order_release);
    if (host_ != nullptr) host_->request_stop();
    state_.store(to, std::memory_order_release);
    return Result<void>::ok_result();
}

Result<void> RtThread::resume() {
    std::lock_guard lock(transition_lock_);
    const ThreadState cur = state_.load(std::memory_order_acquire);
    const ThreadState to = ThreadState::Ready;
    if (!thread_transition_valid(cur, to)) {
        return Result<void>(RuntimeErrc::InvalidTransition,
                            "resume() from " + std::string(thread_state_to_name(cur)));
    }
    stop_flag_.store(false, std::memory_order_release);
    state_.store(to, std::memory_order_release);
    return Result<void>::ok_result();
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
    return Result<void>::ok_result();
}

Result<std::uint64_t> RtThread::join_ns(pal::MonotonicNs timeout_ns) {
    if (host_ == nullptr) {
        return Result<std::uint64_t>(RuntimeErrc::InvalidState, "thread not started");
    }
    // The PAL join is a full wait; timeout joins are approximated by a
    // bounded poll of the exited flag + detach-free waiting (host join has
    // no timeout). Exact-once join enforced by PAL backend state.
    if (timeout_ns == pal::kInfiniteTimeout) {
        const auto joined = host_->join();
        if (!joined.ok()) {
            return Result<std::uint64_t>(joined.errc(), joined.context());
        }
        return Result<std::uint64_t>(exit_code_.load(std::memory_order_acquire));
    }
    // Bounded wait: poll exited_ every 1ms until deadline.
    const pal::MonotonicNs deadline = pal::now_ns() + timeout_ns;
    while (pal::now_ns() < deadline) {
        if (exited_.load(std::memory_order_acquire)) {
            const auto joined = host_->join();  // returns immediately
            if (!joined.ok()) {
                return Result<std::uint64_t>(joined.errc(), joined.context());
            }
            return Result<std::uint64_t>(exit_code_.load(std::memory_order_acquire));
        }
        std::this_thread::yield();
    }
    if (exited_.load(std::memory_order_acquire)) {
        const auto joined = host_->join();
        if (!joined.ok()) {
            return Result<std::uint64_t>(joined.errc(), joined.context());
        }
        return Result<std::uint64_t>(exit_code_.load(std::memory_order_acquire));
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
