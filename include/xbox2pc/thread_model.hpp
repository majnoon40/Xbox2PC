#pragma once
// xbox2pc/thread_model.hpp — M3 abstract thread representation.
//
// Design (docs/process-thread-model.md):
//   - RtThread is a runtime OBJECT (registered in the object manager) that
//     wraps a PAL host thread. Thread identity is the runtime thread id
//     (uint64), NOT the host pthread id (host ids are backend metadata).
//   - Lifecycle: Created -> Ready -> Running -> {Blocked | Suspended} ->
//     Terminated; Failed reachable from any pre-terminal state on error.
//     Transitions are validated (table in thread_model.cpp); invalid
//     transitions return InvalidTransition with a descriptive context.
//   - TLS: per-thread slot map (uint64 key -> bytes), host-independent.
//   - Scheduling metadata: priority is an abstract enum (Idle..Critical);
//     M3 does NOT implement a scheduler (explicit exclusion — the PAL
//     thread runs host-scheduled).
//   - No undocumented Xbox scheduling internals are reproduced; the state
//     machine is an architectural model (documented as inferred).
//
// Concurrency: state transitions take an internal mutex; readers use the
// atomic state(). The joined exit status is written once at termination.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "xbox2pc/handle_manager.hpp"
#include "xbox2pc/platform.hpp"

namespace xbox2pc::rt {

// Shared cooperative gate used by managed threads and execution backends.
// Suspension is resumable; cancellation is terminal and always wakes a parked
// checkpoint. Safe points are explicit: callers must check between work units.
class CooperativeExecutionGate {
public:
    void request_suspend();
    void resume();
    void cancel();
    bool is_suspend_requested() const;
    bool is_cancelled() const;
    bool is_parked() const;
    bool checkpoint(const std::atomic<bool>& interrupted);
private:
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    bool suspend_requested_ = false;
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> parked_{false};
};

// ── thread states ─────────────────────────────────────────────────────────
enum class ThreadState {
    Created,    // object exists; host thread not started
    Ready,      // started + gate released, runnable
    Running,    // executing on the host
    Blocked,    // waiting on a sync primitive
    Suspended,  // cooperative suspend requested
    Terminated, // exited; joinable for exit code
    Failed,     // aborted by error
};

const char* thread_state_to_name(ThreadState s);

// ── priority abstraction ───────────────────────────────────────────────────
enum class ThreadPriority { Idle = 0, Low = 1, Normal = 2, High = 3, Critical = 4 };
const char* thread_priority_to_name(ThreadPriority p);

// ── scheduling metadata (abstract; host maps it best-effort) ────────────────
struct ThreadScheduling {
    ThreadPriority priority = ThreadPriority::Normal;
    std::uint64_t ideal_processor = 0;   // abstract core mask/index (M3: info only)
    std::uint64_t quantum_hint_ms = 0;  // M3: informational, not enforced
};

// ── thread object ──────────────────────────────────────────────────────────

class RtThread : public RuntimeObject {
public:
    XBOX2PC_RUNTIME_OBJECT_TYPE(RtThread, Thread)

    using ThreadMain = void* (*)(RtThread& self, void* user_arg);

    RtThread(ThreadMain main, void* arg, std::string name,
             std::uint64_t owner_process_id = 0);
    ~RtThread() override;

    // Lifecycle control.
    Result<void> start();           // Created -> Ready (host thread spawned)
    Result<void> suspend();         // Running/Ready -> Suspended (cooperative)
    Result<void> resume();          // Suspended -> Ready
    // Cooperative safe point for thread mains. Returns false after stop.
    // A suspended thread parks here until resume() or request_stop().
    bool suspension_point();
    std::shared_ptr<CooperativeExecutionGate> execution_control() const {
        return execution_control_;
    }
    Result<void> block_note();      // Running -> Blocked (called by sync waits)
    Result<void> unblock_note();    // Blocked -> Running/Ready
    Result<void> terminate(std::uint64_t exit_code);  // -> Terminated
    Result<void> fail(std::string reason);            // -> Failed

    Result<std::uint64_t> join_ns(pal::MonotonicNs timeout_ns);  // wait exit
    bool joinable() const;

    // ── M4 join semantics (explicitly defined, all tested) ──
    // Joining a COMPLETED (Terminated) thread: returns the exit code
    // immediately (repeat joins after completion return the recorded
    // status — host join happens exactly once internally).
    // Joining ONESELF: returns ThreadTerminated with context
    // "join-self" (a thread cannot wait for its own exit).
    // Multiple concurrent join attempts: exactly one performs the host
    // join; the others wait on the completion latch and then read the
    // recorded exit code (joinable-join coordination below).

    // M4: exception containment. ThreadMain2 may throw; the trampoline
    // catches ALL exceptions at the thread boundary, records the
    // failure (state Failed + reason) and returns a distinct exit code
    // (kExceptionExitCode). No exception ever escapes a runtime thread.
    using ThreadMain2 = std::function<void*(RtThread& self, void* arg)>;
    static constexpr std::uint64_t kExceptionExitCode = 0xDEAD'0000'0000'0001ull;

    // M4: set_name forwards to the PAL thread (pthread_setname_np, 16-byte
    // host truncation documented).
    Result<void> set_name(const std::string& name);

    // M4: cooperative cancellation. request_stop() sets the flag AND wakes
    // any cancellation-aware wait the thread holds (via its registered
    // waker — see sync_objects.hpp). Threads observe cancellation at
    // safe points: stop_requested() polls, cancellation-aware waits.
    void register_cancellation_waker(void* waker);   // opaque IWaker*
    void unregister_cancellation_waker();
    void wake_for_cancellation();   // calls the registered waker

    // Introspection.
    ThreadState state() const { return state_.load(std::memory_order_acquire); }
    std::uint64_t thread_id() const { return thread_id_; }
    // Stable guest process identity assigned by ProcessManager before start.
    std::uint64_t owner_process_id() const { return owner_process_id_; }
    std::uint64_t exit_code() const;
    ThreadPriority priority() const { return sched_.priority; }
    void set_priority(ThreadPriority p);   // abstract; host mapping later
    const ThreadScheduling& scheduling() const { return sched_; }
    std::string fail_reason() const;

    // Cooperative stop flag (PAL request_stop mirrors it).
    void request_stop();
    bool stop_requested() const;

    // ── TLS (host-independent) ──────────────────────────────────────────
    // Slots are byte arrays keyed by uint64 (TLS index). Freeing other
    // threads' slots is prohibited (validated).
    Result<void> tls_set(std::uint64_t key, const void* data, std::size_t len);
    Result<std::vector<std::uint8_t>> tls_get(std::uint64_t key) const;
    Result<std::size_t> tls_size() const;

    // Static-thread bootstrap helper: PAL threads take plain fn(void*);
    // trampoline adapts.
    static void* pal_trampoline(void* self_ptr);

private:
    void on_destroy() override;

    const std::uint64_t thread_id_;        // runtime id (unique, never zero)
    const std::uint64_t owner_process_id_; // zero only for unmanaged/test threads
    ThreadMain const main_;
    void* const arg_;
    std::string name_;
    std::atomic<ThreadState> state_{ThreadState::Created};
    ThreadScheduling sched_;
    std::unique_ptr<pal::PalThread> host_;
    mutable std::mutex transition_lock_;   // serializes transitions (const readers lock too)
    std::atomic<bool> stop_flag_{false};
    std::shared_ptr<CooperativeExecutionGate> execution_control_;
    std::atomic<std::uint64_t> exit_code_{0};
    std::atomic<bool> exited_{false};
    std::string fail_reason_;
    // TLS (guarded by transition_lock_ + thread affinity)
    std::map<std::uint64_t, std::vector<std::uint8_t>> tls_;

    // Id assignment (thread ids from a process-wide counter via helper).
    static std::uint64_t next_thread_id();

    // ── M4 implementation fields ──
    std::atomic<bool> trampoline_done_{false};  // last trampoline touch of this
    bool host_joined_ = false;              // host join happened exactly once
    std::atomic<void*> cancellation_waker_{nullptr};  // opaque IWaker*
    // Exception-carrying main (set by start_with_fn); pal_trampoline
    // wraps it with the containment try/catch.
    ThreadMain2 main2_;
};

// ── validated transition helper (exposed for tests) ────────────────────────
// Returns true when from -> to is legal per the M3 state machine.
bool thread_transition_valid(ThreadState from, ThreadState to);

}  // namespace xbox2pc::rt
