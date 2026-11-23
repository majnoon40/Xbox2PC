# M4 — Thread Execution

## Responsibility

`RtThread` (`thread_model.hpp/.cpp`, library `xbox2pc_rt_thread`) is now a
fully functional host-backed execution wrapper over the PAL thread (M3
added the model; M4 makes it execute, with defined semantics for the hard
cases).

## Execution model

- `start()` spawns the host thread through the PAL (gated trampoline —
  no `pthread_create` torn reads; see
  [platform-abstraction.md](platform-abstraction.md)).
- The trampoline runs the user `ThreadMain(self, arg)` and publishes, in
  order: `exit_code_` → `exited_` → `state_` → **`trampoline_done_`**
  (the object's last touch — see "Destruction handshake").
- Exit status propagation: the return value becomes the runtime exit
  code; `join_ns` returns it (infinite or bounded).

## Defined join semantics (all tested)

| Case | Behavior |
|---|---|
| join a completed thread | returns the recorded exit code immediately; repeat joins keep returning it (`ThreadExecTest.ThreadExecTest.StartupCompletionJoinExit`) |
| join oneself | typed `ThreadTerminated` with context "join-self" — detected via PAL `current_thread()` vs the host thread id (`JoinSelfRejected`) |
| multiple concurrent joiners | exactly one caller performs the host join (claim flag under the transition lock); the others poll `exited_` and read the recorded code (`MultipleJoiners` — found and fixed a real race: joiners could return a stale code because `host_joined_` was claimed *before* the join completed) |
| bounded join | polls `exited_` until the deadline, then `Timeout` |
| join an unstarted thread | typed `InvalidState` |

## Exception containment

The trampoline wraps `ThreadMain` in try/catch (**all** types):
- `std::exception` → `fail("thread exception: " + what())`;
- unknown types → `fail("thread exception: unknown type")`.

Both record state `Failed` + a distinct exit code
`RtThread::kExceptionExitCode` and nothing ever escapes a runtime thread
(`ExceptionContainment`).

## Cooperative cancellation

- `request_stop()` sets the stop flag, mirrors it to the PAL
  (`request_stop`) **and wakes the thread's registered cancellation
  waker** (an `IWaker*` — see below). Host threads are never forcibly
  killed (M3/M4 safety rule).
- `RtCancellableWait::wait_until(pred, timeout)` (sync_objects.hpp) is the
  cancellation-aware wait: it polls the predicate on 2 ms park ticks and
  ends with Ok (predicate true), `Timeout` (deadline), or
  `ThreadTerminated` (woken by cancellation). Threads register the wait
  via `RtThread::register_cancellation_waker` so `request_stop` breaks
  their wait; `CancellationToken`-style semantics, no lost-wakeup class
  because the predicate is re-checked after every wake.
- Suspension is separate from cancellation. Each `RtThread` owns a
  shared `CooperativeExecutionGate`; `suspend()` requests a resumable
  pause, `resume()` releases it, and `request_stop()` terminally cancels
  it and wakes parked checkpoints. Thread mains cooperate through
  `suspension_point()`.
- `ProcessManager::spawn_thread` stamps the stable guest process ID onto
  each managed `RtThread` before it starts. Constructing an
  `ExecutionContext` from that managed thread derives the guest TID from
  `RtThread::thread_id()` and automatically shares its gate; zero or
  mismatched/unmanaged identities are rejected during initialization.
  This removes a separate manually supplied TID/control pair for managed
  execution contexts. The legacy explicit PID/TID constructor remains for
  synthetic tests and externally managed contexts.
- `ExecutionContext::prepare_entry` retains the image's assigned TLS
  index in its per-thread context metadata. `invoke` and `step` propagate
  the same gate to the backend. TLS callback execution attaches that gate
  and binds the same PID/TID/address-space tuple as normal guest execution.
  Nested task-queue callbacks inherit the active request's gate and
  execution identity, so suspension and termination apply consistently at
  callback instruction boundaries. Per-image TLS template materialization
  remains the explicit `api::tls_init_thread` operation; this milestone
  does not claim implicit loader-side TLS allocation.
- `ProcessManager::suspend_process` and `resume_process` apply those
  distinct operations across owned live threads, with rollback if a thread
  transition fails. The Win32 event/mutex/semaphore wait path checks the
  same cooperative safe point while polling, so a blocked guest thread can
  be suspended and resumed without converting the wait into cancellation.
  This is cooperative host-thread parking, not a guest scheduler or
  asynchronous preemption: code that never reaches a safe point cannot be
  paused until it reaches one.

## Destruction handshake (use-after-free fix)

ASan found a real bug: a detached thread's trampoline wrote `state_`
AFTER the object manager freed the `RtThread` (heap-use-after-free in
`ThreadState::store`). The fix (tested, sanitizer-clean):
- `trampoline_done_` is the trampoline's **last** touch of the object;
- `on_destroy()` drains it: never-started → nothing; exited → done
  already; still running → cooperative stop + bounded wait (250 ms);
  deadline miss is recorded in object metadata (never silently dropped)
  and the host thread is detached as the documented escape hatch.

Naming: `set_name` forwards to the PAL (`pthread_setname_np`; Linux
truncates to 15 chars + NUL — a host fact). Naming an exited thread
returns the host's `ESRCH` as a typed `PlatformError`; naming before
start returns `InvalidState` (both tested).

## Thread-local storage

Per-thread slot map (uint64 key → bytes) from M3, unchanged and
re-covered by tests: key 0 reserved, bounds-checked, `NotFound` for
missing keys, double-set overwrites.

## Known limitations

- No scheduler: priorities are stored abstractions (documented M3
  exclusion; Xbox scheduling internals are proprietary and not modeled).
- Bounded drain (250 ms) on destroy: a thread stuck in a host-internal
  uninterruptible wait (not a cancellation-aware wait) delays destruction
  until the deadline; the miss is recorded, the thread detached.
- Cancellation-aware waits poll at 2 ms granularity (documented
  simplicity trade; no lost wakeups by construction).

## Confirmed vs inferred

Confirmed (host facts, cited):
- `pthread_join` returns when the target's start function returns —
  https://man7.org/linux/man-pages/man3/pthread_join.3.html
- `pthread_setname_np` 16-byte limit incl. NUL; ESRCH for exited threads —
  https://man7.org/linux/man-pages/man3/pthread_setname_np.3.html

Inferred (xbox2pc design): join-self/multi-join semantics table,
`kExceptionExitCode` sentinel, trampoline-done handshake, waker
registration API. Nothing claims Xbox thread scheduling behavior.
