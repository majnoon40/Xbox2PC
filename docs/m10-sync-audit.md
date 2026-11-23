# M10 synchronization and execution audit

Audit target: `feature/m10-game-os-compatibility` at `e9d2b41186ef62a33ff7d4a9`.

This document records implementation constraints found while selecting the next M10 synchronization slice. It is not a claim of Xbox kernel equivalence.

## Existing primitives

- `RtEvent` provides manual/auto-reset signaling and timed waits. The M10 Win32 event API wraps it using the process handle table and ObjectManager.
- `RtMutex` wraps a host `PalMutex`. Its public API exposes blocking lock, unlock, and try-lock; it does not expose timed acquisition, guest-thread ownership metadata, or abandoned-owner state.
- `RtSemaphore` wraps a host counting semaphore with acquire/try-acquire/release.
- `RtCancellableWait` is a polling helper that can be woken by an `RtThread` cancellation request. It is not currently integrated into the Win32 event wait path.
- `WaitSet` polls candidates at 2 ms intervals. Its wait-all operation is explicitly non-transactional for auto-reset events: a consumed event signal cannot be restored if a later candidate times out.

## M10 findings and constraints

### 1. Do not expose Win32 mutexes by simply wrapping RtMutex

Win32 mutex semantics include ownership by the calling thread and recursive acquisition behavior. The current `RtMutex` delegates ownership to the host PAL mutex. That is not a sufficient guest contract unless the runtime guarantees a one-to-one guest-thread/host-thread execution mapping on every backend. M10 has not established that guarantee.

Before adding `CreateMutexW`, `ReleaseMutex`, or allowing mutex handles in `WaitForSingleObject`, add explicit guest-thread ownership and abandonment semantics to the kernel-object layer, and test them independently of the host thread ID.

### 2. Do not expose semaphores without cancellation and lifetime rules

The generic semaphore supports counting and maximum-count validation, but the Win32 layer still needs process-scoped handle registration, release-count validation, wait-result mapping, and a defined policy for waiters during close/process exit. Cancellation must not be simulated by releasing arbitrary extra tokens, because that changes the semaphore's observable count.

### 3. Event waits are still host-blocking

The current `WaitForSingleObject` event implementation blocks the host execution thread. `RtCancellableWait` exists, but it does not by itself make the wait scheduler-aware or connect cancellation to a guest execution context. Keep this limitation explicit until the execution engine has a supported park/resume contract.

### 4. Wait-any/all need a separate correctness pass

The existing `WaitSet` uses polling and has a documented non-transactional wait-all behavior for auto-reset events. Do not map it directly to Win32 `WaitForMultipleObjects` without resolving signal consumption, duplicate objects, ordering, maximum wait count, timeout accounting, and cancellation semantics.

## Recommended implementation order

1. Establish a runtime-owned guest-thread identity/ownership primitive usable by synchronization objects, independent of host thread IDs.
2. Add cancellable timed waits with a single monotonic deadline and explicit wake reasons (signaled, timeout, cancelled, object closed).
3. Add mutex ownership/recursion/abandonment tests and semaphore count/lifetime tests at the generic runtime layer.
4. Add process-scoped kernel-object handles for mutexes and semaphores, with close and process-exit cleanup.
5. Extend the Win32 wait API only after the generic object semantics pass adversarial tests.
6. Connect wait parking to the execution engine only after a backend-level park/resume contract exists.

## Validation boundary

The existing M10 event tests validate the supported event subset. They do not validate mutex/semaphore Win32 behavior, scheduler-aware guest blocking, or full wait-any/all semantics. Those remain M10 work; no unsupported behavior should be marked implemented in the compatibility report.
