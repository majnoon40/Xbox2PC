# M10 synchronization and execution audit

Audit target: `feature/m10-game-os-compatibility` (continuously updated; see the M10 pull request head for the exact audited revision).

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

## Implemented in the current M10 continuation

- Added `RtGuestMutex`, whose ownership key is an explicit guest thread ID, with recursive acquisition, non-owner release rejection, abandonment recovery, timeout, cancellation predicate, and close wake-up.
- Added `RtGuestSemaphore` with validated initial/maximum counts, timed/cancellable acquisition, bounded release, previous-count reporting, and close wake-up.
- Added process-scoped handle-backed `CreateMutexW`, `ReleaseMutex`, `CreateSemaphoreW`, and `ReleaseSemaphore` support. `WaitForSingleObject` now accepts events, mutexes, and semaphores; mutex waits return `WAIT_ABANDONED_0` when ownership was abandoned.
- Guest-thread stop is polled during event, mutex, and semaphore waits when the calling guest thread can be resolved to a managed runtime thread. The same wait safe point now checks the managed thread's shared cooperative suspension gate, so process suspend/resume parks and releases those waits without setting terminal stop. The wait implementation still uses bounded host-thread polling; this is not a guest scheduler, async preemption, or scheduler-owned park queue.
- The Win32 wrappers currently support unnamed mutexes/semaphores with null security attributes and names. `ReleaseSemaphore` supports an optional previous-count output pointer and the descriptor metadata now reflects that behavior. Named objects, security descriptors, and DuplicateHandle-style duplication for Win32 synchronization objects remain unsupported. Task-queue handle duplication is implemented separately; see the task-queue section below.
- `CloseHandle` closes service-created event, guest mutex, and guest semaphore handles. An internal guest wait-any primitive polls 1–64 unique process-owned synchronization handles and returns the selected object index (including abandoned-mutex status). Tests cover manual/auto-reset events, semaphore consumption, timeout, duplicate/oversized handle rejection, and abandoned-mutex results. The Win32 `WaitForMultipleObjects` wait-any and transactional wait-all subsets are exposed through the guest marshalling bridge; scheduler-aware parking remains unimplemented.

## Remaining implementation order

1. Add deterministic tests for cancellation during a blocked wait, wake-on-release, abandonment, and object-close races; run all sanitizer configurations.
2. Connect guest wait parking to the execution engine only after a backend-level park/resume contract exists.
3. Automatic mutex abandonment is now invoked by the managed guest-thread exit trampoline; continue testing this path under sanitizers.
4. Replace bounded host-thread polling with scheduler-owned park/resume queues once every supported execution backend exposes a safe wait integration contract.
5. Continue virtual memory, task queue, I/O, and final compatibility audit work.

## Validation boundary

The M10 tests cover the implemented event, mutex, and semaphore slices, including wait-any selection and transactional wait-all rollback/abandonment. They do not establish scheduler-aware guest blocking or full Xbox kernel equivalence; no unsupported behavior should be marked implemented in the compatibility report.


## M10 virtual-memory API slice

- Added VirtualAlloc, VirtualFree, and VirtualProtect descriptors, implementations, and explicit x64 marshalling plans.
- VirtualAlloc supports automatic and fixed-address placement with MEM_RESERVE and MEM_RESERVE|MEM_COMMIT, plus page-range MEM_COMMIT within one reservation. VirtualFree supports MEM_RELEASE with size zero and page-range MEM_DECOMMIT. VirtualProtect changes protection over page ranges and returns the first page's previous protection.
- Supported page protections are PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, and policy-gated PAGE_EXECUTE_READWRITE. Unsupported constants fail closed.
- Page-range operations split metadata segments while preserving the original allocation base. MEM_RELEASE requires that original base. Fixed-address reservations use 64-KiB allocation-granularity rounding; initial allocation-protection metadata is retained and reported by VirtualQuery.
- Committed PAGE_NOACCESS is represented as committed but inaccessible memory, distinct from releasing a region.
- Reservation quotas count the full reserved virtual-address span even after pages are committed. Region growth must satisfy both the reservation quota and, for committed regions, the committed-byte quota.

- Extended the virtual-memory slice with page-range MEM_COMMIT and MEM_DECOMMIT. Linux decommit marks the host subrange inaccessible and discards anonymous backing with MADV_DONTNEED; this is host behavior, not Xbox physical-memory fidelity.


## AllocationProtect metadata

VmRegion keeps allocation_protection independently from current protection. Win32 VirtualAlloc records the initial requested protection when creating a reservation; later VirtualProtect calls do not overwrite it. VirtualQuery returns this value in the x64 MEMORY_BASIC_INFORMATION.AllocationProtect field. Generic M4 reservations use the runtime's PAGE_READWRITE default. Image/mapped/shared region types remain outside this model.

## Guest-facing wait-multiple subset

- `WaitForMultipleObjects` is registered as partially implemented. The bridge reads a bounded 1–64 element `HANDLE` array from guest memory and passes the decoded handles to the process-scoped wait-any or transactional wait-all service.
- `bWaitAll=FALSE` returns `WAIT_OBJECT_0 + index` or `WAIT_ABANDONED_0 + index` as applicable, and supports finite/infinite timeouts through the existing service.
- `bWaitAll=TRUE` uses a serialized probe/rollback transaction across 1–64 unique process-owned event, guest-mutex, and guest-semaphore handles. A failed/expired attempt restores consumed auto-reset event signals, semaphore counts, and mutex ownership; an abandoned mutex remains abandoned if the overall wait fails. Successful wait-all retains acquired mutex ownership and returns `WAIT_ABANDONED_0` if any acquired mutex was abandoned. This remains host-thread polling, not scheduler-aware parking.


## Task-queue handle lifetime

- `XTaskQueueDuplicateHandle` is registered as partially implemented and exposed through the guest marshalling bridge. It creates a distinct same-process handle ID referencing the same queue object and writes the duplicated 64-bit handle through the documented output pointer.
- Closing one alias removes only that handle. Active dispatch waits retain the underlying queue while any duplicate alias remains; closing the final alias wakes blocked dispatch. Process exit removes every alias owned by that process.
- `live_queues()` counts unique queue objects rather than aliases. Tests cover alias lifetime, process isolation, duplicate API output, closing the original handle while dispatch is blocked, and waking dispatch when the final alias closes.
- `XTaskQueueSubmitCallback` stores bounded guest callback records per work/completion port. `XTaskQueueDispatch` invokes one callback on the calling guest thread through the deterministic backend, passing `(context, canceled)` in RCX/RDX. Queue termination marks pending callbacks canceled; a later manual dispatch delivers them with `canceled=true`. Delayed callbacks, automatic/thread-pool/immediate modes, monitors, waiters, and termination callbacks remain unsupported.


## Managed-thread suspension continuation

- `RtThread` owns a shared `CooperativeExecutionGate`. Its suspend request is resumable and is independent of the terminal cancellation state.
- `ExecutionRequest::control` accepts that same gate, so the deterministic backend checks it at instruction boundaries. The execution owner must explicitly attach `thread.execution_control()` to the request.
- `ProcessManager::suspend_process`/`resume_process` now use the thread suspend/resume operations rather than `request_stop` and a later attempt to clear the stop flag. Thread transitions are rolled back if a process-wide operation cannot be applied consistently.
- A thread must reach an explicit safe point to pause. Native host code or guest paths without a connected execution gate are not asynchronously preempted; a full guest scheduler remains out of scope for this slice.


### Page-range virtual memory expansion

The M10 memory slice now supports page-aligned partial commit, decommit,
and protection within a single tracked reservation. Range boundaries split
metadata segments while preserving the original allocation base; MEM_RELEASE
must use that original base and removes all segments. Linux decommit uses
MADV_DONTNEED after changing the range to PROT_NONE. This is a Linux host
memory-management behavior, not Xbox physical-memory emulation.


MEM_COMMIT is idempotent across a mixed range of already-committed and
reserved pages within one allocation. Existing committed pages retain their
current protection; newly committed pages receive the requested protection.
Global commit accounting charges only the newly committed pages.


## Transactional guest wait-all continuation

- The Win32 `WaitForMultipleObjects` bridge now supports `bWaitAll=TRUE` for 1–64 unique, process-owned event, guest-mutex, and guest-semaphore handles.
- A service transaction mutex serializes guest wait probes with signal, release, and close operations. Wait-all probes every object without blocking while holding this gate; if any object is unavailable, it rolls back acquired resources before releasing the gate and retrying.
- Auto-reset event signals consumed during an unsuccessful attempt are restored; semaphore tokens are returned; acquired mutexes are released. If a mutex was abandoned, rollback re-abandons it so a later successful wait can still report `WAIT_ABANDONED_0`.
- On success, all semaphore/event state changes are committed and guest mutex ownership is retained by the calling guest thread. The result is `WAIT_OBJECT_0` or `WAIT_ABANDONED_0` when one or more mutexes were abandoned.
- Wait-all remains bounded to 64 unique handles and uses 2 ms host-thread polling. It is not a scheduler-owned wait queue and does not establish complete Win32 synchronization fidelity.
