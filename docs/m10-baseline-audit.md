# M10 baseline audit — existing Game OS foundation

## Audited baseline

This inventory was prepared against the M9 branch tip used as the parent of
M10. It is a source inventory, not a claim that every existing implementation
is complete or conformant.

| Existing component | Current role | M10 treatment |
|---|---|---|
| `RtService` / `ServiceRegistry` | Service registration, dependency ordering, init/shutdown | Reuse; add Game OS service grouping only if needed |
| `ApiDescriptor` / `ApiRegistry` | Evidence-backed API metadata and implementation registration | Reuse; expand descriptors with verified evidence |
| `ApiDispatcher` / `ApiResolver` | Controlled dispatch and PE import resolution | Reuse; strengthen argument/context validation |
| `GameRuntimeService` | Runtime init/uninit, XSystem defaults, XThread time-sensitive state | Audit existing stubs and state ownership |
| `TaskQueueService` | Queue handles and manual-mode dispatch model | Expand only after callback lifetime/execution semantics are defined |
| `TimingService` | QPC/QPF using PAL clock | Reuse and test guest-visible units/monotonicity |
| M4 process/thread manager | Process/thread state and cleanup | Reuse as authoritative owner |
| M4 memory manager | Guest process address spaces and protections | Reuse; no second memory manager |
| M4 sync objects | Events, mutexes, semaphores, waits | Reuse; extend semantics rather than duplicating primitives |
| M8 guest memory/ABI bridge | Guest pointer validation and argument marshalling | Route guest-facing buffers through this boundary |
| Compatibility report | API-level status reporting | Extend with service-level evidence and limitations |

## Initial gaps to investigate

These are audit targets, not confirmed defects:

1. **API evidence and versioning:** verify every descriptor's source, version,
   parameter count, return kind, calling convention, and documented behavior.
2. **Thread identity:** verify API context carries distinct process and
   calling-thread identities; do not overload process IDs to represent thread
   IDs.
3. **Guest pointers:** confirm output buffers are validated and written by the
   bridge, not treated as host pointers by service implementations.
4. **Task queue callbacks:** current manual queue model must not claim callback
   execution while no safe guest callback lifecycle exists.
5. **Per-process state:** verify state is removed on process termination and
   service shutdown.
6. **Service lifecycle:** verify dependencies, partial initialization
   rollback, repeated shutdown, and failure propagation.
7. **System calls:** only add interfaces with authoritative ABI evidence;
   kernel syscall numbers and internal layouts remain out of scope absent
   reliable public documentation.
8. **Compatibility reporting:** distinguish metadata recognition, stubbed
   behavior, partial behavior, and fully implemented behavior.

## First implementation priorities

- Create an evidence/gap matrix from the current descriptor table.
- Fix any proven process/thread context ambiguity before adding more APIs.
- Define a typed Game OS environment/configuration boundary that composes
  existing registries and managers rather than owning duplicates.
- Add process-termination hooks for per-process GDK state if missing.
- Select a small set of documented system/process/memory APIs for a complete
  vertical slice, including invalid inputs and cleanup tests.

## Audit rule

No API is marked supported merely because it has a descriptor or resolves an
import. A supported status requires implementation evidence and tests for the
documented behavior. Stubs remain explicitly stubbed/partial.


## M10.2 implementation slice — process-exit state cleanup

- `GameRuntimeService` subscribes to M4 `ProcessManager` process-exit notifications.
- M4 emits notifications only after thread drain, handle closure, address-space
  release, thread detachment, and the transition to `Terminated` succeed.
- Failed/deferred termination does not notify observers, so GDK state is not
  discarded while a process may still be running.
- The GDK service unregisters its observer during shutdown and removes its
  process initialization and thread time-sensitive state on successful exit.
- Tests cover automatic cleanup, replacing the prior manual-only follow-up.


### Observer concurrency contract

Process-exit callbacks execute while the manager lock is held. Unregistration
therefore waits for any active callback before returning, preventing a service
from being destroyed while its callback is in flight. Callbacks must be short,
non-throwing, and must not re-enter `ProcessManager`.


## M10.3 implementation slice — task-queue ownership and teardown

- Task-queue handles are now scoped to the creating process identity; dispatch,
  termination, and close reject a handle presented by another process.
- Only manual/manual queues are accepted. Immediate and thread-pool modes are
  explicitly rejected rather than represented by a queue that cannot schedule
  callbacks.
- Dispatch validates the Work/Completion port enum. It still reports an empty
  queue because guest callback submission/execution is not implemented.
- Process-exit observation removes all queues owned by a successfully
  terminated process. Service shutdown unregisters the observer and clears
  remaining queues.
- Partial service initialization revokes any API registrations already made.
- Tests cover cross-process handle misuse, invalid ports, close behavior, and
  automatic queue cleanup after process termination.

This is not full XTaskQueue compatibility: callback submission, callback
execution, duplicate handles, and real wait/dispatch scheduling remain outside
this slice and must stay reported as partial.


## M10.3 implementation slice — process/thread identity queries

Added evidence-backed Win32 identity exports to the existing kernel32 registry and service:

- `GetCurrentProcessId()` returns the calling guest process ID from `ApiContext`, rejecting a missing identity or a value outside the documented DWORD range.
- `GetCurrentThreadId()` returns the calling guest thread ID from `ApiContext`, rejecting a missing identity or a value outside the DWORD range.
- Descriptor signatures, zero-argument contracts, scalar DWORD return types, and Microsoft Learn evidence URLs are recorded in the built-in descriptor table.
- Tests cover normal values, absent identities, and DWORD overflow.

Evidence:
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid

This does not imply that the execution engine automatically supplies a calling-thread ID in every execution path. The API is only fully usable where the caller provides a valid guest identity in `ApiContext`.


## M10.4 — VirtualQuery memory-query slice

Added the documented Win32 VirtualQuery descriptor and x64 marshalling plan. ProcessManager supports a pinned lookup by stable PID, and GameRuntimeService queries the authoritative M4 AddressSpace. The implementation emits the 48-byte x64 MEMORY_BASIC_INFORMATION layout for tracked committed/reserved regions. Tests cover a committed RW region, output fields, an untracked address, and a short output buffer.

Partial behavior: free gaps are not enumerated as MEM_FREE; original allocation protection is not retained, so current protection is reported; memory type is reported as MEM_PRIVATE. This is not complete Win32 or Xbox memory-query behavior.

Evidence: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery and https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information


## M10.5 — automatic execution-context identity binding

The M8 `ExecutionContext` now binds its process ID, guest thread ID, and
authoritative M4 address space to an execution backend before invoke and
single-step operations. TLS callback execution uses the same binding path.
The deterministic backend rejects zero identities and binds its guest memory
and fault/API identity together. A test probe verifies that invoke and step
receive the exact context identities and address-space reference.

Other execution backends retain a default no-op hook for source compatibility;
a backend that dispatches guest APIs must override it before it can claim
process/thread-aware API dispatch. This does not itself implement a general
x86-64 emulator or prove automatic OS thread scheduling.
