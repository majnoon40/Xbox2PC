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
