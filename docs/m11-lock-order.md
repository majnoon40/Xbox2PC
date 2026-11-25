# M11.7 — Runtime lock-order table

This is the maintained contract for every mutex the runtime core may hold
while calling into another component. The M11 baseline audit observed a set
of nested acquisition orders; Phase 7 turns that observation into this
table, enforced by the adversarial lock-order regression suite in
`tests/m11_lock_order_test.cpp` (each test runs the interaction on real
threads with a deadline — a deadlock fails the test instead of hanging CI).

## Levels (acquire strictly top to bottom)

| # | Lock | Owner | Kind | Purpose |
|---|-----|-------|------|---------|
| 1 | `ProcessManager::lock_` | `process_management.hpp` | mutex | process map, PID index, exit-observer registry |
| 2 | `GameRuntimeService::sync_transaction_lock_` | `gdk_services.hpp` | mutex | serializes guest wait probes vs signal/release/close |
| 3 | service state locks — `GameRuntimeService::state_lock_`, `TaskQueueService::lock_` | `gdk_services.hpp` | mutex | per-service maps (procs, sync objects, queues) |
| 4 | `ManagedProcess::detail_lock_` | `process_management.hpp` | mutex | per-process thread lists, stats fields |
| 5 | object locks — `RtEvent/RtGuestMutex/RtGuestSemaphore::lock_`, `RtThread::mutex_`, heap/xmem allocator `lock_` | sync/thread headers | mutex | single guest object state |
| 6 | `HandleTable::lock_` / `ObjectManager::lock_` | `handle_manager.hpp` | shared_mutex | slot tables, object registry |
| 7 | `AddressSpace::lock_` | `memory_management.hpp` | mutex | guest region metadata |
| 8 | leaf locks: `ServiceRegistry::lock_`, `TebPebTls` `tls_index_lock_`, `ExecutionContext::lock_`, PAL | various | mutex | never call out while held |

## Codified nesting orders (observed at the M11 baseline, preserved)

These are the ONLY nestings that are allowed to occur. Each row is
enforced or exercised by a named regression test.

1. **Manager → handle-table → object pin.** `ProcessManager` map
   operations (`find_process`, `resolve_pid`, `process_stats`) hold
   `lock_` while resolving the object through the manager's table.
   *Test: `ManagerLookupDuringTerminationCompletes`.*
2. **Manager → service state → (released) → object destruction.**
   Process-exit notification runs observers with `lock_` RELEASED
   (snapshot-and-pin first); service cleanup may then take state locks,
   and object destruction happens after service map locks are released.
   *Test: `ExitObserversRunUnlockedAndRemovalDrainsActiveCalls`
   (pre-existing) + `ManagerLookupDuringTerminationCompletes`.*
3. **Sync transaction → process lookup → handle-table close → service
   state.** Guest sync close nests `sync_transaction_lock_` →
   `find_process_by_pid` (manager) → `HandleTable::close` →
   `state_lock_`. *Test: `SyncCloseConcurrentWithWaitAndStats`.*
4. **Sync transaction → individual sync-object lock.** Wait probes and
   signal/release operations serialize on the transaction lock before
   touching a single object's mutex. *Test:
   `SyncCloseConcurrentWithWaitAndStats`.*
5. **Task-queue dispatch** waits on its condition variable with the queue
   lock released by the wait, and releases the queue lock before invoking
   the guest callback. *Pre-existing Phase 7 coverage: bounded 2 ms
   dispatch cancellation test.*

## Rules for new code

- A component at level N may call components at level > N; the reverse
  direction is a lock-order inversion and must be redesigned (usually by
  snapshot-then-release, as the exit observers do).
- Never call an embedder callback, an observer, or guest code while
  holding a level 1–3 lock. The exit-observer path is the model: pin a
  snapshot under the lock, release, then invoke.
- Every new nesting must be added to this table and covered by a
  deadline-guarded test in `tests/m11_lock_order_test.cpp`; a test that
  times out IS the failure signal, so it must not use unbounded waits.
- `HandleTable`/`ObjectManager` use `shared_mutex`: readers may run
  concurrently; a writer at level 6 must not call upward while holding
  the exclusive lock.

## Boundary

This table covers the runtime core (`xbox2pc_core`, `xbox2pc_rt_gdk`).
Interpreter/decoder components are lock-free by design. The table is a
code-review contract, not a runtime-checked invariant: there is no
deadlock detector hook in this runtime, so the deadline-guarded test
suite is the enforcement mechanism.
