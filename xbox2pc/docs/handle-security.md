# M4 — Handle Security

## Responsibility

M4 hardens the M3 handle manager (`handle_manager.hpp/.cpp`, library
`xbox2pc_rt_handles`) with process-scoped ownership, access rights,
inheritance metadata and cross-table isolation, while preserving the M3
generation-based stale protection.

## Handle encoding (M4 change — documented architectural fix)

```
bits 63..55 : table id  (9 bits — the OWNING table)
bits 54..40 : slot index (15 bits — 32K slots/table)
bits 39..9  : generation (31 bits — stale protection)
bits 8..0   : type id    (9 bits — mirrors TypeId)
```

**The fix:** in M3, handles from different tables with equal
index/generation/type produced the SAME raw value, so a handle handed to
the wrong table could alias a foreign object. M4 embeds the owning table
id; `lookup` checks it first and answers `InvalidHandle` ("handle belongs
to table X, this is table Y") — cross-table aliasing is structurally
impossible (`HandleRightsTest.CrossTableIsolation`). Capacity per table
drops 16M → 32K (typed `HandleTableFull` when hit — far above realistic
per-process use).

Table ids: 0 = the runtime root table; process tables take 1..511
(9-bit space; exhaustion is a documented limit — 511 live process
tables).

No raw memory address appears in any handle (unchanged from M3).

## Access rights

`AccessRights` is a capability mask on each handle slot:
`Read | Write | Execute | Duplicate | Close | Synchronize` (+ bundles
`ReadWrite`, `All`).

- `create` grants `All`; `create_with_rights` can grant narrower views.
- **Rights only ever narrow**: `duplicate(h, reduced, inheritable)`
  validates the requested mask is a SUBSET of the source rights —
  widening attempts fail typed `InvalidArgument` with both masks in the
  context (`RightsMetadataAndReduction`).
- `close(h)` requires the `Close` right — a handle without it cannot
  retire its slot (`CloseRequiresCloseRight`).
- `duplicate(h, ...)` requires `Duplicate` on the source.
- Rights checks happen at operation sites (lookup resolves identity
  only; the caller composes `rights_of(h)` + `has_right()`).

## Inheritance metadata

Every slot carries an `inheritable` flag (queryable; set at creation and
on duplication). M4 stores and reports it (CLI `handle-info` shows it);
spawn-time handle copying into child processes is a future milestone
(see [process-management.md](process-management.md) limitations).

## Enumeration and diagnostics

`list_handles()` yields live slots (raw handle, table id, object id,
type name, rights, inheritable) — the `handle-info` CLI command prints
exactly that, live. `all_handles()` unchanged from M3.

## Closure during process termination

`terminate_process` step (c): the process's table `close_all()` —
regardless of per-handle rights (termination is not a capability
exercise) — every handle of the dying process dies together
(`ProcessMgmtTest.FullLifecycleWithCleanup`).

## Concurrency guarantees

- Lookups: shared lock + pin-under-read-lock (lookup-vs-destroy races
  closed since M3).
- Create/close/duplicate: unique lock on the slot vector.
- Concurrent duplicate + close stress: 8 threads × 50 ops on a shared
  handle — exact live-count accounting (`ConcurrentDuplicateCloseStress`,
  ×5 repetitions, TSan-clean).

## Pin drain (M4 refinement)

The M3 bounded-spin drain (destroy waiting for RefGuard pins) is now a
**condvar drain**: `ObjectManager::destroy` drops its pin and waits on a
dedicated drain mutex+condvar; `RuntimeObject::unpin` wakes the OWNING
manager (context installed at registration) when a destroying object's
last pin drops. The context-carrying callback receives a snapshot taken
**before** the pin decrement — after the decrement the object may be
freed concurrently, so the wake path never touches it (a real TSan-found
use-after-free; see [runtime-object-model.md](runtime-object-model.md) —
M4 appendix). Bounded 50 ms fallback ticks keep the drain robust.

## Known limitations

- 32K slots/table and 511 process tables (encoding space; typed errors on
  exhaustion).
- Rights enforcement is at runtime layer call sites; the PAL does not
  mediate capability checks for host-side operations.
- No ACL-style per-right auditing log (future diagnostics milestone).

## Confirmed vs inferred

Confirmed (cited): Win32 HANDLE/DuplicateHandle semantics (new handles,
capability masks, inheritance flags) —
https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
https://learn.microsoft.com/en-us/windows/win32/sysinfo/handles-and-objects

Inferred (xbox2pc design): the 9/15/31/9 bit split, rights lattice
(subset-only duplication), the drain-context handshake. Xbox handle
internals are proprietary and NOT reproduced.
