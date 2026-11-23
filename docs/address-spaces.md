# M4 — Address Spaces

## Responsibility

Per-process virtual-memory isolation: every `ManagedProcess` (see
[process-management.md](process-management.md)) owns exactly one
`AddressSpace` (`memory_management.hpp`); lookups never cross spaces.

## Isolation model

- An `AddressSpace` = one host PAL region + a private sorted map of region
  descriptors in its own Xbox-VA coordinate system (base chosen per
  process, `0x10000000 * (pid%256 + 1)`).
- **Every lookup path goes through a space**: `find_region`,
  `find_containing`, `translate`, `validate_access` are member functions
  with no cross-space back doors. A VA that exists in process A fails
  typed (`NotFound`) in process B — even with identical VA numbers
  (`ProcessMgmtTest.MultipleProcessesIsolation`).
- `space_id()` gives a stable per-space identity for diagnostics.
- `ProcessManager::reserve/commit/protect/release_region` route through
  the OWNING process's space (resolved from the process handle) — a
  handle to process B can never operate on process A's memory through
  these APIs.

What this is NOT: Xbox page-table or partition emulation (explicit M4
exclusion). The isolation is bookkeeping-level: host pages behind
different spaces are distinct mmaps, and the runtime validates every
access against the right space before translation.

## Lifecycle

| Event | Behavior |
|---|---|
| creation | with the process (`ProcessManager::create_process`): backing reserved (PROT_NONE), VA base assigned |
| region churn | reserve / commit / protect / resize / release (see [memory-management.md](memory-management.md)) |
| process termination | `terminate_process` step (d): `space_->release_all()` — every region gone, whole backing back to PROT_NONE |
| manager teardown | every remaining process terminated (exact ordering), spaces die with their objects |

Failure rollback: a process whose initialization fails has its space
`release_all()`-ed and descriptors dropped (documented rollback contract
in `ProcessManager::initialize_process`).

## Statistics

`AddressSpace::stats()` (reserved/committed bytes, region count,
capacity) roll into per-process `ResourceStats` and the manager's global
snapshot (see [resource-accounting.md](resource-accounting.md)). Per-space
`MemoryLimits` (max reserved/committed/regions) are enforced at the space;
global caps at the manager.

## Known limitations

- One backing mapping per space: regions are mprotect subranges — host
  VA reuse across spaces is not modeled (no cross-space aliasing exists
  by construction, which is also the point).
- No shared-memory regions between processes (future milestone: the
  loader's shared section model).
- Per-space VA base scheme caps at 256 distinct bases modulo pid — a
  diagnostic simplification, not a limit on correctness (spaces remain
  isolated regardless of base collision; only the VA numbering overlaps).

## Confirmed vs inferred

Confirmed (host): Linux `mmap` gives independent address ranges per
mapping — https://man7.org/linux/man-pages/man2/mmap.2.html

Inferred (design): per-process spaces keyed to one host mapping each;
the VA-base numbering scheme; release-on-termination ordering. Nothing
here claims Xbox OS memory layout facts.
