# M4 — Memory Management

## Responsibility

`memory_management.hpp/.cpp` (library `xbox2pc_rt_memory`) implement the
virtual-memory abstraction: address spaces, region descriptors, the
protection model, region lifecycle, aligned allocation with tracking and
limits. Host specifics (`mmap`/`mprotect`) stay inside the PAL
(`pal_linux.cpp`); this layer speaks only PAL interfaces.

## Model: Xbox virtual addresses

Each `AddressSpace` owns ONE host PAL region (`reserve_memory`, PROT_NONE)
as its backing and gives it a **virtual coordinate system** starting at
an `xbox_base` (default per-process `0x10000000 * (pid%256 + 1)` — an
xbox2pc design choice, **not** a claim about Xbox OS layouts). All public
operations take/return Xbox VAs; `translate()` is the explicitly
documented runtime-internal escape hatch (loader/tests only) — no host
pointer is ever part of the public identity.

```
AddressSpace(host_capacity, xbox_base)
  reserve_region(va, size)      -> sorted map of VmRegion (PROT_NONE subrange)
  commit_region(va)             -> subrange RW (mprotect)
  protect_region(va, prot)      -> R / RW / RX / RWX (validated)
  release_region(va) / resize_region(va, new_size)
```

Region descriptors: `xbox_va, size (page-rounded), state
(Reserved/Committed), protection, name, alloc_id`. Overlap detection is
exact (interval arithmetic over the sorted map); auto-placement is a
first-fit scan computed and inserted **under one lock** (see "Races"
below).

## Protection model (W^X discipline)

| Protection | Read | Write | Exec | Default? |
|---|---|---|---|---|
| `NoAccess` | – | – | – | reserved regions |
| `ReadOnly` | yes | – | – | opt-in |
| `ReadWrite` | yes | yes | – | **the commit default** |
| `ReadExecute` | yes | – | yes | opt-in |
| `Full` (RWX) | yes | yes | yes | **never**; requires `allow_wx_pages` |

Rules (all tested):
- commits default to RW — never RWX;
- `protect_region(Full)` is rejected unless the ProcessManager was given
  `ResourceLimits{allow_wx_pages=true}` (`ProcessManager::protect_region`
  enforces it — `WxProtectionDiscipline` test);
- reserved regions cannot be re-protected (commit first);
- `NoAccess` on a committed region is a valid inaccessible committed
  state; `release_region` remains the separate deallocation path;
- `validate_access(va, write, exec)` answers legality from the
  descriptor's protection (`MemoryTest.ReserveCommitProtectRelease`).

## MemoryAllocator

Tracked aligned allocations carved from a committed region's host
translation:
- alignment is validated (power of two ≤ page size) and computed in
  **absolute** terms (the host buffer itself may be unaligned to the
  requested alignment — the skew is folded in; found by a flaky test,
  fixed with residue-correct math);
- every allocation carries metadata (id, ptr, size, aligned size,
  alignment, tag) and usage stats (used/peak/count) with byte limits;
- double-free and stale-id frees are typed `NotFound`; scrub-on-free is
  available;
- placement: **tail fast path** (O(log n)) for the common append case +
  full first-fit gap scan (O(n)) only when fragmented — the naive
  per-alloc span rebuild (O(n²) total) measured at 2.6k ops/s and was
  replaced by a sorted layout map + fast path: **2.2M ops/s** for
  32-byte alloc+free cycles (bench numbers in the PR description).

## Failure handling

- zero size, misaligned VA, out-of-capacity, overlapping range, limit
  exceeded: typed `InvalidArgument` / `AlreadyExists` / `OutOfResources`;
- a space whose backing mapping failed at construction serves typed
  `OutOfResources` on every region op (never a silent nullptr deref);
- PAL mprotect/mmap errno strings ride along in the result context.

## Races fixed during M4 (all TSan-verified)

1. `reserve_region` called the locking `find_overlap` while holding the
   space lock — recursive deadlock; fixed with a lock-free internal scan.
2. `reserve_region_auto` released the lock between scanning and insertion
   — concurrent placements could lose reservations (234/256 under
   stress); fixed by scanning + inserting under one lock.

## Known limitations

- One host mapping per space (PROT_NONE reserve up front); committing is
  an mprotect — no real "decommit to zero pages" (Linux lacks a portable
   MADV_DONTNEED contract here; documented, revisit with the Windows PAL).
- No file-backed mappings, no NUMA, no hugepages.
- First-fit placement fragments under adversarial free patterns (bounded
  by the gap scan); a free-list is a future refinement.
- Xbox page tables / partition semantics are explicitly NOT modeled
  (milestone exclusion).

## Confirmed vs inferred

Confirmed (host facts, cited):
- `mmap`/`mprotect` semantics, PROT_NONE reservation —
  https://man7.org/linux/man-pages/man2/mprotect.2.html
- `mprotect` applies at page granularity — same page

Inferred (xbox2pc design decisions — no Xbox documentation consulted):
- the per-space Xbox-VA coordinate system and base choice,
- Reserved/Committed two-state region model,
- W^X-by-default discipline and the `allow_wx_pages` opt-in,
- allocator id/metadata/tracking model.


## Guest decommit model

AddressSpace now supports decommitting one complete tracked region: it protects the host subrange as inaccessible and transitions the descriptor from Committed back to Reserved. This is the runtime's current MEM_DECOMMIT model; partial-page-range decommit and physical-page discard/recommit fidelity are not claimed.


## M10 VirtualAlloc W^X enforcement

The Win32 VirtualAlloc adapter applies the runtime's W^X policy before
mutating address-space state. PAGE_EXECUTE_READWRITE is rejected for
MEM_RESERVE, MEM_COMMIT, and MEM_RESERVE | MEM_COMMIT unless the runtime's
explicit allow_wx_pages policy is enabled. In particular, the combined
reserve-and-commit form must not bypass the same protection gate used by the
separate reserve/commit paths. Regression coverage verifies that a rejected
commit leaves the existing reservation intact and uncommitted.
