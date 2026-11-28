# ADR-0009: Guest memory on one memfd, shared across fork, identity-mapped in the child

- Status: Accepted
- Date: 2026-11-28
- Context: M12 P1 item 1 (persistent worker prerequisite); what-broke
  entries 12, 15, 16 (the workaround layers this removes) and 13, 8 (the
  limits it re-examines)
- Deciders: xbox2pc runtime work

## Context

Every managed process owns one `AddressSpace`: ONE host PAL region
(reserved `PROT_NONE`, `mprotect` subranges per region state) with a
guest-VA coordinate system layered on top. The native backend forks a child
that inherits the parent's window and executes guest code in it — so the
child's host addresses and the guest VAs differ by a **load bias**, and the
window is `MAP_PRIVATE` (anonymous). Three workaround layers exist only
because of those two facts:

1. **Load-bias pointer translation** (entry 12). A pointer the guest
   computes (a stack local, a callback address) arrives at the parent in
   child-host form; the bridge rebases it by the bias before the guest
   address space can validate it.
2. **TLS chain adapt/restore** (entry 15). `TEB.ThreadLocalStoragePointer`
   and the vector slots are guest VAs; the child dereferences them raw, so
   the parent rewrites the chain into host form for the run and restores it
   after reaping the child.
3. **Out-buffer payload on the wire** (entry 16). The bridge writes out
   bytes into the parent's copy-on-write view; a forked child never sees
   post-fork parent writes through `MAP_PRIVATE`, so every out payload
   (up to a 200-byte wire cap) rides the reply slot and the child applies
   it itself.

A fourth consequence: every page the parent touched before the fork is a
copy-on-write page in the child — the child pays a COW fault plus a page
copy on its first write to each one.

## Decision drivers

1. Guest memory written by the parent after the fork must reach the child
   without a per-call wire copy or a size cap (correctness; the 200-byte
   cap is a latent trap for any future out structure).
2. One pointer form on the wire: the value the guest computed must be the
   value the parent validates — no host-form/guest-form duality.
3. Sanitizer legs stay green with the native flag OFF and ON: the child
   inherits ASan/TSan from the parent, so the child's mapping must coexist
   with the sanitizer shadow layouts.
4. The deterministic backend shares `AddressSpace`; the backing change must
   be invisible to it (decommit-then-recommit must still read zeros).
5. No regression in the fault-containment contract: a wrong VA must fail
   safely, never overwrite a mapping the child needs.

## Measurements

`scripts/memfd_bench.c` (this repo, standalone like `ipc_bench.c`),
gcc 12.3.0 `-O2`, 2 vCPU sandbox, Linux 5.10, 2026-11-28.

**1. VA ceiling — can a forked child map the guest range at all?** A
forked child inherits the parent's mappings, so probing in a process equals
probing in the child (the runtime forks without exec). Plain, ASan and TSan
builds of the probe:

| Range (`MAP_FIXED_NOREPLACE`) | plain | ASan | TSan |
|---|---|---|---|
| guest 64 MiB @ `0x20000000` (the run path today) | OK | OK | OK |
| same, `MAP_SHARED` memfd | OK | OK | OK |
| guest 1.46 GiB, `0x20000000`..`0x7fff7000` | OK | OK | OK |
| guest 1.5 GiB (crosses `0x7fff8000`) | OK | **EEXIST** | OK |
| binding range `0x51000000` (already mapped today) | OK | OK | OK |
| PE default base `0x140000000` (entry 13) | OK | **EEXIST** | OK |

ASan's LowShadow (`0x7fff8000`..) and its shadow gap above 2 GiB are the
binding constraint: from the run-path base `0x20000000` the largest
identity-mappable guest space under all three builds is **0x5FFF7000
(~1.46 GiB)**. TSan and plain builds would allow more; the design targets
the intersection. The default 64 MiB run-path space is comfortably inside.

**2. Fork semantics — the entry 16 root cause, demonstrated.** Parent
writes `0x2222...` post-fork; the child sees `0x1111...` (stale) through
the inherited `MAP_PRIVATE` window, the new value through a `MAP_SHARED`
memfd window, and the new value again through an identity window mapped at
the guest VA with `MAP_FIXED_NOREPLACE`.

**3. Per-call cost of the layers being deleted** (20M iterations):

| Operation | ns/call |
|---|---|
| translate 4 pointer args (rebias + region lookup) | 8.2 |
| out double copy (48 B: reply slot + child apply) | 2.2 |
| direct shared write (48 B, what replaces both) | 0.4 |

Honest reading: ~10 ns/call is noise against a ~7 µs ring round trip
(ADR-0001: ~143K calls/s). The migration is not a throughput play; it
deletes three correctness workaround layers and a wire cap. The numbers
say the deleted work was cheap — the design pays for itself in semantics,
not speed.

**4. One-time and first-touch costs.** fork+exit 119 µs; fork + child
identity map (64 MiB `PROT_NONE` shared + 10 `mprotect`s) 122 µs — the
identity mapping costs ~3 µs per run. The child's first write to a page
the parent touched: `MAP_PRIVATE` 3053 ns/page (COW fault + copy),
`MAP_SHARED` 965 ns/page.

**5. Decommit semantics on the shared backing.** `madvise(MADV_DONTNEED)`
alone does NOT zero a shmem page (the page cache keeps the data); the
decommit path must also `fallocate(FALLOC_FL_PUNCH_HOLE |
FALLOC_FL_KEEP_SIZE)`. With the punch, decommit→recommit reads zeros in
both the parent window and a second window mapped over the same memfd —
the anonymous-mapping contract `AddressSpace` tests rely on.

## Decision

1. The managed address space is backed by **one memfd per process**:
   `memfd_create` + `ftruncate(capacity)` + the parent window is
   `mmap(NULL, capacity, PROT_NONE, MAP_SHARED, fd, 0)`. Region
   reserve/commit/protect/decommit keep their meanings over that window;
   decommit additionally punches the hole so re-commit reads zeros.
2. The native child, after `fork`, **maps the same memfd at the guest
   VAs**: `mmap(xbox_base, capacity, PROT_NONE, MAP_SHARED |
   MAP_FIXED_NOREPLACE, fd, 0)`, then re-applies each committed region's
   protection with `mprotect` (W^X preserved; the parent serializes the
   region list into the child's run state before the fork). Guest VA ==
   child host VA from that point.
3. Deleted with this model, tests kept: the load-bias pointer translation
   in the ring serve loop (entry 12), the TLS-chain adapt/restore (entry
   15), and the reply-slot out-buffer payload with its 200-byte cap
   (entry 16) — the bridge writes out bytes through the shared window and
   the child simply sees them. The dead `child_patch_iats` (load-bias
   rebase) is removed too.
4. `MAP_FIXED_NOREPLACE` — never `MAP_FIXED` — so a collision (a sanitizer
   or a library in the range) fails the run with a typed error instead of
   silently unmapping something.
5. The parent window stays `mmap(NULL, ...)`-placed (kernel picks a high
   address): the parent's own address space never depends on the guest
   geometry, and the two windows of the same memfd coexist in the child
   without cost.

## What this removes and what it does not

**Removed:** the three workaround layers above; the 200-byte out-payload
wire cap; the host-form/guest-form duality of wire pointer arguments; the
COW fault + copy on every parent-touched page the child first writes.

**Not removed (documented limits):**

- **Post-fork protection changes are parent-window-only.** `mprotect` is
  per-mapping: a ring-served `VirtualProtect` flips the parent's window,
  not the child's identity window — exactly the semantics the inherited
  window had before (fork copies protections; parent `mprotect` never
  reached the child then either). No regression; a worker-model item
  (ADR-0002/0003) will own protection servicing in the child.
- **Entry 13 is NOT closed.** A position-independent image without
  relocations still cannot load at the default PE base `0x140000000`: ASan
  occupies everything from 2 GiB to 16 TiB in every build, so no
  sanitizer-green guest space can contain that base. The ceiling is now
  measured instead of vague: ~1.46 GiB from the run-path base. The
  fixture-side fix (every rung links `rung_reloc.c`) remains the answer;
  a reloc-less image linked inside the guest range (e.g. `/BASE:0x20000000`)
  loads fine, which the rung fixtures' relocations already provide.
- **Entry 8 is untouched.** The binding range `0x51000000` sits below the
  space base and is mapped by the parent at a fixed VA (the thunk page) —
  identity changes nothing there. Its decision stays with the P1
  benchmark and ADR-0002/0003.

## Consequences

- The wire (`ReplySlot`) loses its out-payload fields: replies become
  status, exit code, RAX and aux words only. Both sides compile the same
  header, so the slot stride (256 B) is unchanged.
- `PalMemoryRegion` gains a shared mode (`fd()` accessor); only
  `AddressSpace` uses it — the PAL's anonymous regions (file objects and
  others) keep the private factory.
- Sanitizer legs map ~64 MiB of extra shadow (ASan maps 1/8 of the
  identity range); untouched pages cost nothing (shmem allocates lazily).
- `MAP_FIXED_NOREPLACE` at `[0x20000000, 0x24000000)` has been proven under
  all three builds; if a future host maps something there, the run fails
  with the typed internal error naming the range — never silent corruption.

## Measurement provenance

- Command: `gcc -O2 -o memfd_bench scripts/memfd_bench.c && ./memfd_bench`
  (plus `-fsanitize=address` / `-fsanitize=thread` builds run with
  `ceiling`).
- Machine: 2 vCPU sandbox, Linux 5.10.134, 2026-11-28.
- Full outputs are in the commit message of the slice that lands this ADR
  and re-runnable from `scripts/memfd_bench.c` at any time.
