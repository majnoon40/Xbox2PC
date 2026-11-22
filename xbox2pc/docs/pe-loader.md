# PE Loader (M6)

**Status: M6 complete.** The loader (`xbox2pc_rt_loader`, header
`include/xbox2pc/image_loader.hpp`) validates PE32+ images, maps them
into M4-managed process address spaces, applies X64 base relocations,
resolves imports through an explicit resolver interface, reports TLS
metadata, and prepares a verified execution description. **It never
executes anything** — loading and execution are separate operations by
design (see "Explicit exclusions").

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ CLI (validate-pe / map-image / relocations / imports /        │
│      load-image / unload-image / image-info)                  │
├──────────────────────────────────────────────────────────────┤
│ ImageLoader (lifecycle)                                       │
│   validate → map → relocate → resolve imports → prepare       │
│   LoadedImageObject (RuntimeObject, process handle table)     │
├──────────────────────────────────────────────────────────────┤
│ Component functions (pure):                                   │
│   validate_image · pe_section_protection · decode_relocations │
│   decode_tls · StaticResolver / NullResolver (IImportResolver)│
├──────────────────────────────────────────────────────────────┤
│ M4 AddressSpace / ProcessManager (mapping target; no second   │
│ memory or process manager exists)                             │
├──────────────────────────────────────────────────────────────┤
│ M1 PE parser (bytes → PeImage) · M5 VFS (image sources)       │
└──────────────────────────────────────────────────────────────┘
```

Layering: `rt_loader` links `rt_procman` / `rt_memory` / the M1 parser;
it introduces **no new manager**. All host interaction goes through the
M4 `AddressSpace` (which sits on the PAL); the loader's only host-pointer
exposure is transient staging via `AddressSpace::translate()` inside a
single function scope.

## The address model

| Quantity | Meaning |
|---|---|
| file offset | position in the on-disk image buffer |
| RVA | offset from the image base (PE spec) |
| preferred base | `OptionalHeader.ImageBase` (e.g. 0x140000000) |
| actual base | where the M4 `AddressSpace` mapped the image |
| Xbox VA | `actual_base + rva` — the loader's public currency |
| host backing | ONE mmap per space; `translate()` resolves VAs |

`map_image` honors the preferred base when it falls inside the process
space bounds and is free; otherwise the image moves if (and only if) it
carries a base-relocation directory, and the new base comes from a
deterministic first-fit gap scan. An image with no relocations whose
preferred base is unavailable fails with a typed `InvalidState` — it is
never silently placed elsewhere.

## PE validation rules (pre-allocation)

`validate_image(img, file, size)` runs BEFORE any memory is touched
(separate from mapping by construction). Rejections (typed issue codes):

- `not-pe` / `bad-signature` — DOS magic / PE signature
- `truncated` — headers beyond the buffer (every prefix is tested)
- `bad-machine` — AMD64 only (documented scope)
- `bad-optional-header` — non-PE32+ magic
- `bad-alignment` — SectionAlignment/FileAlignment power-of-two bounds
- `headers-size`, `image-size-inconsistent`, `image-too-large`
- `entry-outside-image`, `entry-bad-section` (non-executable host)
- `section-outside-image`, `section-raw-range`, `section-overlap`
- `directory-range` — RVA+size beyond SizeOfImage
- `reloc-directory` — block alignment/size rules
- `import-directory` — descriptor-size multiple
- `tls-directory` — 64-byte PE32+ structure

The M1 parser sanitizes raw-section ranges (clears `has_raw_data` with a
warning); the loader therefore validates the VIRTUAL extents
(`max(VirtualSize, SizeOfRawData)` consistency with `SizeOfImage`)
independently — the two layers double-cover each other.

## Mapping

One region per PE section (plus one for headers) because M4 regions are
the protection granularity. Sections are committed RW (staging), filled
(zero whole region, then copy raw data bounded by file and region), and
protected to the final mask; headers end `ReadOnly`. Rollback releases
every reservation in exact reverse order on any failure — verified by a
dedicated mid-map-failure test and the map fuzz harness.

## Section protection mapping (W^X)

| PE characteristics | MemProtect |
|---|---|
| executable (+read) | ReadExecute |
| writable | ReadWrite |
| writable+executable | **ReadWrite (degraded)** |
| no access flags | ReadOnly |

W^X is enforced: a W+X request degrades to RW (write honored, execute
refused) — documented, tested, never silently RWX. `MemProtect::Full`
exists in M4 but is never produced by `pe_section_protection`. No
compatibility exception was needed for the test fixtures.

## Base relocations

`decode_relocations` parses the directory into blocks with full bounds
validation (block size ≥ 8, 4-aligned, inside the directory, entry count
limit). Applied types: **DIR64** (64-bit add/subtract of the delta) and
ABSOLUTE (padding, skipped). Everything else — HIGH, LOW, HIGHLOW
(32-bit), HIGHADJ, ARM64 types — is REJECTED with
`PlatformUnsupported` ("rejected, not skipped"): the loader never
silently drops an unsupported relocation. Fixups flip the target section
to RW, apply, and restore the original protection. The delta sign
convention: relocated = old + (actual − preferred) (verified in mapped
memory by the tests).

## Import resolution

`IImportResolver` is an explicit interface (two calls: module-level gate
`resolve_module`, per-symbol `resolve`) so future GDK/Game OS
implementations plug in without touching the loader. M6 ships exactly
two resolvers, both for tests/CLI:

- `StaticResolver` — resolves ONLY registered (DLL, symbol) pairs to
  **deterministic synthetic values** (an FNV-style hash of
  dll+symbol). Values are never host addresses.
- `NullResolver` — refuses everything (module gate false), producing
  `Unsupported` bindings.

Import states stay distinct: `Resolved` (value written to the IAT slot),
`Unresolved` (known module, missing symbol — or no resolver supplied),
`Unsupported` (module rejected by the resolver), `Invalid` (malformed
thunk/name in the image). The loader writes IAT slots only for Resolved
bindings (RW flip + restore; the builder emits IAT inside `.text`, which
the map step protected RX). An image WITH imports that are not all
resolved FAILS loading with `MissingDependency` after full rollback —
never a faked success. Bound-import (INT==0) fallback reads the IAT
itself as the thunk table.

Rules honored: no invented Xbox APIs, no host-function binding, no
pretend-resolution. `resolve_imports` on a valid image with the Null
resolver is the CLI's `imports` "resolver-required view".

## TLS

`decode_tls` validates the PE32+ TLS directory (64-byte structure,
bounded template size, end ≥ start) and reports: template location/size,
zero-fill size, callback count (bounded walk, **counted, never executed**),
index slot RVA. During a full load, a deterministic TLS index is assigned
(`space_id & 0xFFFF` — a runtime bookkeeping id, NOT an Xbox TLS-slot
reproduction) and `LoadDiagnostics.unsupported` records that per-thread
TLS initialization is deferred: the M4 thread model has per-thread slots
but no image-template copy path. Nothing is faked.

## Loading lifecycle

States: `Created → Validating → Allocating/Mapping → Relocating →
ResolvingImports → Preparing → Prepared` (or `Failed` / `Unloaded`).
Every phase failure rolls back ALL image regions (headers + sections,
reverse order) — no partially loaded image is ever reported Prepared.
`LoadedImageObject` (RuntimeObject) carries the layout + diagnostics +
exec description; a handle in the **process's own table** owns it, so
process termination's `close_all` → destroy ordering covers loaded images
(the regions die with `AddressSpace::release_all`). `unload_image`
releases regions reverse-order, closes the handle, destroys the object —
with the guard released before `destroy` (pin-drain self-deadlock fix,
regression-covered by tests). Repeated load/unload cycles leak nothing.

### Object typing note

`LoadedImageObject` uses the built-in `TypeId::MemoryRegion` (7): the M4
handle encoding carries a 9-bit type field, so user ids ≥ 512 truncate
and break lookups. Loaded images ARE mapped memory regions; `as<T>`
still double-validates the dynamic type. User-type ids above 511 are
unusable for handle-bearing objects (an M4 layout constraint, surfaced
by this milestone).

## Execution preparation

`prepare_exec` validates the entry point: inside a mapped section,
that section executable under the final protection, access check through
the space (`validate_access(entry, write=false, exec=true)`). x86-64
entry points have no architectural alignment requirement beyond
containment. The `ExecDescription` reports everything the future executor
needs (bases, layout, import counters, TLS presence, phase completion
flags). **No execution interface exists in M6** (defined contract only:
the description is complete and validated; starting the entry point is
future work — see exclusions).

## Testing and fuzzing

- `loader_test` — 34 tests across validation / mapping / relocations /
  imports / TLS / integration (the 15-step path: M4 process → M5 VFS
  namespace + XPK mount → discovery → VFS-handle read → validate →
  map → relocate → resolve → prepare → inspect → unload → terminate →
  zero regions; termination cleanup without explicit unload;
  two-process concurrent loads with isolated bases).
- `loader_fuzz_test` — 5 seeded deterministic harnesses (~82k
  mutations): PE headers (valid ⇔ zero issues invariant), relocation
  directories, import thunks (null resolver never writes), TLS
  directories, map-fuzz (region-count balance across 2k mutated-valid
  images).
- Sanitizers: ASan+UBSan and TSan clean over the full suite.
- `loader_bench` (manual): validation 0.000 ms/op; map+unmap 0.018 ms;
  relocations 0.013 ms (64 DIR64); import resolve 0.003 ms (16
  symbols); full load lifecycle 0.047 ms; 8-process load+unload 0.43 ms
  (4 KiB synthetic fixture, this container — Release build).

## Confirmed vs inferred

Confirmed (PE/COFF spec, MS-PELYB / pecoff v11): directory layouts,
relocation block format (page RVA + size + 2-byte entries, ABSOLUTE
padding, 4-byte block alignment), DIR64 semantics, import descriptor /
thunk layout (PE32+ 8-byte thunks, ordinal bit 63), TLS directory
structure, section characteristics bits.

Inferred (xbox2pc design): one-region-per-section mapping, W+X
degradation policy, resolver interface shape, TLS index assignment,
deterministic synthetic import values, gap-scan placement policy.

## Supported / unsupported PE features

Fully implemented: PE32+ AMD64 validation, header/section mapping with
zero-fill, protections (R/RW/RX with W^X), DIR64 + ABSOLUTE relocations,
import-by-name, import-by-ordinal, bound-import INT==0 fallback, IAT
writes, TLS directory validation/reporting, load/unload lifecycle with
rollback, execution preparation.

Partially implemented: TLS (validation + index + reporting; no
per-thread template copy — recorded as unsupported).

Unsupported (rejected explicitly): non-AMD64 machines, 32-bit PE,
HIGH/LOW/HIGHLOW/HIGHADJ relocations, delay-import resolution (M2
analyzes them; the loader does not resolve them), forwarded-export
resolution, per-thread TLS initialization, entry-point execution.

## Known limitations

- One resolver interface, zero Xbox API implementations (roadmap: GDK
  compatibility milestone — moved AHEAD of executable execution in the
  roadmap update below; see architecture.md).
- No delay-load import resolution (reported by M2 analysis; unresolved
  at load time — a load with unresolved delay imports still fails the
  required-import rule).
- TLS callbacks are counted but never invoked; per-thread TLS templates
  are not materialized.
- `prepare_exec` validates but does not execute; no Xbox ABI/CPU
  context exists yet (future milestone).
- The loader resolves one image at a time; no cross-image dependency
  DAG loading (an image importing another image's exports resolves
  through the resolver the CALLER supplies, not by loading the target).

## Roadmap change (explicit)

Executable loading (M6) has been delivered before GDK API compatibility,
adjusting the milestone order originally implied by the layer table.
GDK/Game OS API compatibility remains on the roadmap as its own future
milestone (resolver implementations + per-API behavior), followed by
execution-context work. Nothing was silently dropped: graphics, audio,
and game execution stay explicitly excluded until those milestones.
