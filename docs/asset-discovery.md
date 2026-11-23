# M5 — Asset & Module Discovery

## Responsibility

`package_vfs.hpp/.cpp` (library `xbox2pc_rt_package_vfs`) contains
`discover_in_namespace`: a bounded walk over a VFS namespace that
classifies every file by CONTENT, feeding PE32+ modules through the
existing M1 parser and reporting unresolved imports without resolving
anything (M5 exclusion).

## Classification rules (content decides; extensions NEVER do)

| Kind | Decision path |
|---|---|
| `Directory` | stat reports a directory |
| `PeModule` | bytes start `MZ` → **M1 `pe::parse`** succeeds (real DOS/PE headers validated by the existing parser — a `.exe`-named PNG is NOT a PE; a `.dat`-named PE IS) |
| `InvalidPe` | bytes start `MZ` but the M1 parse throws `pe::ParseError` (recorded verbatim; never silently dropped) |
| `KnownAsset` | matched against a TINY, CITED binary-signature set (below) |
| `UnknownFile` | anything else — **honestly unclassified** (no guessing) |

The cited signature set (docs commit to citing what we check):

- **PNG**: `89 50 4E 47 0D 0A 1A 0A` at offset 0 —
  https://www.w3.org/TR/PNG/#5PNG-file-signature
- **JPEG**: `FF D8 FF` (SOI + APP0 marker start) at offset 0 —
  ISO/IEC 10918-1 / the JFIF spec layout
  (https://www.w3.org/Graphics/JPEG/jfif3.pdf)

Anything else (`.dds`, `.wav`, `.xex`, …) reports `UnknownFile` — adding
a signature requires a citable, verifiable layout first (the same rule
as package formats). A file named `.png` without the signature is
`UnknownFile`; a file named `.bin` WITH the signature is `KnownAsset`.

## PE module pipeline

For every `MZ`-starting file: the head is read, then the FULL file is
streamed through the VFS handle (bounded by a 512 MiB hard cap) and
handed to M1's `pe::parse`. Success yields a `DiscoveredFile` with
`module_name`, `size_of_image` (from the optional header), and the
import DLL names as **unresolved imports** — M5 reports them and
resolves nothing. M2's dependency analyzer composes on the same parsed
image upstream consumers (tests demonstrate M1→M5 continuity through
`PackageMountTest.ReadOnlyMountAndDiscovery` /
`IntegrationM5Test`).

`DiscoveryResult` aggregates: directories, PE modules, invalid PEs,
known assets, unknown files.

## Bounds & safety

- the walk is `VfsNamespace::walk` with a caller-set `max_entries`
  (typed `OutOfResources` when exceeded — resource safety);
- PE streaming caps at 512 MiB per file (typed behavior above the cap:
  the file is classified from the head only — currently `UnknownFile`
  if no signature matches; a documented limit);
- discovery takes a MUTABLE namespace reference (open() is required for
  reads — const-correctness documented as a known wart).

## What discovery does NOT do

- No filename-extension classification, ever (tested both directions:
  `DiscoveryTest.ExtensionNeverClassifies` proves a `.exe`-named PNG
  classifies as an asset).
- No import resolution, no loading, no execution (M5 exclusions).
- No recursive archive extraction, no hashing/caching of classifications.

## Known limitations

- Every discovery walk re-reads and re-parses files (no cache);
  benchmark: ~717 full walks/s over 32 PE modules + 1 asset on this
  sandbox (see final report).
- Signature set deliberately tiny; growth requires cited layouts.
- The `InvalidPe` path keeps the parse error text only (no offset
  formatting beyond what `pe::ParseError` carries).
