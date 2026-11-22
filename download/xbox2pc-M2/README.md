# Xbox2PC M2 — Dependency Intelligence Engine

**Status: Complete.** All 77 tests pass (32 M1 + 45 M2). Clean build from
scratch verified.

## What was built

Five new components on top of M1's PE parser, plus CLI commands:

| Component | Library | Purpose |
|---|---|---|
| Dependency analyzer | `xbox2pc_dep_analyzer` | Enumerates DLL/function imports (regular + delay-load), detects duplicates, unresolved imports, forwarded exports; classifies each dependency |
| API classification | `xbox2pc_api_registry` | Evidence-based classification DB. Categories: Windows Win32, Windows Runtime, Direct3D, Xbox GDK, Xbox Game OS, Xbox-specific graphics, Unknown |
| Compatibility DB | `xbox2pc_compat_db` | Per-API status: Compatible / Partially compatible / Unsupported / Unknown / Not applicable, with signature, Windows equivalent, evidence URL, implementation status |
| Dependency graph | `xbox2pc_dep_graph` | Directed graph: DLL nodes, function-level edge records, cycle detection, missing-dependency detection, JSON export |
| JSON writer | `xbox2pc_json` | Strict serializer: escaping, canonical pretty/compact forms, rejects NaN/Inf |

### Parser extension (M1-compatible)

`pe_parser` gained delay-import parsing (ImgDelayDescr, data directory 13)
and per-descriptor import metadata (INT/IAT/name RVAs, timestamp → bound
detection, forwarder chain). The M1 public API is unchanged — all 32 M1
tests pass unmodified.

### CLI

```
xbox2pc dependencies <file>              # text report
xbox2pc dependencies <file> --json out    # JSON report
xbox2pc graph <file>                      # graph text (nodes/edges/cycles/missing)
xbox2pc graph <file> --json out           # graph JSON
xbox2pc classify <file>                   # per-DLL classification + compatibility
xbox2pc inspect <file>                    # M1 report (unchanged)
```

## Classification evidence

Every record cites a source URL opened during development. The core
Xbox-vs-PC distinctions:

| DLL | Category | Evidence |
|---|---|---|
| `d3d12_x.dll` | Xbox-specific graphics | Microsoft GDK Submission Validator docs — "dependency on the Xbox One graphics stack (d3d12_x.dll)" |
| `d3d12_xs.dll` | Xbox-specific graphics | Same docs — "Scarlett graphics stack (d3d12_xs.dll)" |
| `kernelx.dll` | Xbox Game OS | xvalkyrie project — "d3d12_x.dll and kernelx.dll mean Xbox One" |
| `xgameruntime.dll` | Xbox GDK | MS GDK custom-engine docs — GRTS DLL installed by Gaming Services |
| `combase.dll` | Windows Runtime | MS RoGetActivationFactory page — `req.dll: Combase.dll` |
| `d3d11/d3d12/dxgi.dll` | Direct3D (PC) | GDK docs treat stock Direct3D as the PC path |
| `api-ms-win-*` / `ext-ms-win-*` | Windows Win32 | MS API sets doc — loader contracts |

Sources:
- https://learn.microsoft.com/en-us/gaming/gdk/docs/features/common/packaging/subval/submissionvalidator-messages
- https://learn.microsoft.com/en-us/gaming/gdk/docs/gdk-dev/pc-dev/tutorials/get-started-with-custom-engine/gc-get-started-with-custom-engine-pc
- https://github.com/sammwyy/xvalkyrie
- https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-rogetactivationfactory
- https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
- https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

**Discipline:** classification never comes from a similar function name —
only from a documented (library, API) pair or documented DLL identity.
Unknown DLLs are reported as Unknown explicitly (e.g. `XboxOneNativeApi.dll`
in the demo binary).

## Compatibility status (library-level)

- **Compatible:** stock Win32 (kernel32, user32, ...), combase.dll, stock
  Direct3D (d3d11/d3d12/dxgi), API-set contracts.
- **Partially compatible:** GDK runtime (xgameruntime.dll via Gaming
  Services, XSAPI Thunks, XCurl, libHttpClient.GDK — require Gaming
  Services/packaging on PC).
- **Unsupported on PC:** d3d12_x.dll, d3d12_xs.dll (console graphics
  stacks — the APIs Xbox2PC must substitute), kernelx.dll (console OS
  kernel).
- **Unknown:** everything without evidence (explicit).

## Tests (45 new, all passing)

- Delay imports: RVA & VA addressing modes, truncation, unmappable
  directory, runaway descriptors.
- Import metadata: INT/IAT/name RVAs, bound-import detection.
- Analyzer: multi-DLL enumeration, ordinal + by-name imports, duplicate
  detection (case-insensitive), regular+delay merge, forwarded exports,
  unresolved counting, malformed-table survival.
- Classification: all 7 categories, case-insensitivity, name-similarity
  rejection (d3d12_xx.dll → Unknown), function-level exact-pair rule,
  evidence validation.
- Compat DB: statuses per platform, no claims without evidence,
  signatures where documented.
- Graph: single-hop from report, function records on edges, cycle
  detection (incl. self-loop), missing dependencies, transitive closure,
  case-insensitive merge, two-level graphs, cross-image circularity.
- JSON: escaping (control chars, quotes, UTF-8 passthrough), structure,
  int precision, compact/pretty forms, round-trip validation.
- All test binaries are generated in-memory by the extended pe_builder —
  nothing downloaded, nothing executed.

## Repository layout (new/changed)

```
include/xbox2pc/  api_registry.hpp  compat_db.hpp  dep_analyzer.hpp
                  dep_graph.hpp     json_writer.hpp  (pe_parser.hpp: extended)
src/              api_registry.cpp  compat_db.cpp  dep_analyzer.cpp
                  dep_graph.cpp     json_writer.cpp  (pe_tables.cpp: delay imports)
tests/            deps_test.cpp    (45 tests)
samples/          gen_m2_samples.cpp  demo_xbox_m2.exe
tools/            xbox2pc_cli.cpp   (4 subcommands)
```

## Explicitly not implemented (honest scope statement)

- Recursive multi-file analysis: `xbox2pc graph` analyzes one file; its
  imports are reported as missing dependencies (the DLL files are not
  provided). The `build_multi` graph API supports multi-image graphs and
  is fully tested, but no CLI flag walks directories yet.
- API-set schema resolution: api-* contracts are classified Win32, but
  the mapping to concrete host DLLs per Windows version is not modeled.
- Compatibility statuses beyond the curated rows stay Unknown; no
  function-level coverage beyond documented anchors (CreateFileW,
  RoGetActivationFactory, XGameRuntimeInitialize).
- No implementation work on actual substitution/shims — M2 is analysis
  only; graphics_backend/compatibility_core are future milestones.
