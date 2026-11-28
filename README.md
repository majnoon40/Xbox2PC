# Xbox2PC

**Xbox2PC is an experimental C++20 project exploring an Xbox-to-PC compatibility runtime.** It combines PE32+ inspection, dependency analysis, runtime and process models, package/filesystem support, executable loading, Xbox API compatibility foundations, and an evolving x86-64 guest execution engine.

> **Development status:** This is an active research and engineering project, not a usable Xbox emulator. The repository contains substantial infrastructure and automated tests, but it does **not** currently provide general Xbox game compatibility. No claim is made that commercial Xbox titles run, and real-game compatibility has not been demonstrated.

## What it does

The project is organized into milestone-based components:

| Area | Current scope |
|---|---|
| PE32+ inspection | Parses and reports executable headers, sections, data directories, imports, and exports |
| Dependency analysis | Classifies imported modules and builds dependency reports and graphs |
| Runtime foundation | Models runtime objects, handles, processes, threads, synchronization, and services |
| Memory management | Provides managed address spaces, regions, protections, and resource accounting |
| Filesystem and packages | Provides virtual filesystem backends, package parsing, mounting, and asset discovery |
| Executable loader | Validates and maps supported AMD64 PE32+ images, applies supported relocations, and resolves imports through explicit resolvers |
| API compatibility | Tracks documented API metadata, controlled dispatch implementations, and compatibility reports |
| Execution foundation | Models guest CPU state, the Microsoft x64 ABI, guest memory, execution contexts, exceptions, and a bounded instruction-execution backend |
| x86-64 instruction work | Adds a structured decoder and an expanding interpreter with dedicated semantic test suites |

The implementation is deliberately explicit about unsupported behavior. For example, recognizing an imported API does not mean its behavior is implemented; preparing a loaded image does not by itself mean a game can execute; and passing synthetic tests does not establish compatibility with a retail Xbox title.

For the detailed design and limitations, start with [the architecture overview](docs/architecture.md), [the PE loader notes](docs/pe-loader.md), [the API compatibility notes](docs/api-compat.md), and [the execution architecture](docs/execution-architecture.md).

## M12 status (honest table)

Milestone 12 adds a bring-up rig around the runtime: a policy on what may
be a test input, a ladder of programs built from source and executed in CI,
and telemetry. Every row below is backed by an automated test that runs on
GitHub for the branch. "Blocked" means the program loads, runs, and stops
on a named import the runtime does not implement; it is never reported as
passing. Details and reproduction commands are in [docs/m12-status.md](docs/m12-status.md)
and [docs/m12-what-broke.md](docs/m12-what-broke.md).

| Stage | Status | Evidence |
| --- | --- | --- |
| Input policy and asset-policy hook (checker, pre-commit, CI job) | done | asset-policy job green; a crafted PE offered to `git commit` is refused |
| `xbox2pc run` report | done | JSON on every outcome: outcome, stage, every import's status, the API trace, the first unimplemented import reached |
| `--unimplemented=strict\|trap\|zero` | done | trap faults naming `dll!name`, zero returns 0 and continues; both backends |
| Compiler-built M11 sample through `xbox2pc run` | done | exits 42 on the native backend: all 13 imports resolved and called, `VirtualQuery` returns 48 with its structure on the guest stack (entries 12, 15, 16); asserted by the `m11-pe-fixtures` CI job |
| Deterministic backend following `call [iat]` from code | blocked | import calls from compiler-built code need the native backend (entry 8) |
| Rung ladder B–G and `cxxthrow` | fixtures done; all six blocked | built from source in CI, executed, compared with goldens: B at `kernel32!GetModuleHandleW`, C at `CreateFileW`, D and G at `d3d12!D3D12CreateDevice`, E at `CreateThread`, F on its own stubs until P1 |
| `xbox2pc census` and `xbox2pc report` | done | `census_test`, `telemetry_test` |
| Crash telemetry | done, bounded | `crashes.log`, `XBOX2PC_WATCH`, `XBOX2PC_CRASH_SAVE`, `XBOX2PC_STACKS`; sampled at API call boundaries, no frame walk yet |
| Determinism | done for run reports | 100 consecutive native trap runs give byte-identical reports; rung goldens |
| Sanitizers with the native flag OFF and ON | green on GitHub | ASan+UBSan and TSan, both positions |
| Warning-clean | done | 0 warnings and 32 of 32 tests with gcc 14.2.0 (five configurations) and with clang 18.1.8 locally |
| Graphics, shaders, worker and threads (P1, P3, P4, P5) | not started | no window, no triangle, no GPU run |

## Requirements

- Linux development environment (the current platform backend is Linux-specific)
- C++20 compiler (GCC or Clang)
- CMake 3.20 or newer
- Ninja (recommended, but another CMake generator can be used)
- pthreads / platform thread support

GoogleTest is included in the repository under `third_party/googletest` for the test targets.

## Build

From the repository root:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

To configure without the test or command-line tool targets:

```bash
cmake -S . -B build-no-tests \
  -DXBOX2PC_BUILD_TESTS=OFF \
  -DXBOX2PC_BUILD_TOOLS=OFF
cmake --build build-no-tests --parallel
```

## Run the tests

```bash
ctest --test-dir build --output-on-failure
```

The test suite includes parser, dependency, runtime, memory/process, filesystem/package, loader, API-compatibility, execution, decoder, and interpreter tests. Some benchmark executables are built separately and are not CTest tests. Sanitizer configurations are documented in the relevant component documentation and CI workflow.

## Command-line tool

When the tools option is enabled, the build produces `build/tools/xbox2pc`.

Examples:

```bash
# Inspect a PE file
build/tools/xbox2pc inspect path/to/program.exe

# Analyze imported dependencies
build/tools/xbox2pc dependencies path/to/program.exe

# Export a dependency graph/report as JSON
build/tools/xbox2pc graph path/to/program.exe --json dependency-graph.json

# Validate a supported PE image
build/tools/xbox2pc validate-pe path/to/program.exe

# Produce an API compatibility report
build/tools/xbox2pc compat-report path/to/program.exe

# Run a PE32+ image and write a report on every outcome (see docs/m12-status.md)
build/tools/xbox2pc run path/to/program.exe --backend native --unimplemented trap --json run.json

# Import coverage of a directory of PEs, ranked by first reach from run reports
build/tools/xbox2pc census path/to/dir --missing --trace run.json --triage 10

# Aggregate crash records written under XBOX2PC_CRASH_SAVE
build/tools/xbox2pc report crashes/crashes.log

# Show the tool version
build/tools/xbox2pc --version
```

Run `build/tools/xbox2pc` without arguments to print the command usage. The PE inspection and analysis commands are diagnostic tools; they do not make an arbitrary executable runnable.

## Project documentation

The `docs/` directory contains component-level design notes, including:

- [Architecture](docs/architecture.md)
- [Execution architecture](docs/execution-architecture.md)
- [PE loader](docs/pe-loader.md)
- [Xbox API compatibility](docs/api-compat.md)
- [Virtual filesystem](docs/virtual-filesystem.md)
- [Package formats](docs/package-formats.md)
- [Asset discovery](docs/asset-discovery.md)
- [Guest CPU state](docs/guest-cpu-state.md)
- [Xbox x64 ABI](docs/xbox-x64-abi.md)

These documents describe implementation boundaries and known limitations; consult them before assuming a feature is complete.

## Compatibility and testing disclaimer

Xbox2PC is not affiliated with or endorsed by Microsoft. Xbox, Xbox Game OS, and related names are used only to describe the technical compatibility target.

Use only software and executable files that you are legally permitted to access and test. The project does not provide Xbox firmware, game files, encryption keys, or proprietary system components.

**Current goal:** build and validate the compatibility layers incrementally, with explicit evidence, reproducible tests, and honest reporting of unsupported instructions and APIs. Passing the repository's tests is a development milestone—not proof that a commercial Xbox game will work.
