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
