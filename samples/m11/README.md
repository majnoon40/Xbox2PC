# M11 PE test binaries

These are original, synthetic test programs. They contain no retail game code,
Microsoft SDK headers, Microsoft import libraries, or derived retail data.

## `m11_freestanding.exe`

- x64 PE32+ console image with a custom `entry` point.
- Built without a CRT, C runtime startup, or Windows SDK headers.
- Imports only from `kernel32.dll`: `GetCurrentProcessId`,
  `GetCurrentThreadId`, `VirtualAlloc`, `VirtualQuery`, `VirtualProtect`,
  `VirtualFree`, `CreateEventW`, `SetEvent`, `WaitForSingleObject`,
  `CloseHandle`, `SetLastError`, `GetLastError`, and `ExitProcess`.
- Uses a real PE TLS directory and a `__declspec(thread)` variable. The
  compiler-generated access reads the TLS vector through `gs:[0x58]`.
- The calls are made in the order required by the M11 Phase 1 specification.
  A failed check exits with a distinct code (51–61); success calls
  `ExitProcess(42)`.

The build creates a tiny, locally authored `kernel32.dll` solely to produce an
import library with the requested export names. That DLL is a build artifact;
it is not copied beside the sample as a runtime dependency and is not a
Microsoft binary. The PE import table names `kernel32.dll` only.

## `m11_cpp_exceptions.exe`

A small MinGW C++ program with nested non-inlined frames. It throws an integer
in an inner frame, catches it in the middle frame, prints `caught=42`, and
returns zero. The build uses the MinGW x64 CRT and C++ exception runtime so
that the compiler/linker produce Windows x64 unwind metadata in `.pdata`.

## Rebuild

From the repository root on Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y clang lld mingw-w64
scripts/build-m11-samples.sh
```

The script uses Clang's `x86_64-pc-windows-msvc` COFF target plus `lld-link`
for the CRT-free sample, and `x86_64-w64-mingw32-g++` for the C++ exception
sample. It fixes PE timestamps to zero and records compiler versions and
SHA-256 hashes in `build/m11-samples/SHA256SUMS.txt`.

To capture the static-analysis golden files after building the main CLI:

```bash
scripts/capture-m11-goldens.sh
```

The golden files cover `inspect`, `validate-pe`, and `compat-report` for both
samples. These are static-analysis outputs only; they do not claim that either
sample currently executes under Xbox2PC.

A local environment without MinGW may set `M11_SKIP_CPP=1` to build and inspect
only the freestanding sample while working on the toolchain setup. CI must
build both samples; skipping the C++ fixture is not a passing Phase 1 result.
