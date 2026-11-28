# M12 rung fixtures

The rung ladder is the plan's CI strategy for large-program behaviour
(plan section 3.2): each rung is a small program of ours, an `xbox2pc run`
exit-code contract, and a golden that records what the runtime does with it
today. A rung is **passing** only when the automated run returns its contract
exit code; **blocked** when it stops on an import the runtime does not
implement; anything else is a failure. `scripts/rung_check.py` decides.

Everything here is written for this repository. No CRT, no Windows SDK or
GDK header: `rung_common.h` and the `rung_*.h` headers declare what the
fixtures call. The import libraries come from the stub DLL sources
`stub_*.c`, which `scripts/build-rung-fixtures.sh` links as DLLs only so
lld-link emits the `.lib`; a stub is never loaded by a fixture and is not a
Microsoft file. Nothing is committed as a binary: CI builds the fixtures
from this source (docs/input-policy.md).

| Rung | Program | Exit-code contract | What it exercises |
| --- | --- | --- | --- |
| B | `bootloop.c` | 60 (the frame count) | window, message pump, present loop |
| C | `assetload.c` | FNV-1a of `assets/rung_c.bin` & 0xFF | VFS, streamed read, hash |
| D | `gpucompute.c` | FNV-1a of the compute readback & 0xFF (not expressible before P3/P4) | device creation, compute dispatch, readback |
| E | `threads.c` | 36 (1 + … + 8) | guest threads blocking on an event, rendezvous, schedule checksum |
| F | `cxxthrow.cpp` | 42 | a C++ exception across nested frames, freestanding toolchain |
| G | `titlelike.c` | 36-thread checksum + asset hash bits (D + E + C) | threaded, asset-streaming, device-using synthetic program |

## Build and check

```
scripts/build-rung-fixtures.sh                 # clang + lld-link -> build/rungs
cmake -S . -B build-native -DXBOX2PC_NATIVE_EXECUTION=ON && cmake --build build-native --target xbox2pc
python3 scripts/rung_check.py --cli build-native/tools/xbox2pc --dir build/rungs
```

`--update` rewrites `golden/*.json` from the current run. Never pass it in
CI: a changed report must be looked at, then recorded deliberately.

## Where the rungs stand

`golden/<rung>.json` is the record; its `status` field is `passing` or
`blocked`, and `first_unimplemented` names the import the run stopped on.
The goldens depend on the fixtures' import sets and on the runtime's
registry, not on code generation, so they are the same for the clang that
CI installs and for any clang 18 that builds them.

Known limits of the fixtures themselves:

- The deterministic backend cannot follow a `call [iat]` from code
  (`docs/m12-what-broke.md`, entry 8), so the rungs run on the native
  backend only.
- Rung F's throw helper and frame handler are stubs in
  `cxxthrow_runtime.c` until the real exception path exists (P1, section
  4.5); the fixture exits with 99 and is reported as blocked.
- Rung B's present step and rung D's dispatch are the graphics provider's
  work (P3) and are not written yet; the programs say so where they stop.
