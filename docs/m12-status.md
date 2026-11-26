# M12 — status

Branch `feature/m12`, based on `main` at `1ce36e0`. Written at the end of
the first P0 working session (2026-11-26).

Rules for this page: nothing is "done" without an automated test that
passes; nothing is "verified in CI" until the branch has run on GitHub;
stubs and partials are labeled as such.

## Where this branch stopped

**P0 is in progress and is not complete.** The session stopped because its
step budget ran out, not at a planned stop point. The branch is green in
every configuration that was built locally. The plan's week-3 checkpoint
(rungs B to G merged, plus the `census` and `report` commands) is **not**
met on this branch.

Nothing has been pushed and no pull request exists: the `GITHUB_TOKEN`
environment variable was not available in the working environment.

## Status per pillar

| Pillar | State | Evidence |
| --- | --- | --- |
| P0.1 input policy, asset-policy checker, pre-commit hook | done, verified locally | `scripts/check_assets_test.py` (42 tests); a crafted PE offered to `git commit` is rejected |
| P0.1 committed binaries removed from the tip | done | `3aae2c7`; history not rewritten |
| P0.1 asset policy enforced in CI | written, not run on GitHub | `asset-policy` job in `.github/workflows/ci.yml` |
| P0.1 third-party register and ADR-0008 | done | `docs/third-party.md`, `docs/adr-0008-license-and-third-party.md` |
| CI sanitizers with the native flag OFF and ON | written, verified locally | five configurations below |
| Warning-clean | done for gcc; clang unchecked | 0 warnings, gcc 14.2.0 |
| P0.2 rung fixtures B to G and `cxxthrow` | **not started** | |
| P0.3 `xbox2pc census` | **not started** | |
| P0.4 `xbox2pc run` JSON on every outcome, `--unimplemented` | **not started** | see `docs/m12-what-broke.md` entry 3 |
| P0.4 crash telemetry (`crashes.log`, `XBOX2PC_WATCH`, `XBOX2PC_CRASH_SAVE`, `XBOX2PC_STACKS`) | **not started** | |
| P0.4 `xbox2pc report` | **not started** | |
| README honesty table updated for M12 | **not started** | |
| P1 worker, per-thread ring slots, shim tier, async waits, MSVC exceptions, multi-module loader, seccomp | **not started** | |
| ADR-0002 to ADR-0007 | **not started** | only ADR-0008 exists |
| P2 descriptor factory, API waves 1 to 5 | **not started** | |
| P3 `Vkd3dForwardingProvider`, `VulkanGraphicsProvider`, `CaptureGraphicsProvider` | **not started** | no window, no triangle; nothing was run on a GPU |
| P4 DXBC/DXIL translation; RDNA2 ISA to SPIR-V | **not started** | |
| P5 x86-64 decoder/interpreter conformance, proxy-title loop | **not started** | |
| "What broke" report | started | `docs/m12-what-broke.md` |
| M13 proposal | **not started** | |

## Verified locally

Toolchain: gcc 14.2.0, cmake 3.31.10, Linux x86-64, 2 vCPU. The times are
incremental rebuild times of the final round, not clean builds. The exact
sanitizer flags are the ones in `.github/workflows/ci.yml`.

| Configuration | Native flag | Tests | Warnings | Sanitizer reports |
| --- | --- | --- | --- | --- |
| Release | ON | 29 of 29 | 0 | not applicable |
| ASan + UBSan | OFF | 29 of 29 | 0 | 0 |
| ASan + UBSan | ON | 29 of 29 | 0 | 0 |
| TSan | OFF | 29 of 29 | 0 | 0 |
| TSan | ON | 29 of 29 | 0 | 0 |

Also run: the asset-policy checker over the whole tree (clean), its 42
self-tests, and the handshake proof for the task-queue race described in
`docs/m12-what-broke.md`.

To reproduce one configuration:

```
cmake -S . -B build-native -DCMAKE_BUILD_TYPE=Release -DXBOX2PC_NATIVE_EXECUTION=ON
cmake --build build-native -j2
ctest --test-dir build-native --output-on-failure
python3 scripts/check_assets_test.py
python3 scripts/check_assets.py --all
```

## Not verified

- **GitHub CI has not run on this branch.** Every "CI" statement above means
  "the workflow file was edited and the same steps were run locally".
- **clang was not used to build this tree in this session.** The local
  clang 18.1.8 built the M11 freestanding sample; it did not build the
  project.
- **Release with the native flag OFF was not rebuilt in the final round.**
- **No 100-consecutive-run output comparison exists** (`docs/m12-what-broke.md`,
  entry 7).
- **No real-GPU result of any kind.** No graphics provider was written.

## What remains before the P0 stop point, in order

1. P0.4 run path: a JSON report on every outcome including a failed load;
   `--unimplemented=strict|trap|zero`; the first missing import in the
   report; a run world that loads `build/m11-samples/m11_freestanding.exe`
   in both backends.
2. P0.2 rung fixtures B to G and `cxxthrow`: our own freestanding sources,
   built by clang and lld-link in CI, each with an exit-code contract and a
   golden trace; `xbox2pc run` executes them. A rung that stops at a named
   missing import is reported as blocked, never as passing.
3. P0.3 `xbox2pc census <dir> [--json] [--missing]`.
4. P0.4 telemetry and `xbox2pc report`.
5. README honesty table for M12, then the P0 stop-point report.

## Commits on this branch

| Commit | Subject |
| --- | --- |
| `1d941e0` | M12.P0: input policy, asset-policy checker and pre-commit hook |
| `3aae2c7` | M12.P0: remove committed binaries from the tree |
| `72adeb7` | M12.P0: enforce the asset policy in CI |
| `724deee` | M12.P0: third-party register and ADR-0008 |
| `4de257f` | M12.P0: sanitize with the native flag on and off |
| see `git log` | M12.P0: warning-clean and a handshake for the blocked-dispatch tests |
| see `git log` | M12.P0: M12 status and the what-broke log |

Seven commits; the plan asks for under forty per pull request.
