# M12 — status

Branch `feature/m12`, based on `main` at `1ce36e0`. Draft pull request:
<https://github.com/majnoon40/Xbox2PC/pull/18>. Its first seven commits, up
to `569529c`, are pushed. The commits after them are local: the token used
to push was unset as soon as the pull request was open, as instructed, and
is to be revoked.

Rules for this page: nothing is "done" without an automated test that
passes; nothing is "verified in CI" until the branch has run on GitHub and
the result has been read; stubs and partials are labeled as such.

## Where this branch stopped

**P0 is in progress and is not complete.** Two sessions went into it; the
second published the branch and built the P0.4 run path. Neither stopped at
a planned stop point. The plan's week-3 checkpoint (rungs B to G merged,
plus the `census` and `report` commands) is **not** met on this branch.

## Status per pillar

| Pillar | State | Notes |
| --- | --- | --- |
| P0.1 input policy, asset-policy checker, pre-commit hook | done | verified by hand; CI result on GitHub not read |
| P0.1 committed binaries removed | done | tip only; history not rewritten |
| P0.1 asset policy in CI | in progress | job pushed with the first seven commits; result not read |
| P0.1 third-party register, ADR-0008 | done | project license left to the maintainer |
| CI sanitizers, native flag OFF and ON | in progress | matrix pushed; result not read |
| Warning-clean | done for gcc | 0 warnings in five configurations; clang unchecked |
| P0.4 `xbox2pc run` JSON report on every outcome | done, local | `tests/m12_run_test.cpp`; every IAT slot with its status |
| P0.4 `--unimplemented=strict\|trap\|zero` | done, local | native backend end to end; deterministic backend at engine level (entry 8) |
| P0.4 `xbox2pc run` on the M11 sample | in progress | loads (13 of 13), starts, stalls after 4 calls (entry 10) |
| Byte-identical determinism test | partial | 100 native runs of the trap fixture give identical reports; no rung trace goldens yet |
| P0.2 rung fixtures B–G, `cxxthrow` | not started | |
| P0.3 `xbox2pc census` | not started | |
| P0.4 crash telemetry, `xbox2pc report` | not started | |
| README honesty table | not started | |
| P1 worker, ring slots, shim tier, async waits, MSVC exceptions, loader, seccomp | not started | |
| ADR-0002 … ADR-0007 | not started | |
| P2 descriptor factory, waves 1–5 | not started | |
| P3 graphics providers | not started | no window, no triangle, no GPU run |
| P4 shader translation | not started | |
| P5 x86-64 conformance, proxy title | not started | |
| "What broke" report | in progress | `docs/m12-what-broke.md`, ten entries |
| M13 proposal | not started | |

No API and no feature is marked supported by this branch.

## Verified locally

Toolchain: gcc 14.2.0, cmake 3.31.10, Linux x86-64, 2 vCPU. The sanitizer
flags are the ones in `.github/workflows/ci.yml`. Clean builds of the
final tree of the second session.

| Configuration | Native flag | Tests | Warnings | Sanitizer reports |
| --- | --- | --- | --- | --- |
| Release | ON | 30 of 30 | 0 | not applicable |
| ASan + UBSan | OFF | 30 of 30 | 0 | 0 |
| ASan + UBSan | ON | 30 of 30 | 0 | 0 |
| TSan | OFF | 30 of 30 | 0 | 0 |
| TSan | ON | 30 of 30 | 0 | 0 |

To reproduce one configuration:

```
cmake -S . -B build-native -DCMAKE_BUILD_TYPE=Release -DXBOX2PC_NATIVE_EXECUTION=ON
cmake --build build-native -j2
ctest --test-dir build-native --output-on-failure
python3 scripts/check_assets_test.py
python3 scripts/check_assets.py --all
```

## Not verified

- **GitHub CI results were not read.** The first seven commits triggered the
  workflow when the pull request was opened; the unauthenticated API was
  rate-limited from this machine, so the outcome is on the pull request
  page, not here. The later commits have not run on GitHub at all.
- **clang did not build the project.** The clang 18.1.8 toolchain built the
  M11 PE sample only.
- **Release with the native flag OFF was not rebuilt in the second session.**
- **No real-GPU result of any kind.**

## What remains before the P0 stop point, in order

1. Diagnose the stall of entry 10 so `xbox2pc run` returns 42 for the
   compiler-built sample, then tighten the CI step of entry 4.
2. Decide how the deterministic backend follows `call [iat]` (entry 8).
3. P0.2 rung fixtures B–G and `cxxthrow`: our own freestanding sources,
   built by clang and lld-link in CI, each with an exit-code contract and a
   golden trace; a rung that stops at a named missing import is reported as
   blocked, never as passing.
4. P0.3 `xbox2pc census <dir> [--json] [--missing]`.
5. P0.4 telemetry (`crashes.log`, `XBOX2PC_WATCH`, `XBOX2PC_CRASH_SAVE`,
   `XBOX2PC_STACKS`) and `xbox2pc report`.
6. README honesty table for M12, a clang build, then the P0 stop-point
   report.

## Commits on this branch

Pushed (in pull request #18):

| Commit | Subject |
| --- | --- |
| `1d941e0` | M12.P0: input policy, asset-policy checker and pre-commit hook |
| `3aae2c7` | M12.P0: remove committed binaries from the tree |
| `72adeb7` | M12.P0: enforce the asset policy in CI |
| `724deee` | M12.P0: third-party register and ADR-0008 |
| `4de257f` | M12.P0: sanitize with the native flag on and off |
| `9328a73` | M12.P0: warning-clean and a handshake for the blocked-dispatch tests |
| `569529c` | M12.P0: M12 status and the what-broke log |

Local, not pushed (see `git log main..feature/m12` for their hashes):

- M12.P0: `xbox2pc run` reports every outcome, loads the M11 sample,
  `--unimplemented`
- M12.P0: status and what-broke after the run path

Nine commits; the plan asks for under forty per pull request.
