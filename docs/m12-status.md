# M12 — status

Branch `feature/m12`, based on `main` at `1ce36e0`. Draft pull request:
<https://github.com/majnoon40/Xbox2PC/pull/18> (every commit of the branch is
pushed; nothing is local-only).

Rules for this page: nothing is "done" without an automated test that
passes; "verified in CI" means the job ran on GitHub for the pushed commit
and the result was read back; stubs and partials are labeled as such.

## Where this branch stands

**P0 is not complete.** Three sessions went into it. The plan's week-3
checkpoint — rungs B to G merged with tests, plus the `census` and `report`
commands — is met on this branch: the rung fixtures exist, are built from
source in CI, executed and compared with goldens; `census` and `report`
exist. What the checkpoint does not say, and what is honest to add, is that
every rung is **blocked**, not passing: the runtime lacks the APIs they
call. P0's remaining gap is the VirtualQuery layer of entry 12 and the
deterministic `call [iat]` limit of entry 8.

## Status per pillar

| Pillar | State | Notes |
| --- | --- | --- |
| P0.1 input policy, asset-policy checker, pre-commit hook | done | asset-policy job green on GitHub |
| P0.1 committed binaries removed | done | tip only; history not rewritten |
| P0.1 third-party register, ADR-0008 | done | project license left to the maintainer |
| CI sanitizers, native flag OFF and ON | done | all four legs green on GitHub for the latest commit |
| Warning-clean | done | 0 warnings with gcc 14.2.0 (five configurations) and with clang 18.1.8 (Release, native flag ON); 32 of 32 tests in both final builds |
| P0.4 `xbox2pc run` JSON report on every outcome | done | `tests/m12_run_test.cpp` |
| P0.4 `--unimplemented=strict\|trap\|zero` | done | native backend end to end; deterministic backend at engine level (entry 8) |
| P0.4 `xbox2pc run` on the M11 sample | in progress | loads (13 of 13), allocates, exits 53: `VirtualQuery` (entry 12) |
| P0.4 crash telemetry (`crashes.log`, `XBOX2PC_WATCH`, `XBOX2PC_CRASH_SAVE`, `XBOX2PC_STACKS`) | done, bounded | API-boundary sampling; no `.pdata` frame walk yet; one guest thread |
| P0.4 `xbox2pc report` | done | faults by site, unimplemented calls, API histogram |
| P0.2 rung fixtures B–G, `cxxthrow` | done as fixtures; all six **blocked** | built from source and executed in CI against goldens |
| P0.3 `xbox2pc census` | done | first-reach ranking from run reports; weekly triage |
| Byte-identical determinism test | done for run reports | 100 native trap runs identical; rung goldens are deterministic traces |
| README honesty table | done | the M12 table in README.md |
| P1 worker, ring slots, shim tier, async waits, MSVC exceptions, loader, seccomp | not started | |
| ADR-0002 … ADR-0007 | not started | |
| P2 descriptor factory, waves 1–5 | not started | |
| P3 graphics providers | not started | no window, no triangle, no GPU run |
| P4 shader translation | not started | |
| P5 x86-64 conformance, proxy title | not started | |
| "What broke" report | in progress | `docs/m12-what-broke.md`, fourteen entries |
| M13 proposal | not started | |

No API and no feature is marked supported by this branch beyond what the
registry already documented before M12.

## Verified on GitHub

Workflow runs exist for every pushed commit of the branch. Read back:

| Commit | Jobs | Result |
| --- | --- | --- |
| `569529c` (first seven commits) | 22 | all green |
| `3f7f96d` (run path) | 22 | 21 green; `Debug · gcc` failed in the pull-request run (`ProcessResumePreservesPreexistingManualSuspension`), passed in the push run: the race of entry 11 |
| `f256b69` (race, ExitProcess, process start) | 22 | all green |
| `a45758b` (rung fixtures) | 24 | all green, including the new `M12 rung fixtures B-G` job |
| later commits | 24 | see the pull request's check list; this page is updated with them |

## Verified locally

gcc 14.2.0, cmake 3.31.10, Linux x86-64, 2 vCPU; sanitizer flags as in
`.github/workflows/ci.yml`. Clean builds of the tree before the last docs
commit.

| Configuration | Native flag | Tests | Warnings | Sanitizer reports |
| --- | --- | --- | --- | --- |
| Release | ON | 32 of 32 | 0 | not applicable |
| ASan + UBSan | OFF | 30 of 30 | 0 | 0 |
| ASan + UBSan | ON | 30 of 30 | 0 | 0 |
| TSan | OFF | 30 of 30 | 0 | 0 |
| TSan | ON | 30 of 30 | 0 | 0 |

The sanitizer rows were run before the census and telemetry slices (30
tests); those two slices and the clang warning fixes are covered by the
GitHub sanitizer legs of their pushed commits, which are green. After the
last code change the tree was rebuilt and tested with both compilers:
gcc 14.2.0, Release, native flag ON: 32 of 32 tests, 0 warnings; clang
18.1.8, same configuration: 32 of 32 tests, 0 warnings. One gcc run in
between reported a failure that was not a test failure: a build killed at
this machine's ten-minute command limit had left a zero-length, non-
executable test binary behind (`x86_differential_test`), which make did not
relink because its timestamp was newer than the sources. That was this
sandbox's tooling, not the project; the file was removed and relinked.

## Not verified

- **Sanitizers were not run locally on the last two slices** (census,
  telemetry); GitHub ran them on the pushed commits.
- **No real-GPU result of any kind.**
- **Rungs pass nowhere**: all six are blocked at a named import.
- **The deterministic backend cannot follow `call [iat]`** (entry 8): every
  compiler-built program runs on the native backend only.
- **`xbox2pc run` on the M11 sample returns 53, not 42** (entry 12).

## What remains before the P0 stop point, in order

1. Diagnose `VirtualQuery` in the run path (entry 12) so the sample returns
   42; tighten the CI step of entry 4.
2. Decide how the deterministic backend follows `call [iat]` (entry 8).
3. Rungs: each becomes passing only as its pillar lands (window P2 wave 4,
   files P2 wave 3, threads P1, graphics P3/P4). The goldens move with
   them, one deliberate `--update` at a time.
4. Local sanitizer runs on the final tree; the clang build with the
   project's warning flags.
5. The P0 stop-point report.

## Commits on this branch

Pushed, in pull request #18:

| Commit | Subject |
| --- | --- |
| `1d941e0` | M12.P0: input policy, asset-policy checker and pre-commit hook |
| `3aae2c7` | M12.P0: remove committed binaries from the tree |
| `72adeb7` | M12.P0: enforce the asset policy in CI |
| `724deee` | M12.P0: third-party register and ADR-0008 |
| `4de257f` | M12.P0: sanitize with the native flag on and off |
| `9328a73` | M12.P0: warning-clean and a handshake for the blocked-dispatch tests |
| `569529c` | M12.P0: M12 status and the what-broke log |
| `25103ee` | M12.P0: `xbox2pc run` reports every outcome, loads the M11 sample, `--unimplemented` |
| `3f7f96d` | M12.P0: status and what-broke after the run path |
| `f256b69` | M12.P0: ExitProcess from a real import table, a started run process, a suspension race |
| `a45758b` | M12.P0: rung fixtures B to G, built from source and executed in CI |
| `852a4db` | M12.P0: `xbox2pc census` with first-reach ranking, and a JSON reader |
| `2b20414` | M12.P0: crash telemetry, `XBOX2PC_WATCH`, `xbox2pc report` |
| (pushed with this page's update) | M12.P0: warning-clean with clang |
| (pushed with this page's update) | M12.P0: README honesty table, status and what-broke after the third session |

Sixteen commits; the plan asks for under forty per pull request.
