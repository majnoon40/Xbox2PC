# M12 — status

Branch `feature/m12`, based on `main` at `1ce36e0`. Draft pull request:
<https://github.com/majnoon40/Xbox2PC/pull/18> (every commit of the branch is
pushed; nothing is local-only).

Rules for this page: nothing is "done" without an automated test that
passes; "verified in CI" means the job ran on GitHub for the pushed commit
and the result was read back; stubs and partials are labeled as such.

## Where this branch stands

**P0's stop point has arrived.** Four sessions went into it. The plan's
week-3 checkpoint — rungs B to G merged with tests, plus the `census`
and `report` commands — is met on this branch, and the fourth session
finished the run path: the VirtualQuery layer of entry 12 is fixed end
to end (entries 15 and 16 with it), so the compiler-built M11 sample
runs all thirteen of its imports and returns 42, asserted in CI. What
the checkpoint does not say, and what is honest to add, is that every
rung is still **blocked**, not passing: the runtime lacks the APIs
they call. P0's remaining open item is the deterministic `call [iat]`
limit of entry 8, deliberately left documented for the P1 benchmark
and ADR decision.

## Status per pillar

| Pillar | State | Notes |
| --- | --- | --- |
| P0.1 input policy, asset-policy checker, pre-commit hook | done | asset-policy job green on GitHub |
| P0.1 committed binaries removed | done | tip only; history not rewritten |
| P0.1 third-party register, ADR-0008 | done | project license left to the maintainer |
| CI sanitizers, native flag OFF and ON | done | all four legs green on GitHub for the latest commit |
| Warning-clean | done | 0 warnings in all six gcc configurations and with clang 18.1.8 (Release, native flag ON) on the final tree; 33 of 33 tests in every build |
| P0.4 `xbox2pc run` JSON report on every outcome | done | `tests/m12_run_test.cpp` |
| P0.4 `--unimplemented=strict\|trap\|zero` | done | native backend end to end; deterministic backend at engine level (entry 8) |
| P0.4 `xbox2pc run` on the M11 sample | done | returns 42 on the native backend: 13 of 13 imports resolved and called; `m11-pe-fixtures` job asserts it (entries 12, 15, 16) |
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
| "What broke" report | in progress | `docs/m12-what-broke.md`, sixteen entries |
| M13 proposal | not started | |

No API and no feature is marked supported by this branch beyond what the
registry already documented before M12.

## Verified on GitHub

Workflow runs exist for every push head of the branch. Read back:

| Commit | Jobs | Result |
| --- | --- | --- |
| `569529c` (first seven commits) | 22 | all green |
| `3f7f96d` (run path) | 22 | 21 green; `Debug · gcc` failed in the pull-request run (`ProcessResumePreservesPreexistingManualSuspension`), passed in the push run: the race of entry 11 |
| `f256b69` (race, ExitProcess, process start) | 22 | all green |
| `a45758b` (rung fixtures) | 24 | all green, including the new `M12 rung fixtures B-G` job |
| `852a4db` (census), `2b20414` (telemetry), `f7eb166` (clang-clean), `0f52eb9`, `b29d153` | 24 | all green |
| `c9a9b6e` (final docs update) | 24 | all green |
| `4299e0d` → `ba86689` (VirtualQuery fix + honest numbers; pushed together, so the workflow ran on the head `ba86689` only) | 24 (push run) + 24 (pull-request run) | all green; the tightened `m11-pe-fixtures` step ran and printed `returned exit 42 \| 13 API calls` |

## Verified locally

gcc 14.2.0 and clang 18.1.8, cmake 3.31.10, Linux x86-64, 2 vCPU;
sanitizer flags as in `.github/workflows/ci.yml`. Clean builds of the
final tree, after the last code change.

| Configuration | Native flag | Tests | Warnings | Sanitizer reports |
| --- | --- | --- | --- | --- |
| Release (gcc) | OFF | 33 of 33 | 0 | not applicable |
| ASan + UBSan (gcc) | OFF | 33 of 33 | 0 | 0 |
| ASan + UBSan (gcc) | ON | 33 of 33 | 0 | 0 |
| TSan (gcc) | OFF | 33 of 33 | 0 | 0 |
| TSan (gcc) | ON | 33 of 33 | 0 | 0 |
| Release (gcc) | ON | 33 of 33 | 0 | not applicable |
| Release (clang 18.1.8) | ON | 33 of 33 | 0 | not applicable |

The M11 freestanding sample returns 42 through the `xbox2pc` binary of
every native-flag-ON build above (gcc and clang), and five consecutive
native runs were checked individually on the final tree (all 42). The clang build needed the conda
toolchain pointed at the host (system sysroot, GNU linker, GCC builtin
headers); with those flags it is warning-clean, and it found two
long-standing unused private fields (`api_reg_`, `space_`) that gcc's
`-Wunused-private-field` does not have; both now carry `[[maybe_unused]]`
and the gcc builds were re-run green on the final tree.

## Not verified

- **No real-GPU result of any kind.**
- **Rungs pass nowhere**: all six are blocked at a named import.
- **The deterministic backend cannot follow `call [iat]`** (entry 8): every
  compiler-built program runs on the native backend only.
- **The remaining TEB pointer fields (self, stack bounds, PEB) stay in
  guest form** (entry 15, remaining); nothing reads them through GS yet.
- **Out payloads above the ring's 200-byte wire cap are not carried to
  the child** (entry 16); no implementation produces one today.

## What remains before the P0 stop point, in order

1. ~~Diagnose `VirtualQuery` in the run path (entry 12) so the sample
   returns 42; tighten the CI step of entry 4.~~ Done: the sample
   returns 42 (entries 12, 15, 16); the `m11-pe-fixtures` step now
   asserts `outcome == returned`, `exit_code == 42`, 13 API calls.
2. Entry 8 (deterministic `call [iat]`) stays documented, not decided;
   the decision belongs to the P1 benchmark and ADR-0002/0003.
3. Rungs: each becomes passing only as its pillar lands (window P2 wave 4,
   files P2 wave 3, threads P1, graphics P3/P4). The goldens move with
   them, one deliberate `--update` at a time.
4. ~~Local sanitizer runs on the final tree; the clang build with the
   project's warning flags.~~ Done (see "Verified locally").
5. The P0 stop-point report: written into the pull request after the
   final push is green on GitHub.

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
| `f7eb166` | M12.P0: warning-clean with clang |
| `0f52eb9` | M12.P0: README honesty table, status and what-broke after the third session |
| `b29d153` | M12.P0: correct the commit count on this page |
| `c9a9b6e` | M12.P0: record the final CI outcome |
| `4299e0d` | M12.P0: VirtualQuery through the native run path (pointer args, TLS chain, out buffers across the ring) |
| `ba86689` | M12.P0: honest numbers for the final tree in the README table; real hashes in this page |
| (this commit) | M12.P0: the CI table records how the last two commits were actually verified |

Twenty commits (including this one); the plan asks for under forty per
pull request.
