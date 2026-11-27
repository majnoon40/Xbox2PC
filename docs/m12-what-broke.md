# M12 — what broke

Log of what broke, was found already broken, or resisted, in milestone 12.
Newest entries first. Every entry names the symptom, the cause, the fix or
the open state, and how to reproduce it. Nothing in this file is a claim of
support for anything.

## 1. Three task-queue tests raced the thread that terminates them (the ASan flake)

**Symptom.** `GdkServiceTest.ProcessExitReleasesDuplicatedTaskQueueAndWakesDispatch`
failed once in the ASan+UBSan baseline of untouched `main` (28 of 29 tests).
It did not fail again in that run's four repetitions, which is the signature
of a race and not of a broken feature.

**Cause.** Four tests in `tests/api_compat_test.cpp` start a waiter thread,
sleep a fixed 10 ms, and then close the queue handle or terminate the owning
process. `TaskQueueService::dispatch` resolves its queue handle first
(`lookup_queue`). A waiter whose thread starts more than 10 ms late resolves
a handle that is already closed, or a process that is already gone, and
fails legitimately. The test then asserts that the dispatch succeeded and
fails. Three tests can fail this way:
`TaskQueueDuplicateHandlesShareLifetime`, `ProcessExitReleasesDuplicatedTaskQueueAndWakesDispatch`
and `TaskQueueFinalCloseWakesDispatchAcrossAliases`. The fourth,
`TaskQueueLifecycle`, could not fail (its terminating call only sets the
`terminated` flag), but its "not done yet" assertion proved nothing: it was
true whenever the thread had not started.

**Fix (tests only, no production change).** The waiter now passes a
`cancellation_requested` predicate that sets an atomic flag and returns
false. `dispatch` evaluates that predicate only once the dispatch holds the
queue and is inside its wait loop, so the flag is a real "I am parked"
handshake. The main thread waits for the flag (bounded, 5 s) instead of
sleeping. The one 10 ms sleep that remains, in
`TaskQueueDuplicateHandlesShareLifetime`, follows the handshake and only
gives a wrong implementation time to wake the dispatch.

**Proof.** With a 50 ms delay injected before every waiter's `dispatch` call
(standing in for a slow thread start):

| Test code | Delayed waiter | Runs | Result |
| --- | --- | --- | --- |
| `main` (fixed 10 ms sleep) | 50 ms | 20 | 0 passed, 20 failed; the three tests above fail every time |
| this branch (handshake) | 50 ms | 20 | 20 passed, 0 failed |

**Reproduce.** Build any configuration and run
`ctest --test-dir <build> -R api_compat_test --repeat until-fail:100`.
The delay-injection script is not in the repository; it is described above
and is four lines to recreate (a `sleep_for` as the first statement of each
waiter lambda).

**Still sleeping on a timer.** `TaskQueueInfiniteDispatchObservesGuestCancellation`
sets its `entered` flag before calling `dispatch` and sleeps 10 ms after it.
Nothing is destroyed concurrently in that test, so it cannot fail from the
late start, but the sleep is not a handshake either.

## 2. The tree did not build warning-clean

**Symptom.** 41 compiler diagnostics (38 unique sites) in every build with
gcc 14.2 and the project's warning flags, on untouched `main`.

**Sites and fixes (all behavior-preserving).**

- `src/dep_analyzer.cpp`: unused helper `lower_copy`, deleted.
- `src/dep_graph.cpp`: unused `diags` parameter of `add_dependencies`,
  unnamed (kept in the signature for symmetry with `build_from_report`).
- `src/json_writer.cpp`: two `int` to `std::size_t` conversions in
  `serialize_to` (a negative indent or depth now counts as 0) and one
  `char` to `unsigned char` conversion in the escape loop.
- `src/native_child.cpp`: `int` to `char` conversion in the decimal writer.
- `src/process_model.cpp`: `std::uint64_t` to `std::uint32_t` conversion for
  `size_of_image` (SizeOfImage is a 32-bit PE field).
- `src/run_cli.cpp`, `tools/xbox2pc_cli.cpp`: ten old-style casts.
- `tools/xbox2pc_cli.cpp`, `tests/vfs_packages_test.cpp`, `tests/vfs_fuzz.cpp`:
  `XpkBuildEntry` initializers missing the `data` member.
- `tools/xbox2pc_cli.cpp`: fifteen lines of dead scaffolding in
  `cmd_packages` (an empty loop over mounts and an unused `PackageInfo`),
  deleted.
- Tests: `int` loop counters used as indexes (`loader_test.cpp`,
  `pe_parser_test.cpp`, `vfs_packages_test.cpp`), an unused `rd16` helper,
  two shadowing names (`m11_lock_order_test.cpp`, `runtime_m4_test.cpp`) and
  one unused lambda parameter.

**Status.** 0 warnings in all five configurations built locally with gcc
14.2.0 (see `docs/m12-status.md`). Not checked with clang in this session;
the `build-and-test` job in CI builds with clang as well and has not run on
this branch.

## 3. `xbox2pc run` could not load the compiler-built M11 sample, and wrote no report (fixed in part)

**Symptom.** `xbox2pc run build/m11-samples/m11_freestanding.exe` failed in
both backends with `error: load failed: imports not fully resolved: 2 of 13
unresolved/unsupported/invalid`, exit status 1, and no JSON report.

**Cause.** `RunWorld` in `src/run_cli.cpp` registers only
`GameRuntimeService`, so every import that is not a game-runtime export has
no implementation and the loader's required-import rule rejects the image.
The sample imports 13 `kernel32` functions; two of them have no resolved
binding in that world. (Which two was not recorded; the resolver reports
them per import.)

**Consequences.** No JSON report is written on that path (the file is only
written after a successful run), so a caller cannot learn the first missing
import from the tool. `xbox2pc run --help` is treated as a file name.

**State.** Fixed in part. The run world registers all three services the
repository has (`GameRuntimeService`, `TaskQueueService`, `TimingService`,
the `M7World` set), so the sample's 13 imports all resolve, and a JSON
report is written on every outcome, listing every IAT slot with its status.
`xbox2pc run --help` prints usage. The sample then stalls at run time:
entry 10.

## 4. CI never executed a compiler-built PE (in part)

The `m11-pe-fixtures` job builds the freestanding samples with clang and
lld-link, checks their bytes with `objdump` and compares their SHA-256 with
`samples/m11/golden/SHA256SUMS.txt`. It never passed one to `xbox2pc run`,
so the gap in entry 3 was invisible to CI. It now runs the freestanding
sample through `xbox2pc run --backend native --json` and asserts that it
loads and that guest code runs (13 of 13 imports resolved, `ran` true),
printing the outcome; the assertion is deliberately loose because of entry
10 and must be tightened to `outcome == returned` and `exit_code == 42`
once that is fixed. The rung fixtures of P0.2 are still the real answer:
each rung executed, its exit code and trace checked.

## 5. Binaries were committed, and so were build directories

At `main` (`1ce36e0`) eleven binary files were tracked: `core`,
`samples/core`, `samples/demo_badmagic.exe`, `samples/demo_minimal.exe`,
`samples/demo_truncated.exe`, `samples/demo_valid.exe`,
`samples/demo_xbox_m2.exe`, `samples/exit42.o`, `samples/sample_exit42.exe`,
`samples/sample_throwcatch.exe` and `samples/throwcatch.o`. Five of the 696
commits on `main` track a build directory (none at the tip; the pack is
489 MiB).

**Fix.** The eleven files were removed from the tip (`3aae2c7`), the
asset-policy checker and the pre-commit hook reject any new one
(`1d941e0`), and CI runs the checker on every push and pull request
(`72adeb7`). The history was not rewritten and the pack was not shrunk:
that would rewrite published history, which M12 forbids. The old objects
are still reachable by commit id.

## 6. There is no project license file (open, needs the maintainer)

The repository has no top-level `LICENSE` at `main`. `docs/third-party.md`
and ADR-0008 put the third-party policy in force and leave the project
license to the maintainer, with the considerations listed. This is not
something an agent can decide.

## 7. No 100-run determinism test exists (open)

The hard rule says "determinism tests (100 consecutive runs) stay green".
At the start of M12 the suite had 29 tests and none of them was a
100-consecutive-run comparison of outputs. Repeating the deterministic
execution tests 100 times with `ctest --repeat until-fail:100` shows they
keep passing; it does
not show that two runs produce byte-identical traces. That test belongs
with the rung fixtures of P0.2, whose goldens are exactly such a trace.
One such comparison now exists for the run report: 100 consecutive native
runs of the trap fixture must give byte-identical reports apart from the
file path (`M12NativeRun.HundredConsecutiveRunsProduceByteIdenticalReports`).

## 8. The deterministic backend cannot follow a `call [iat]` from code (open)

**Symptom.** A compiler-built image that calls an import through its IAT
faults under `--backend deterministic` after a few instructions: the M11
sample stops after 5 with `invalid-access ... step: branch target`.

**Cause.** The interpreter validates every call target as executable guest
memory before it jumps. Import bindings are synthetic addresses
(`0x51000000` to `0x5101FFFF`) that the engine intercepts before the next
fetch, but nothing maps them, and nothing can: the managed address space
starts at `0x10000000`, above the binding range. The native backend
sidesteps this with a host thunk page at the binding base. Engine-level
tests that enter at a binding directly work; real code does not.

**Consequence.** `--unimplemented=trap|zero` is reachable from real code on
the native backend only, and so is every compiler-built fixture. The
deterministic engine's handling is covered at the engine level
(`EngineTest.UnimplementedImport*`).

**State.** Open. Two ways out: place the managed address space so that it
contains the binding range and map it execute-only there, or emit thunks in
guest memory. Both change where images and stacks land and need their own
tests.

## 9. The native backend validated the wrong stack range (fixed)

**Symptom.** The native backend refused the compiler-built sample with
`native guest stack is not a committed writable region` while every
hand-built test image passed.

**Cause.** The context reports `stack_top = region base + size - 64` and
`stack_size = size`. The check validated `[stack_top - stack_size,
stack_top)`, which is `[base - 64, base + size - 64)`: 64 bytes below the
committed region, and not its top 64 bytes. The hand-built images passed
because a writable region happened to lie right below the stack; the sample
had a read-only section there.

**Fix.** The check validates the part of the range that lies inside the
region holding the stack top (`src/native_execution.cpp`).

**Remaining.** The engine's guard floor (`stack_top - stack_size`) is still
64 bytes below the committed region on the deterministic backend; a push
there faults as invalid-access instead of stack-overflow. Not changed.

## 10. The compiler-built M11 sample stalls after its fourth import call (open)

**Symptom.** `xbox2pc run build/m11-samples/m11_freestanding.exe --backend
native --json` gives `imports: 13 of 13 resolved`, `ran: true`, `api_calls:
4`, `outcome: faulted`, `budget-exceeded: native guest entry exceeded its
child-process time limit`.

**What is known.** The image loads and starts; four ring requests were
served; a fifth never arrives within the 5 s limit. By the sample's call
order the fourth call is `VirtualQuery` and the next is `VirtualProtect`.
Not diagnosed: whether the child hangs after the fourth reply or the parent
is stuck inside that dispatch.

**Reproduce.** `scripts/build-m11-samples.sh`; build with
`-DXBOX2PC_NATIVE_EXECUTION=ON`; `build-native/tools/xbox2pc run
build/m11-samples/m11_freestanding.exe --backend native --json out.json`.
The CI step added with entry 4 runs the same command.

**State.** Open. `xbox2pc run` on the sample is not claimed to work; the
report names the stage and the count so the next session starts there.
