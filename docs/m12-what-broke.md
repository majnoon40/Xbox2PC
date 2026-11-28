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

## 3. `xbox2pc run` could not load the compiler-built M11 sample, and wrote no report (fixed)

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

**State.** Fixed. The run world registers all three services the
repository has (`GameRuntimeService`, `TaskQueueService`, `TimingService`,
the `M7World` set), so the sample's 13 imports all resolve, and a JSON
report is written on every outcome, listing every IAT slot with its status.
`xbox2pc run --help` prints usage. What happened next is entries 10
and 12.

## 4. CI never executed a compiler-built PE (fixed for the rungs; the M11 sample step is deliberately loose)

The `m11-pe-fixtures` job builds the freestanding samples with clang and
lld-link, checks their bytes with `objdump` and compares their SHA-256 with
`samples/m11/golden/SHA256SUMS.txt`. It never passed one to `xbox2pc run`,
so the gap in entry 3 was invisible to CI. It now runs the freestanding
sample through `xbox2pc run --backend native --json` and asserts that it
loads and that guest code runs (13 of 13 imports resolved, `ran` true),
printing the outcome; the assertion stays loose until entry 12's open layer
is fixed, then must be tightened to `outcome == returned` and
`exit_code == 42`. The `rung-fixtures` job goes further: it builds the six
rung programs from source and compares each run report with a committed
golden, so a regression in loading or dispatching a compiler-built image
fails CI.

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

## 10. The compiler-built M11 sample spun forever after its fourth import call (fixed)

**Symptom.** `xbox2pc run build/m11-samples/m11_freestanding.exe --backend
native --json` gave `imports: 13 of 13 resolved`, `ran: true`, `api_calls:
4`, `outcome: faulted`, `budget-exceeded: native guest entry exceeded its
child-process time limit`.

**What it was.** The fourth call was `ExitProcess(52)`, the sample's
"VirtualAlloc returned NULL" exit (entry 12). The native parent recognized
`ExitProcess` by comparing the module name byte-exact with `"kernel32"`. A
real import table spells the module `kernel32.dll`, so `ExitProcess` was
dispatched as an ordinary call, the reply carried no terminate contract,
the child resumed after the call into the sample's `for (;;) {}`, and it
spun until the watchdog fired.

**Method.** Sampling both processes while the run hung settled it in one
step: the parent was asleep in its 1 ms poll with zero CPU time, the child
was running at 100% in user code. That ruled out a dispatch hang and
pointed at guest code. The earlier reading that the fourth call was
`VirtualQuery` was an inference from the call count alone and was wrong;
the run report now carries the API trace, which answers that question
directly.

**Fix.** The parent compares the registry's normalized module name
(`registry::normalize_module_name`). Regression test:
`M12NativeRun.ExitProcessIsRecognizedFromARealDllName`, with both
spellings of the module.

## 11. A parked thread could be left parked forever (fixed)

**Symptom.** CI, Debug gcc, pull-request run of `3f7f96d`:
`ProcessMgmtTest.ProcessResumePreservesPreexistingManualSuspension` failed
(`is_parked()` true after `resume_process`, progress counter frozen for
2 s) while the push run of the same commit passed.

**Cause.** `RtThread::suspension_point()` flipped the state from
`Suspended` to `Running` from a `checkpoint()` result that could predate a
concurrent `suspend()` (which requests the gate before storing the
state). The thread then parked on the requested gate with a `Running`
state, and `resume_process()` skips threads that are not `Suspended`
without an error, so nothing ever resumed it.

**Fix.** The gate is re-checked under the transition lock before the
state is touched; a pending suspension leaves the state alone and the
next checkpoint parks with the state intact. 300 of 300 runs in a Debug
build and 200 of 200 in Release locally; the Debug gcc leg is green in CI
since `f256b69`.

## 12. The run path never started the process, so Win32 memory and sync APIs failed (fixed)

**Symptom.** After entry 10 the sample exited with 52: `VirtualAlloc`
returned NULL.

**Cause.** `run_file` created the process and loaded the image but never
called `initialize_process` and `start_process`. `reserve_region_by_pid`
and its siblings act only on a process in the `Running` state, so every
Win32 memory or synchronization call in `xbox2pc run` failed, in both
backends, and the M11 hand-built fixtures never noticed because they do
not call those APIs.

**Fix.** The run path initializes the process with the module and starts
it, as the execution tests do. The sample now allocates.

**Second layer, diagnosed and fixed.** It then exited with 53:
`VirtualQuery(allocation, &information, 48)` answered 0. The
registry-level unit test passed because the defect was not in the
implementation: the child executes the image through the load bias, so
`&information` — a pointer the guest computed from its own stack —
arrived at the parent as a HOST address, and the marshalling bridge
validated it as a guest VA and rejected the call (`pointer arg 1
invalid: invalid-address`). `VirtualAlloc` had slipped through only
because its pointer argument is passed by value. The parent now
translates pointer arguments that the plan declares as pointers back to
guest VAs through the same load bias it already uses for the stack;
every other value passes through untouched. Regression:
`M12NativeRun.VirtualQueryReceivesGuestStackPointers` (a hand-built
image that VirtualAllocs a page, queries it with the
MEMORY_BASIC_INFORMATION on its own stack, and checks the return value
and three written fields) — it failed on the unfixed parent. What the
fix revealed is entries 15 and 16. The buffer-length semantics the plan
asked about are pinned at the bridge level by
`BridgeTest.VirtualQueryMarshalsExactAndShortBuffers`: an exact
48-byte buffer returns 48 and writes the documented offsets (including
PartitionId and the tail padding), dwLength 47 answers 0 and writes
nothing, and an out buffer that is not writable guest memory is
rejected before dispatch.

**Removed by.** ADR-0009 (`ccda389`): the child identity-maps the
space, so a pointer the guest computed is a guest VA by construction and
the load-bias translation above is deleted from the ring serve loop.
Its regression test is now the identity proof: the child sends guest VAs
or the bridge rejects the call.

## 13. A position-independent image without relocations cannot be placed (fixture side fixed; runtime limit open)

**Symptom.** Every rung fixture failed to load with `invalid-state:
preferred image base unavailable and the image has no relocations
(cannot move)`.

**Cause.** The fixtures are position-independent code with no absolute
addresses, so lld-link emits no base relocation table even with
`/DYNAMICBASE`. A PE without relocations can only load at its preferred
base, and the managed address space does not contain the default PE base
(`0x140000000`). The M11 sample carries absolute VAs in its TLS directory
and was never affected.

**Fixture fix.** Every rung image links `rung_reloc.c`, one
self-referential pointer that forces a DIR64 relocation.

**Runtime limit (open).** A reloc-less image still cannot be loaded. Real
Windows honors the preferred base; the managed space would have to contain
it, or the loader would need to say so earlier (it does say so precisely).

**Revisited (ADR-0009).** The identity mapping does not close this. A
forked child under ASan cannot map above 2 GiB at all — the shadow gap
occupies it (measured in
`docs/adr-0009-guest-memory-memfd-identity.md`) — so no sanitizer-green
guest space can contain the default PE base `0x140000000`. The ceiling
is now measured instead of vague: from the run-path base `0x20000000`
the largest identity range that is green under plain, ASan and TSan
builds ends at `0x7FFF7000` (~1.46 GiB); TSan and plain builds allow
more, and the design targets the intersection. The fixture-side fix
stands (link reloc-less images inside the guest range, which
`rung_reloc.c` effectively does). Still open.

## 14. Under trap and zero the module gate still rejected unknown modules (fixed)

**Symptom.** Rung B reported `7 of 9 unresolved/unsupported/invalid`
under `--unimplemented=trap`: its `user32` imports were `Unsupported`, not
bound.

**Cause.** The loader asks the resolver's module gate once per DLL and
marks every import of an unknown module `Unsupported` without consulting
`resolve()`, so the policy never saw them.

**Fix.** Under `trap|zero` the gate passes every module and each import is
bound (or not) on its own; the resolver still words its note from the real
descriptor scan. `strict` is unchanged.

## 15. The child faulted dereferencing the guest-form TLS chain (fixed)

**Symptom.** After entry 12's fix the M11 sample ran all twelve
non-exit imports, then died with SIGSEGV before calling `ExitProcess`,
faulting at `addr=0x20048000`: its `__declspec(thread)` word read never
returned.

**Cause.** The child dereferences the TLS chain with raw addresses:
GS base -> `TEB.ThreadLocalStoragePointer` -> vector slot -> TLS block.
The environment materializes every link of that chain as a guest VA,
and the child executes the image through the load bias, so the first
guest-form pointer it dereferenced was not mapped in its address
space. Only the GS base itself had been translated to a host address;
the M11 hand-built tests never read a TLS variable through GS on the
native backend, so nothing had noticed.

**Fix.** Before the fork the parent translates the chain into the
child's host form — `TEB.ThreadLocalStoragePointer` and every nonzero
TLS vector slot — through the same load bias; an RAII guard restores
the guest form after the child is reaped, so the deterministic view
never observes host pointers. Proof: the sample's TLS check
(`tls_word != 0x13579BDFu` would exit 61) now passes on its run to 42,
asserted by the tightened `m11-pe-fixtures` step in CI
(`outcome == returned`, `exit_code == 42`, 13 API calls).

**Remaining.** The other TEB pointer fields — self, stack bounds, PEB —
are still written in guest form; nothing reads them through GS yet.
When one does, translate it the same way and regress it with a fixture.

**Removed by.** ADR-0009 (`ccda389`): with the child identity-mapping
the space, guest form == child host form for every byte of the space,
so the TEB and its TLS chain stay in guest form for both backends and
the adapt/restore layer above is deleted. The "Remaining" note stands
in a new form: the other TEB pointer fields stay in guest form because
that is now the correct form; nothing needs translating.

## 16. Out-buffer bytes never reached the child: the ring crossed the fork, guest memory did not (fixed)

**Symptom.** The native regression fixture of entry 12 exited 56:
`VirtualQuery` had returned 48 and the parent's own view of the 48-byte
structure was byte-perfect (BaseAddress and AllocationBase at the
allocation, State MEM_COMMIT, Protect PAGE_READWRITE, RegionSize
0x1000, at the documented offsets), yet the child read zeros from its
own stack. The M11 sample passed only because it checks the return
value and never reads the fields.

**Cause.** The managed address space is mapped `MAP_PRIVATE`
(`src/pal_linux.cpp`), so the fork gives the child a copy-on-write
view. The bridge's out-buffer write happens parent-side after the fork,
so it landed in the parent's private copy. The only mapping shared
across the fork is the import ring, which carried the reply registers
only. Every out-struct on the native backend — `VirtualQuery`'s
MEMORY_BASIC_INFORMATION, `VirtualProtect`'s old protection, the
`XSystemGet*` strings — was silently never delivered to the guest.

**Fix.** The reply slot's spare 200 bytes now carry the out payload
(`[u32 out_len][u32 out_arg][payload]`; one out argument per call, as
in the M9 model; bounded by the plan's out deref size and the wire
cap), and the child applies it to the raw pointer it passed — the
parent already validated that pointer, rebased, as guest-writable for
exactly that many bytes. The parent still writes its own view through
the bridge, so both sides hold the same bytes. Payloads above the
wire cap are not carried; none exists today. Regression:
`M12NativeRun.VirtualQueryReceivesGuestStackPointers` reads State,
Protect, and RegionSize from the guest stack at their documented x64
offsets, which is impossible without this fix (verified: with entry
12's rebase present and this fix absent the fixture fails at 56).

**Removed by.** ADR-0009 (`ccda389`): the space is now one memfd mapped
MAP_SHARED in parent and child, so the bridge's out writes are visible
to the child directly; the reply-slot payload and its 200-byte wire cap
are deleted (the wire reply is status, exit code, RAX and aux words).
The regression test above is unchanged and still proves delivery — now
through the shared object.
