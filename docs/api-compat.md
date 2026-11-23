# Xbox API Compatibility (M7)

**Status: M7 complete.** The compatibility foundation
(`xbox2pc_rt_api` + `xbox2pc_rt_gdk` + `xbox2pc_rt_compat_report`) lets
Xbox PE32+ executables resolve supported Xbox APIs through the
xbox2pc runtime: verified API identities can be registered, supported
implementations dispatched safely, executable imports resolved through
the runtime, and unsupported APIs reported accurately. **It does not
execute guest code and does not claim game compatibility.**

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ CLI: api-list api-info api-status dispatch-test compat-report │
│      gdk-services gameos-services                             │
├──────────────────────────────────────────────────────────────┤
│ rt_compat_report: build_compat_report (M1/M2/M6/M7 join)      │
├──────────────────────────────────────────────────────────────┤
│ rt_gdk: GameRuntimeService · TaskQueueService ·              │
│         TimingService (RtService subclasses; M3 registry      │
│         drives init/shutdown ordering) + TLS init             │
├──────────────────────────────────────────────────────────────┤
│ rt_api: ApiDescriptor table · ApiRegistry (thread-safe) ·     │
│         dispatch (validation) · ApiResolver (M6               │
│         IImportResolver) · resolve_delay_imports             │
├──────────────────────────────────────────────────────────────┤
│ M2 ApiRegistry/CompatibilityDb (evidence DBs, extended use)  │
│ M6 ImageLoader/IImportResolver · M3 ServiceRegistry ·         │
│ M4 threads/processes · PAL clock                             │
└──────────────────────────────────────────────────────────────┘
```

Dependency graph: `rt_gdk → rt_api → rt_loader/M2 DBs/rt_services`;
`rt_compat_report → rt_api + M2 dep_analyzer`. No library links
upward; the CLI depends on all three but nothing depends on the CLI.
No second registry duplicates M2's evidence DB — rt_api's descriptor
table EXTENDS the same evidence discipline (citations required).

## API metadata and evidence policy

Each `ApiDescriptor` records the library, export name, documented
signature (verbatim from the reference page), calling convention,
parameter count, return-type class, category, compat + implementation
status, evidence tag, verified URL, and notes (limitations, version
differences). Statuses: NativeEquivalent / FullyImplemented /
PartiallyImplemented / Stubbed / Unsupported / Unknown.

Policy (enforced by `validate()`, tested by fuzz + unit tests):
- signatures come from OPENED reference pages (never inferred)
- ordinals are never invented (no verified ordinals exist in M7)
- evidence URL must be https and the tag non-empty
- a descriptor without established calling convention is REFUSED
- "FullyImplemented" requires a registered implementation covering the
  documented behavior — an export's existence alone never qualifies

## The 16 built-in descriptors (all evidence-cited)

| API | Signature (documented) | Status |
|---|---|---|
| XGameRuntimeInitialize | `HRESULT XGameRuntimeInitialize()` | fully-implemented |
| XGameRuntimeUninitialize | `void XGameRuntimeUninitialize()` | fully-implemented |
| XGameRuntimeInitializeWithOptions | `HRESULT ...(const XGameRuntimeOptions*)` | stubbed |
| XSystemGetDeviceType | `XSystemDeviceType XSystemGetDeviceType()` | stubbed (Unknown fallback) |
| XSystemGetConsoleId | `HRESULT ...(size_t, char*, size_t*)` | stubbed (all-zero PC id) |
| XSystemGetXboxLiveSandboxId | `HRESULT ...(size_t, char*, size_t*)` | stubbed ('RETAIL') |
| XSystemGetAppSpecificDeviceId | `HRESULT ...(size_t, char*, size_t*)` | stubbed (40×'0') |
| XSystemGetRuntimeInfo | `XSystemRuntimeInfo XSystemGetRuntimeInfo()` | stubbed |
| XThreadSetTimeSensitive | `HRESULT ...(bool)` | partially-implemented |
| XThreadIsTimeSensitive | `bool XThreadIsTimeSensitive()` | partially-implemented |
| XTaskQueueCreate | `HRESULT ...(mode, mode, handle*)` | partially-implemented |
| XTaskQueueDispatch | `bool ...(queue, port, timeoutInMs)` | partially-implemented (timeout wait; no callback execution) |
| XTaskQueueCloseHandle | `void ...(queue)` | partially-implemented |
| XTaskQueueTerminate | `HRESULT ...(queue, bool, void*, cb*)` | partially-implemented |
| XTaskQueueSubmitCallback | `HRESULT ...(queue, port, context, callback*)` | unsupported implementation |
| XTaskQueueSubmitDelayedCallback | `HRESULT ...(queue, port, delayMs, context, callback*)` | unsupported implementation |
| XTaskQueueDuplicateHandle | `HRESULT ...(queue, duplicatedHandle*)` | unsupported implementation |
| WaitForMultipleObjects | `DWORD ...(count, HANDLE*, waitAll, timeout)` | partially-implemented (wait-any only) |
| QueryPerformanceCounter | `BOOL ...(LARGE_INTEGER*)` | native-equivalent |
| QueryPerformanceFrequency | `BOOL ...(LARGE_INTEGER*)` | native-equivalent |

Evidence: the per-function reference pages under
`learn.microsoft.com/en-us/gaming/gdk/docs/reference/system/...`
([GDK-INIT], [GDK-SYS], [GDK-THREAD], [GDK-TQ]) and the Win32
profileapi pages ([MS-QPC]) — URLs stored verbatim in each descriptor
and printed by `api-info`/`compat-report`.

Documented semantics implemented (cited): per-process GRT
ref-counting, terminal-uninit failure, `E_GAMERUNTIME_DLL_NOT_FOUND`,
`ERROR_INSUFFICIENT_BUFFER` size bounds, the all-zero console id /
'RETAIL' sandbox / 40-zero app-device fallbacks, `XSystemDeviceType`
values (Unknown=0x00 … XboxScarlettDevkit=0x08), queue ref-counts and
`E_ABORT` termination semantics, dispatch bool semantics, QPC/QPF
native equivalents through the PAL monotonic clock (1 GHz model).

## Runtime registration and dispatch

`IApiImplementation` is a controlled C++ interface
(`invoke(const ApiContext&, ApiCallResult&)`) — implementations are
NEVER raw host function pointers. Services (M3 `RtService`
subclasses) register implementations into the `ApiRegistry` at
`on_initialize` and REVOKE them at `on_shutdown` (`revoke_owner`) —
a destroyed service's registrations disappear, they never dangle.

Dispatch validation: descriptor must exist → argument count must equal
the documented parameter count → calling convention must be
established → an implementation must be registered → then the
implementation runs under the lock-free-of-registry contract
(shared_ptr copy taken under the lock; invocation outside it).
Every failure is a structured `ApiCallResult` with error text.

Case policy: module and export lookups fold case (matching the
Windows/GDK loader's case-insensitive export resolution); a different
name never matches regardless of similarity.

## Import resolver integration

`ApiResolver` implements M6's `IImportResolver`: imports resolve to
synthetic dispatch-table binding values — opaque ids encoding an
implementation ticket, never host addresses. States stay distinct:
implemented → Resolved; descriptor-without-implementation or
known-module-unknown-export → Unresolved; unknown module →
Unsupported. A full M6 `load_image` through the ApiResolver resolves
imports, writes IAT slots, and (with unresolved imports) fails with
`MissingDependency` after full rollback — exactly like M6's own
resolver discipline.

## Delay-load imports

`resolve_delay_imports` walks directory 13's 32-byte `ImgDelayDescr`
records (RVA/VA addressing per the descriptor's attribute bit),
resolves each thunk through the SAME ApiRegistry, and writes bound
values into the mapped image's IAT slots: bounds-checked against the
mapped image, section RW-flipped then restored (M6 discipline).
Unresolved entries are reported individually (`DelayLoadReport`);
with `fail_on_unresolved=true` the whole call fails with
`MissingDependency`. Delay resolution is tested independently of
normal imports AND in the 15-step e2e path.

## Calling conventions and ABI limitations

`Convention` is a metadata layer: `None` (no args), `X64Microsoft`
(x64 Windows/Microsoft convention — the only convention Xbox PE32+
AMD64 images use; documented by the Win32 ABI pages), `Unknown`
(refuses dispatch). Matching metadata authorizes the DISPATCH
CONTRACT only — **no host ABI forwarding happens**: implementations
receive typed `ApiContext` argument slots and set documented return
values through `ApiCallResult`. A guest-to-host call bridge (real
argument marshalling from a guest stack into these slots) requires
the execution-context milestone and is explicitly DEFERRED: the
interface (`ApiContext` shape) exists, the marshalling does not.
A matching function name NEVER implies host ABI compatibility.

## Game OS compatibility foundation

The Game OS surface in M7 is the M3–M6 runtime itself exposed through
documented GDK-facing APIs: per-process lifecycle state (M4 processes),
time-sensitive thread bits (M4 thread model), task queues (M4-backed
manual-mode queues), timing (PAL). `gameos-services` reports this
honestly — it is the compatibility FOUNDATION, not a Game OS
implementation; no kernel emulation is claimed, and internal host OS
objects are never exposed directly (everything rides the M4/M3/PAL
abstractions).

## GDK services

Three `RtService` subclasses register into M3's `ServiceRegistry`
(PlatformInfoService remains the built-in): `gdk_game_runtime`
(lifecycle + XSystem + XThread), `gdk_task_queue` (XTaskQueue),
`win32_timing` (QPC/QPF native equivalents). Initialization order and
reverse-order shutdown come from the M3 registry; a failed
`initialize_all` reports typed errors; per-process state is keyed by
M4 process ids; access is thread-safe (mutex-guarded state + the
registry's shared_ptr discipline). Test providers are deterministic —
no Xbox Live, authentication, multiplayer, or cloud behavior is
faked anywhere.

## TLS

`tls_assign_index` allocates a stable per-(process, module) index
(0 reserved); `tls_init_thread` copies the file-backed template into
the thread's slot (M4 `RtThread::tls_set`), zero-fills
`SizeOfZeroFill` bytes beyond it, and enforces the 1 MiB total bound
(the fuzz-found fix: a mutated ~4 GiB SizeOfZeroFill previously
caused an unbounded resize — now a typed `OutOfResources`;
regression-locked). TLS callbacks remain counted-but-never-executed
(M6 rule; full callback support needs the execution context).
Thread death frees the per-thread slots with the M4 thread object;
`tls_release_indices` frees a process's index table at termination
(verified in the e2e test).

## Compatibility reporting

`build_compat_report` joins M1 (parse), M2 (DependencyReport incl.
delay-load + unresolved markers), M7 (descriptors + implementations),
and the delay-load resolution report into one row per imported
function with STABLE codes: `ok-implemented`, `ok-stubbed`,
`ok-native`, `partial`, `stub-missing`, `unsupported-api`,
`unsupported-module`, `unknown-import`, `unresolved-delay`,
`invalid-import`, `missing-service`. Each verified row carries its
evidence citation and documented signature. The verdict line never
claims compatibility from recognition — coverage is reported as
coverage, and the CLI prints the explicit note
"import coverage is NOT game compatibility".

## CLI

```
xbox2pc api-list                                  # 16 descriptors + statuses
xbox2pc api-info <library!name>                  # signature/convention/evidence/notes
xbox2pc api-status                                # live registry + registrations
xbox2pc dispatch-test <library!name>              # controlled dispatch (no guest code)
xbox2pc compat-report <pe-file>                   # per-import codes + delay-load verdict
xbox2pc gdk-services                              # live M3 service registry state
xbox2pc gameos-services                           # the M4-backed foundation surface
```

All commands boot a live runtime with the three services
initialized; exit codes: 0 success, 1 typed failure (e.g.
dispatch-test on a validation-rejected probe), 2 usage. `--json out`
supported everywhere. M1–M6 commands all remain functional.

## Testing and fuzzing

- `api_compat_test` — 23 tests: registry (validation/conflicts/
  ownership/revoke/concurrent), dispatcher (documented semantics +
  rejections + shutdown revocation), resolver (states + full load +
  rollback), delay-load (mapped-IAT write + unresolved policy), GDK
  services (ref-counts isolation, id fallbacks + bounds, task queues,
  timing monotonicity, TS bits, failed-init semantics), TLS (indices,
  template + zero-fill, multi-module, release; the HugeZeroFill
  regression), compat-report codes, and the 15-step e2e path
  (M4 process → M5 VFS/XPK → discovery → VFS read → M6 load through
  the ApiResolver → delay-load → TLS init → report → protections →
  unload → terminate → zero regions + TLS release).
- `api_compat_fuzz_test` — 6 harnesses, ~120k mutations (descriptors,
  export lookups, dispatch arguments, delay descriptors, TLS metadata,
  register/revoke/dispatch race under 4 threads).
- Sanitizers: ASan+UBSan and TSan clean over the full suite (the race
  harness included), 0 findings; fresh-directory Release build green
  with no new M7 warnings.
- `api_compat_bench`: descriptor load 0.009 ms, lookup 170 ns,
  dispatch 0.36 us, concurrent dispatch 1.22 us/op/op (4 threads),
  import resolve 0.44 us, delay-load pass 0.024 ms, TLS init 0.099 us,
  compat report 19 us — container CPU, Release, steady_clock.

## Security findings and fixes (this milestone)

1. **TLS zero-fill unbounded resize** (found by the TLS fuzz harness):
   a mutated `SizeOfZeroFill` (~4 GiB) caused a multi-GB allocation;
   now bounded to 1 MiB with a typed error + regression test.
2. **ApiWorld destruction-order use-after-free** (found by the test
   suite itself): the world held `ApiRegistry` as a member declared
   AFTER `RuntimeCore`, so services (owned by core) outlived the
   registry they referenced. Fix: declaration order (registry first).
   Documented as a lifetime rule for future service authors.
3. **Duplicate service init semantics clarified** (found while
   testing): RuntimeCore's `initialize()` already ran
   `initialize_all`; services registered after get `on_initialize`
   only via re-init. Tests now register services BEFORE
   `core.initialize()` — the documented pattern for M7 consumers.

## Confirmed vs inferred

Confirmed (opened pages; cited per descriptor): every signature,
parameter/return semantics, HRESULT/error-code behavior, enum values,
fallback strings, ref-count and E_ABORT semantics listed above.

Inferred (xbox2pc design): descriptor/registry/dispatcher shape,
synthetic binding values, per-process index keying, dispatch
argument-slot contract, the 1 MiB TLS block bound, descriptor
conflict rules, case-folding policy (documented loader behavior
mirrored).

## Known limitations

- 35 built-in API descriptors are cataloged, including partially implemented and explicitly unsupported imports; the GDK surface is far larger (users, achievements,
  multiplayer, storage, input, networking, graphics, audio stay
  unsupported/unknown — deliberately, without fabrication).
- No verified ordinals (nothing ships one).
- Guest-code execution is limited to the deterministic interpreter subset and explicitly supported execution paths; this is not a complete Xbox execution environment or game-compatibility claim.
- XTaskQueue models process-owned Manual-mode queue handles only. Callback submission and delayed submission are cataloged but fail closed: guest callback invocation, cancellation delivery, callback-held queue references, and dispatch scheduling are not implemented. ThreadPool/Immediate modes are unsupported.
- XSystemGetDeviceType always returns the documented Unknown
  fallback (no device spoofing).
- Delay-load resolution resolves at load time; the runtime does not
  implement lazy first-call hooking (the documented delay-load
  semantics of resolving on first call require an execution context).

## Current execution boundary

The M8 execution-context foundation is present: guest CPU state, ABI marshalling, a bounded interpreter, TLS callback execution, and controlled entry-point invocation. M10 expands selected Game OS services but still lacks scheduler-aware waits, complete guest-thread lifecycle integration, full task-queue callback execution, broad system-service coverage, and full virtual-memory subrange semantics. A successful import resolution or partial guest execution does not establish that a retail Xbox game can boot.
