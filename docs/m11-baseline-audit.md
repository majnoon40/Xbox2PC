# M11 baseline audit

**Audit scope:** merged `main` at `5dcda95b2620530c89ad0cb1ebb250cbae078cf4` (M10 merge commit).  
**Phase:** M11 Phase 0 only. No feature code was changed for this audit.  
**Method:** source inspection of the loader, memory manager, execution engine/context, ABI bridge, GDK services, process/thread/handle managers, PAL, tests, and existing documentation.

This is a baseline report, not a design approval and not a claim of Windows or Xbox kernel equivalence. Source line references below refer to the audited commit.

## Executive summary

The repository already has a narrow end-to-end execution demonstration: a synthetic PE loaded through the package/VFS and loader path executes a tiny instruction sequence in the deterministic interpreter and returns 42. That is useful proof of the M4–M8 plumbing, but it is **not** a native PE process runner and does not demonstrate a conventional Windows program reaching `ExitProcess`.

The main M11 blockers are concrete:

- Only the bounded deterministic interpreter is implemented. No native backend, native call thunk, guest GS-base management, or host-fault containment exists.
- The current guest address space is a logical Xbox-VA coordinate system backed by an unrelated `mmap(nullptr)` host mapping. Native instruction fetches and ordinary guest pointers cannot use those logical addresses directly.
- There is no TEB/PEB. Existing TLS is an explicit per-thread byte map, not Windows implicit TLS through `gs:[0x58]`.
- The handle system is split between runtime/per-process `HandleTable` objects and a separate monotonic task-queue ID map. The current handle bit layout does not satisfy M11's nonzero-multiple-of-four requirement.
- Event/mutex/semaphore waits observe managed-thread cancellation; an infinite task-queue dispatch does not. Because process-exit observers run only after thread drain, a managed guest thread blocked in infinite `XTaskQueueDispatch` can prevent the observer that would wake it from running.
- Relocation processing is not sized or optimized for 600k entries. The current benchmark exercises only a tiny synthetic relocation set, and the current relocation loop can toggle page protections repeatedly for each relocation targeting a non-writable section.

No feature implementation should begin until these findings are accepted as the baseline.

---

## 1. Can a current backend run a PE from entry to exit? What blocks it?

### Finding: narrowly yes for a synthetic PE; no general/native process runner

The implemented backend is `DeterministicBackend`, labeled `deterministic-test`. Its source and public header describe a bounded instruction subset, not a general x86-64 emulator. The instruction loop in `src/execution_engine.cpp` rejects unsupported instructions with structured outcomes. The interface `IExecutionEngine` permits other backends, but no native implementation is registered or present.

There is a real end-to-end test, `ExecE2eTest.VfsPackageLoadResolveExecuteCleanup`, in `tests/execution_test.cpp:1987-2126`. It builds a synthetic PE containing:

- `mov rax, 20`
- `add rax, 22`
- `ret`

The test places that PE in a synthetic XPK package, mounts and discovers it through VFS, loads it with the M6 loader, prepares an M8 execution context, invokes `DeterministicBackend`, and asserts a return value of 42. This is a meaningful entry-to-return integration test for the implemented subset.

It does **not** demonstrate a normal PE process running to `ExitProcess`:

- The sample returns through the M8 completion sentinel; it does not call `ExitProcess`.
- The test supplies explicit synthetic PID/TID values and a deterministic backend.
- The test does not execute CRT startup, compiler-generated TLS access, C++ exception unwinding, or a general Windows API surface.
- The M6 loader explicitly separates loading/preparation from execution; `prepare_exec()` validates and describes an entry point but does not start it (`include/xbox2pc/image_loader.hpp:37-46)).
- The current CLI exposes inspect/validation/static-analysis/compatibility-report functionality; there is no `xbox2pc run` command or backend-selection runner in `src/m9_cli.cpp` and `tools/xbox2pc_cli.cpp`.

### Blockers

1. No native x86-64 execution backend.
2. Interpreter coverage is intentionally bounded and excludes large parts of the ISA (including SIMD/VEX/EVEX and other classes); see `include/xbox2pc/execution_engine.hpp`, `src/execution_engine.cpp`, and `include/xbox2pc/x64_decoder.hpp:9-24`.
3. No guest TEB/PEB, implicit TLS, last-error state, or Windows exception unwinder.
4. No native executable mapping at the guest virtual addresses.
5. No executable host-shim thunk for imported APIs.
6. No process-level runner connecting loader, process/thread lifecycle, entry invocation, exit-code propagation, trace output, and cleanup.

**Conclusion:** the existing E2E test is a good interpreter oracle and integration fixture. It must not be described as general PE execution or native execution.

## 2. How does guest code reach host shims?

### Current interpreter path

The M7 resolver writes deterministic synthetic dispatch values in the reserved `0x5100xxxx` range into resolved IAT slots. The deterministic backend recognizes these values as API bindings and calls the M8 marshalling bridge. The bridge:

1. identifies the exact imported DLL/export binding;
2. extracts arguments according to the per-API `MarshalPlan` and Microsoft x64 register/stack model;
3. validates and reads guest pointers through `GuestMemory`;
4. dispatches through `ApiRegistry`;
5. writes documented output buffers back through guest memory and updates the modeled return state.

The exact import identity is retained in `ExecutionRequest::api_bindings`; the execution context does not treat an arbitrary address in the synthetic range as sufficient identity. See `include/xbox2pc/execution_engine.hpp`, `src/execution_engine.cpp`, `src/execution_context.cpp:144-230`, and `src/api_compat.cpp`.

### ABI work that already exists

`src/xbox_abi.cpp:101-242` models the Microsoft x64 call layout:

- positional integer/pointer arguments use RCX, RDX, R8, R9;
- floating-point arguments use the corresponding XMM position;
- the caller reserves 32 bytes of shadow space;
- later arguments spill to stack slots;
- the modeled stack frame preserves the documented 16-byte alignment rules and return-address placement.

This is CPU-state/guest-memory preparation. It is not a native host call thunk.

### Native-path gap

A native CPU executing a guest `call [IAT]` would jump to the synthetic value in the IAT. That value is not currently an executable thunk. There is no assembly bridge that:

- saves/restores the required host callee-saved state;
- switches from the guest stack to a controlled host stack;
- maintains Microsoft x64 shadow-space and alignment requirements at the guest/host boundary;
- switches or restores GS state as needed;
- invokes the typed `ApiRegistry` implementation;
- writes results back to guest state without exposing arbitrary host pointers.

The current no-host-function-pointer rule is sound for the interpreter bridge, but native execution needs a real, executable thunk mechanism rather than reusing the interpreter's synthetic-address interception unchanged.

**Conclusion:** ABI layout and typed API dispatch exist as a model. Native thunk execution does not.

## 3. What exists for TEB/PEB, and where does GS-relative access resolve?

### Finding: no TEB or PEB implementation

The audited source has no TEB/PEB structure or per-process/per-thread allocation for those structures. In particular:

- `cpu::CpuState` contains 16 GPRs, RIP, RFLAGS, XMM registers, MXCSR, and x87 control word; it has no FS/GS base fields (`include/xbox2pc/guest_cpu_state.hpp:66-99`).
- The decoder can represent an operand's segment as `Gs` (`include/xbox2pc/x64_decoder.hpp:91-114`), but that is decode metadata, not a GS-base implementation or a memory-resolution rule.
- The deterministic backend does not implement a general segment-relative memory execution path.
- The Linux PAL exposes memory/thread primitives but no guest GS-base context API or save/restore abstraction.
- There is no `ThreadLocalStoragePointer` implementation and no `gs:[0x58]` resolution.

Therefore GS-relative access currently resolves nowhere as a guest Windows TEB access. It is not redirected to a TEB or TLS array.

### Existing TLS is not implicit Windows TLS

There are three separate pieces:

1. `decode_tls()` validates and reports PE TLS template/index/callback metadata (`src/image_loader.cpp:1226-1378`).
2. `tls_assign_index()` assigns a runtime bookkeeping index per process/image.
3. `tls_init_thread()` copies template bytes, appends zero-fill bytes, and stores the result using `RtThread::tls_set(index, ...)` (`src/gdk_services.cpp:2100-2178`).

`RtThread` stores a map from a 64-bit key to a byte vector. That is not a guest-memory TLS block referenced through a TEB. The current helper does not build the TLS pointer array at `gs:[0x58]`, and it does not write the PE TLS index slot. The loader reports per-thread template materialization as unsupported; `ExecutionContext::prepare_entry` retains the TLS index as metadata but does not allocate implicit TLS (`src/image_loader.cpp:1399-1618`, `src/execution_context.cpp:144-230`, `docs/thread-execution.md`).

M8's separate TLS callback helper invokes callbacks with reason `DLL_PROCESS_ATTACH` only. It does not implement the full process/thread attach/detach lifecycle and documented ordering. The normal loader path validates/counts callbacks but does not automatically execute the complete lifecycle.

### Last-error state

There is no TEB-backed last-error slot and no registered `SetLastError`/`GetLastError` implementation in the current API descriptor/implementation set. Error strings and typed runtime errors are internal diagnostics; they are not the Windows per-thread last-error contract.

**Conclusion:** TEB/PEB, GS-base management, implicit TLS, TLS index-slot initialization, complete callback reasons/order, and last-error APIs are all M11 work.

## 4. Handle representation across services; colliding token spaces

### M4 handle representation

`Handle` is a 64-bit token with this layout (`include/xbox2pc/handle_manager.hpp:22-55`):

| Bits | Field |
|---|---|
| 0–8 | object type |
| 9–39 | generation |
| 40–54 | slot index |
| 55–63 | table ID |

Generation checks reject stale slot reuse; table IDs prevent a token from one table resolving in another table. Each `HandleTable` has a 32K-slot maximum. There is a runtime root table and process-owned tables.

This representation is not the M11 format requirement: the object type occupies the low bits, so the raw value is not guaranteed to be a nonzero multiple of four. For example, built-in Event, Mutex, and Semaphore type IDs are 3, 4, and 5 (`include/xbox2pc/runtime_object.hpp:24-34`).

### Current service ownership is split

- Win32 synchronization objects are registered with `ObjectManager` and placed in the owning `ManagedProcess::handle_table()`. `GameRuntimeService` separately tracks `(PID, raw handle) -> object ID` for cleanup (`src/gdk_services.cpp:1199-1258)).
- Loaded images also receive a process-table handle (`src/image_loader.cpp:1570-1618`).
- Process/thread/runtime objects can use the runtime root table.
- Task queues do **not** use `HandleTable`. `TaskQueueService` assigns monotonically increasing service IDs from `next_id_`, starting at 1, and stores them in its own `queues_` map (`include/xbox2pc/gdk_services.hpp:174-220`, `src/gdk_services.cpp:1795-1837)).
- Task queues close through `XTaskQueueCloseHandle`; the current Win32 `CloseHandle` implementation only recognizes synchronization objects (`src/gdk_services.cpp:760-830)).

Consequently, numerically equal values can exist in the task-queue token space and the process handle-table token space. They are currently disambiguated by which API/service receives the value, not by one unified per-process object table.

### M11 implication

The unified table is not a small wrapper around the current maps. It must become the authoritative per-process registration/lookup/close path for synchronization objects, task queues, and later object types. The current raw encoding also needs to be reconciled with the M11 alignment requirement while preserving stale-generation and cross-process rejection.

## M11 implementation update (2026-11-24)

The baseline observations below describe the audited pre-M11 implementation.
The consolidated M11 branch now changes one Phase 7 item:

- Process-exit observers are snapshotted and pinned under
  `ProcessManager::lock_`, then invoked after releasing that lock.
- Removing an observer prevents future snapshots and waits for any already
  active callback to finish.
- A regression test verifies an observer can call `process_count()` without
  deadlocking and that unregistration drains an active callback.
- An observer must not synchronously unregister itself; that would wait for
  its own active invocation.

This does **not** complete Phase 7. The task-queue infinite-wait termination
problem described below was addressed in a later M11 implementation update:
the execution bridge now propagates the cooperative cancellation state into
API dispatch, and manual task-queue dispatch checks it on bounded 2 ms wait
intervals. A regression test covers cancellation of an otherwise idle
infinite dispatch. The global lock-order policy still needs a broader audit
and tests.

---

## 5. Lock ownership and observed lock order

There is no single global lock-order document in the current repository. The following table records the important locks and nested paths observed in the audited source. It is not a claim that every possible path has been exhaustively model-checked.

| Owner | Lock(s) | Observed nesting / notes |
|---|---|---|
| `ProcessManager` | `lock_` | Protects PID/object map, limits, and exit observers. Some paths hold it while looking up objects and querying process/address-space statistics. |
| `ManagedProcess` | `detail_lock_` | Protects module/thread lists and process suspension bookkeeping. Process transitions are routed through process-model state locks. |
| `ObjectManager` | object-map `lock_`, `drain_mutex_` | Object lookup pins under the map lock. Destruction marks the object, drops the map lock while waiting for pins, runs `on_destroy()` outside the map lock, then reacquires it to erase. |
| `HandleTable` | per-table `shared_mutex` | Protects slots/free list. Lookup releases the table lock before resolving the object ID through `ObjectManager`. |
| `AddressSpace` | `Impl::lock` | Protects the sorted region map and host protection changes. |
| `GameRuntimeService` | `state_lock_`, `sync_transaction_lock_` | State maps use `state_lock_`. Guest wait/signal/close transactions serialize through `sync_transaction_lock_`, then take individual event/mutex/semaphore locks. Some close paths hold the transaction lock while validating process/table ownership. |
| `TaskQueueService` | `lock_` + `queue_cv_` | Queue map, callback queues, and dispatch counts use one lock. Dispatch releases it before invoking a guest callback. |
| `RtThread` | `transition_lock_`, execution-gate mutex | Thread state/metadata and cooperative park/cancel state are separately synchronized. |
| Guest sync objects | per-object mutex/condition variable | Event, guest mutex, and semaphore state is protected internally; service transaction lock serializes cross-object wait-all probes with signal/release/close. |

### Important observer ordering

`ProcessManager::terminate_process` invokes process-exit observers while holding `ProcessManager::lock_` (`src/process_management.cpp:305-388`). The Game Runtime observer then takes `GameRuntimeService::state_lock_` and later destroys retired objects; the task-queue observer takes `TaskQueueService::lock_` (`src/gdk_services.cpp:851-967`, `1721-1795`, `1687-1720`).

The current contract explicitly forbids observer callbacks from re-entering `ProcessManager`; observer removal takes the same manager lock and therefore serializes with callback execution. This is a fragile global lock boundary: callbacks are required to remain short and non-reentrant.

### Observed nested orders to preserve or deliberately redesign

- Process-manager map operations can nest manager lock → object lookup/pin; process statistics can continue into address-space, process-detail, and handle-table locks.
- Process-exit notification nests ProcessManager lock → service state/queue lock → (after service map locks are released) ObjectManager destruction.
- Guest sync close nests sync-transaction lock → process lookup → process handle-table lookup/close → service state lock. Wait probes serialize sync-transaction lock → individual sync-object lock.
- Task-queue dispatch waits on its condition variable with the queue lock released by the condition-variable wait and releases the queue lock before calling the guest callback.

M11 should turn this observed order into a maintained lock-order table and move process-exit cleanup out of the ProcessManager lock as specified in Phase 7. The current callback-under-manager-lock contract should not be silently carried forward.

## 6. Process termination while a thread is blocked in a wait

### Win32 event/mutex/semaphore waits

`ProcessManager::terminate_process` transitions the process toward termination, calls `request_stop()` on each owned thread, and joins each thread with a 50 ms timeout before closing handles or releasing the address space (`src/process_management.cpp:305-367`).

`RtThread::request_stop()` sets the stop flag, cancels the cooperative execution gate, and invokes a registered cancellation waker (`src/thread_model.cpp:442-479`). The M10 Win32 wait implementation resolves the calling managed thread by PID/TID, marks it blocked, and checks its stop flag and suspension gate in bounded 2 ms wait slices (`src/gdk_services.cpp:1331-1472`). Wait-all also checks stop/suspension between bounded attempts.

For a correctly identified managed thread blocked in these specific Win32 waits, termination is expected to be observed promptly. If a thread is blocked in an operation that does not observe cancellation, or cannot be resolved to its managed `RtThread`, process termination can return a deferred error after the bounded join. In that case the process-owned handles and address space are intentionally left intact for a retry; they are not released underneath a still-running thread.

### Confirmed lifecycle defect: infinite task-queue dispatch

`TaskQueueService::dispatch` can block indefinitely in `queue_cv_.wait(lock, ready)` for an infinite timeout. Its readiness predicate is based on queued callbacks, queue termination, or loss of all public aliases. The dispatch API has no guest PID/TID cancellation parameter and does not register a managed-thread cancellation waker (`src/gdk_services.cpp:1868-1947`).

The process-exit observer that calls `TaskQueueService::release_process` is invoked only after ProcessManager has drained the process's threads and marked the process terminated (`src/process_management.cpp:305-367`, `src/gdk_services.cpp:1753-1763`). Therefore a managed guest thread blocked in infinite `XTaskQueueDispatch` can prevent the process from reaching the observer that would terminate the queue and wake that dispatch. The current test `ProcessExitReleasesDuplicatedTaskQueueAndWakesDispatch` uses a separate host `std::thread` waiter, not a managed process-owned guest thread (`tests/api_compat_test.cpp:1384-1426)); it does not cover this cycle.

**Conclusion:** the M11 termination test must cover every blocking guest-facing service, not only `WaitForSingleObject`. Task-queue dispatch needs a pre-teardown cancellation/wake path or another lifecycle arrangement that breaks the cycle without freeing guest state early.

**Update (2026-11-24, M11 branch):** the task-queue dispatch cancellation gap
described above has been addressed. The execution bridge propagates the
managed execution gate's cancellation predicate into API dispatch through
`ApiContext`, and manual task-queue dispatch checks it during bounded 2 ms
wait intervals. Cancellation returns a typed `ThreadTerminated` result so the
guest execution path unwinds and ProcessManager can complete its join. This
is polling rather than a registered task-queue waker; wake latency is bounded
by the polling interval.

**Remaining validation:** the dedicated idle/infinite-dispatch cancellation
regression exists. It still needs confirmation on the current CI run and
end-to-end stress coverage under TSAN.


## 7. Loader performance and memory at ~600k relocations and ~180 MB images

### Current bounds and data flow

- The loader caps image size at 256 MiB and relocation count at 1 Mi entries (`include/xbox2pc/image_loader.hpp:69-83`). A 180 MB image and 600k relocations are therefore within current configured structural bounds.
- `ImageLoader::load_image` receives the complete file buffer, validates it, maps headers and sections, copies section bytes into the process AddressSpace, decodes/applies relocations if rebased, resolves imports, decodes TLS, and registers a loaded-image object (`src/image_loader.cpp:1399-1618`).
- `AddressSpace` owns one host PAL mapping per process. The Linux PAL reserves it with `mmap(nullptr, ...)`; guest Xbox VAs are logical coordinates. `AddressSpace::translate()` converts a guest VA into a different host pointer within that backing mapping (`src/memory_management.cpp:117-139,709-726`, `src/pal_linux.cpp` memory-region implementation).
- Mapping touches pages by zeroing section extents and copying raw section data. Thus a large loaded image requires the original file buffer plus populated guest backing pages and loader metadata. The exact resident peak has not been measured for a 180 MB fixture.

### Confirmed relocation hot path

`decode_relocations()` builds a vector of relocation blocks, each containing a dynamically grown vector of entries (`src/image_loader.cpp:433-512`). It does not pre-size the entry storage from a validated count.

For every DIR64 entry, `apply_relocations()`:

1. linearly scans `layout.sections` to find the target section;
2. checks the original `host->protection` value;
3. for a section whose original protection is not writable, calls `protect_region(..., ReadWrite)` and appends another entry to `flipped`;
4. calls `apply_dir64()`, which resolves the target through `AddressSpace::translate()`;
5. after the loop, restores every recorded protection in reverse order.

The test of `host->protection` is against the original layout value, not a tracked “already flipped” set. Therefore a read-only or executable section receiving many relocations can be toggled RX/RO → RW repeatedly once per relocation, and the `flipped` vector can contain repeated entries for the same section. This is a concrete scalability problem for hundreds of thousands of relocations, not merely an unmeasured concern (`src/image_loader.cpp:867-953`).

The per-entry section scan is O(relocations × section-count). The per-entry translate also performs an AddressSpace region lookup. The decode stage retains all relocation entries in vectors at once.

### Benchmark coverage gap

`tests/loader_bench.cpp` describes a small synthetic image and relocation benchmark. The fixture creates two relocation blocks with 32 entries each (64 entries total), despite the nearby comment describing 96 entries. It does not benchmark 600k relocations or an image near 180 MB. No audited benchmark result establishes load time, peak RSS, allocation count, or protection-call count at the M11 target scale.

### Native execution makes the address model a blocker too

The current host mapping is not located at the logical guest VA. The guest CPU model's RIP and pointers are guest coordinates, while `translate()` returns a separate host pointer. A native CPU cannot fetch instructions from the logical guest RIP unless the memory architecture is extended to provide executable mappings at the guest addresses (or a deliberately designed equivalent mapping strategy). The current loader's relocation delta is based on the logical guest image base, not the unrelated host mmap address.

**Conclusion:** do not infer that the current loader is ready for a 180 MB native image. First add representative large-image measurements and fix the per-relocation protection churn. Native execution also requires reconciling the logical guest-VA/host-mmap split with M4 ownership rather than introducing a second memory manager.

---

## Phase 0 decision record

The audit supports the following constraints for later M11 design work; it does not implement them:

1. Keep the deterministic interpreter as a bounded test oracle/tracing backend. Do not expand its ISA merely to avoid using the native x86-64 host.
2. A native backend cannot be connected safely until guest VA mapping, GS-base switching, native API thunks, and host-fault containment are specified together.
3. Reuse M4's process/thread/handle/address-space owners. Do not add parallel TEB, handle, or memory ownership registries that can diverge from those managers.
4. Treat the infinite task-queue dispatch termination cycle as an existing defect to fix in the lifecycle slice.
5. Make large-relocation and large-image benchmarks part of the loader work before claiming the 600k/180 MB target.
6. Keep unsupported APIs and platform imports explicitly unsupported/partial until their behavior and tests exist.

**No feature code was changed during Phase 0.** The “what broke in M1–M10” deliverable remains a separate final-audit artifact and should be based on confirmed defects and their fixing commits, not reconstructed from memory.

---

### TLS callback validation hardening (2026-11-24)

The M11 follow-up now rejects the complete TLS callback plan if any non-null callback VA is not executable mapped guest memory. The previous behavior counted and skipped invalid entries, which could silently run a partial callback sequence and leave module initialization inconsistent. A regression test covers a readable callback array containing a non-executable target. This does not complete automatic process/thread attach-detach lifecycle wiring; callback execution is still an explicit helper and must be integrated by the process/thread lifecycle owner.


### TEB-backed last-error APIs (2026-11-24)

The M11 branch now registers `kernel32!SetLastError` and
`kernel32!GetLastError` implementations. They use the per-call
`ApiContext` accessors wired by the execution engine to the calling
`GuestThreadEnvironment`; calls without an initialized guest TEB are
rejected instead of silently using process-global or host-thread state.
The descriptors are marked fully implemented for this modeled per-thread
contract, and dispatch tests verify independent values for two guest threads
plus rejection when no TEB-backed accessors are supplied. This does not imply
that native GS-relative guest execution is implemented.
