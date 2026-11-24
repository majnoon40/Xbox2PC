# M11 baseline audit

**Audit scope:** Phase 0 only. Source inspection of the merged `main` at
`5dcda95b2620530c89ad0cb1ebb250cbae078cf4` (M10 merge commit), dated
2026-11-23. No feature code is included in this slice.

**Method:** Findings below are based on the implementation and tests present
at that revision. This is a source audit, not a fresh local build or a
benchmark run. Source pointers below identify the relevant implementation areas at this
baseline commit; line numbers may move as M11 changes the source.

## Executive summary

M10 provides useful process, thread, address-space, synchronization, API
marshalling, and task-queue foundations. It does **not** yet provide a
general-purpose Windows x64 process environment or an end-to-end native PE
runner.

The current execution backend is an interpreter over a modeled guest address
space. API imports are represented by synthetic guest dispatch addresses and
handled by the interpreter's marshalling bridge. The runtime has no TEB/PEB,
no guest GS-base setup, no implicit loader-managed TLS, no Windows SEH
unwinder, and no single guest-visible handle namespace spanning all services.

A notable lifecycle gap is also visible: Win32 event/mutex/semaphore waits poll
for managed-thread cancellation, but an infinite manual task-queue dispatch
wait is not cancellation-aware. Process-exit observers that release queues run
only after ProcessManager has joined the process's threads. A thread blocked in
that dispatch can therefore prevent the cleanup callback that would wake it.

These findings support investigating native execution as the primary x86-64
path, but they do not by themselves settle the native execution design.

---

## 1. Can a current backend run a PE from entry to exit?

**Answer: only a restricted, explicitly driven PE execution path exists. There
is no general native PE runner.**

Evidence:

- `src/execution_engine.cpp` implements `DeterministicBackend` as an
  interpreter loop. It checks a bounded execution budget, asks the x86
  interpreter to execute one instruction, and handles guest faults as
  structured `ExecutionResult` values. The code constructs
  `x86::Interpreter` and calls `step_at_rip()`; it does not transfer control
  to native guest instructions.
- The interpreter's supported instruction set is deliberately bounded.
  Unsupported instructions produce guest faults. AVX/VEX/EVEX and broad
  architectural coverage are not a goal of this backend.
- `ExecutionContext::prepare_entry` in
  `src/execution_context.cpp` validates a loaded image's entry point,
  prepares the Microsoft x64 entry stack, installs a completion sentinel, and
  records resolved import bindings. `invoke()` then calls the selected
  `IExecutionEngine`. This is a runtime/test API, not a command-line PE
  process runner.
- Imported calls are intercepted when RIP equals a synthetic API-binding
  address. The bridge resolves the import identity, extracts arguments,
  validates guest pointers, dispatches through `ApiRegistry`, and resumes at
  the guest return address. See `src/execution_engine.cpp` and
  `src/execution_context.cpp`.
- The PE loader maps images, applies the currently supported relocation subset,
  resolves imports, and creates loader objects. Loading/preparing an image is
  not equivalent to executing an arbitrary Windows program. See
  `src/image_loader.cpp`.
- Existing execution tests exercise bounded guest snippets and synthetic PE
  fixtures; they do not demonstrate an independently built Windows PE
  completing a normal process lifecycle through a user-facing `run` command.
- The M10 API surface does not yet cover all calls in the proposed Phase 1
  fixture. In particular, this revision has no registered
  `SetLastError`, `GetLastError`, or `ExitProcess` implementation. The
  existing TLS helper is explicit rather than automatic (see section 3).

**Conclusion:** A synthetic PE can be loaded and a restricted entry path can
be driven through the interpreter where its instructions and imports are
supported. The current tree does not establish that a freestanding Windows
PE can run from its real entry point to process exit. There is no native
backend or `xbox2pc run` implementation at this baseline.

## 2. How does guest code reach host shims?

**Answer: through synthetic API-binding addresses and an interpreter-side
marshalling bridge, not through native executable thunks.**

Current path:

1. The loader resolves imports and records their library/export identity.
2. `ExecutionContext::prepare_entry` assigns the resolved imports synthetic
   API-binding addresses in the execution request.
3. The interpreter recognizes a binding address as a special dispatch point.
4. The bridge reads the guest return address from `[RSP]`, extracts arguments
   according to the call's ABI plan, validates pointer ranges through
   `GuestMemory`, and invokes the registered host implementation.
5. The interpreter resumes at the guest return address.

Relevant implementation: `src/execution_context.cpp`,
`src/execution_engine.cpp`, `src/xbox_abi.cpp`, and
`src/guest_memory.cpp`.

The existing ABI model covers important Microsoft x64 mechanics:

- Integer arguments in RCX, RDX, R8, and R9.
- Floating-point arguments in XMM0–XMM3 according to argument position.
- 32-byte shadow space.
- Stack arguments after the return-address and shadow-space area.
- 16-byte call-frame alignment and an 8-byte return-address slot at callee
  entry.
- Return values through the modeled CPU state.

The ABI code prepares and extracts a **modeled** CPU/guest stack frame. It does
not provide a native assembly thunk that switches from executing guest code
to a host C++ shim while preserving host callee-saved registers, stack
alignment, shadow space, floating-point state, and exception boundaries.

Guest pointers are guest virtual addresses, not host pointers. The current
bridge uses `GuestMemory` to validate and copy data through the M4
`AddressSpace`; this is an important boundary to preserve for native shims.

**Conclusion:** The current shim mechanism is interpreter-specific. Native
execution will need an actual ABI transition path; the existing marshalling
plans and pointer bridge are reusable concepts, not an already implemented
native thunk layer.

## 3. What exists for TEB/PEB, and where does GS-relative access resolve?

**Answer: no TEB/PEB implementation or guest GS-base setup was found.**

- There are no guest TEB or PEB structures allocated in each process/thread's
  M4 address space.
- There is no code setting or retrieving a guest GS base. The source search
  found no `ARCH_SET_GS`, `wrgsbase`, or equivalent GS-base implementation.
- There is no mapping for `gs:[0x30]`, `gs:[0x60]`, or
  `gs:[0x58]`; guest GS-relative loads therefore have no Windows TEB
  semantics in the current runtime.
- `ExecutionContext::Info` records process/thread identity, stack bounds,
  and the image TLS index, but it is not a TEB.
- M7/M10 TLS support consists of `tls_assign_index` and the explicit
  `tls_init_thread` helper in `src/gdk_services.cpp`. It copies a module's
  TLS template and zero-fill into an `RtThread` TLS slot. It does not build
  the Windows TLS pointer array at `gs:[0x58]`, install a TEB, or make
  compiler-generated Windows TLS access work automatically.
- `docs/thread-execution.md` explicitly describes TLS materialization as the
  explicit `api::tls_init_thread` operation and says implicit loader-side TLS
  allocation is not claimed.
- TLS callback execution exists as a separately invoked execution operation;
  it is not proof that the complete Windows process/thread TLS lifecycle is
  automatically driven by the loader.

**Conclusion:** The proposed TEB/PEB and implicit TLS work is new
functionality, not a small extension of an existing GS implementation.

## 4. Handle representation across services; colliding token spaces?

**Answer: M4 has generation-checked per-table handles, but the guest-facing
service surface is not unified.**

M4 `Handle` is a 64-bit encoded token. At this revision it contains:

- 9 low bits for object type,
- 31 bits for generation,
- 15 bits for slot index,
- 9 high bits for table ID.

`HandleTable` validates the owning table, slot, generation, and object type.
Closing a slot advances its generation, so stale handles are rejected.
Processes own their own M4 handle tables. See
`include/xbox2pc/handle_manager.hpp` and `src/handle_manager.cpp`.

M10 guest synchronization objects (events, mutexes, semaphores) are registered
in the owning process's M4 `HandleTable`. Their raw encoded values are
validated against that process table. The registered `CloseHandle`
implementation currently dispatches only to the synchronization-object close
path. It is not a general object-type dispatcher.

Task queues use a separate namespace:

- `TaskQueueService::next_id_` issues monotonically increasing 64-bit IDs.
- The queue map is keyed by those IDs and stores shared queue objects.
- Duplicate queue handles are new IDs referring to the same shared queue.
- `XTaskQueueCloseHandle` closes those IDs through TaskQueueService.
- These IDs do not use M4 `HandleTable` slots, generation checks, or the
  M4 table ID.

The task-queue counter currently starts at small values, while normal
generation-encoded M4 handles have generation bits set. No immediate numeric
collision is demonstrated by the current allocation sequence. However, they
are separate token spaces with no global uniqueness contract. Treating both
as interchangeable Windows `HANDLE` values, or adding generic
`CloseHandle` dispatch without first unifying the representation, would be
unsafe.

The M4 encoding also does not implement the M11 proposal's explicit
nonzero-multiple-of-four guest handle encoding. Its generation protection is
useful and should not be confused with that requested guest ABI.

**Conclusion:** There is a reusable M4 object/handle manager, but Phase 3
requires a guest-visible unified namespace and type-directed close semantics.
It should not create a second independent owner of object lifetime.

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

## 5. Lock order across ProcessManager, services, and observers

**Answer: locks are locally scoped and several nested orders can be observed,
but there is no single documented global lock-order contract.**

The following table records the principal locks and observed nesting. It is
not a claim that every possible path has been exhaustively proven deadlock-free.

| Lock / owner | Protects | Observed interactions / cautions |
|---|---|---|
| `ProcessManager::lock_` | PID/object map, pending thread count, exit-observer registry | Termination takes this lock while invoking exit observers. Observer callbacks therefore execute under this lock and must not re-enter ProcessManager, as the public header explicitly states. |
| `ManagedProcess::detail_lock_` | Thread and module lists; process-suspended thread IDs | Thread IDs are generally snapshotted and the lock released before object lookup/join. |
| `ObjectManager` internal lock | Runtime-object registry and lookup/destruction | Used to pin process/thread/sync objects. RefGuards keep objects alive across operations. |
| Per-process `HandleTable::lock_` | Handle slots, generations, rights | Sync-handle lookup/close reaches this table after resolving the owning process. |
| `AddressSpace::Impl::lock` | Guest VM region map and backing protection transitions | Region metadata changes and PAL protection operations are serialized here. |
| `GameRuntimeService::sync_transaction_lock_` | Multi-object wait transactions and sync close/set/reset operations | Some operations first resolve a process-owned handle; wait-all coordinates several object acquisitions under this transaction lock. |
| `GameRuntimeService::state_lock_` | Service-side process/TLS/sync-object bookkeeping | The process-exit observer acquires it, removes process state, then destroys objects after releasing it. |
| Sync-object internal locks | Event, mutex, semaphore state and wait conditions | Wait paths poll/cancel and interact with these objects; wait-all must keep its transaction/rollback discipline consistent. |
| `TaskQueueService::lock_` | Queue map, callback queues, dispatch counts, termination state | Dispatch waits on `queue_cv_`; it unlocks before invoking a guest callback. Process-exit observer cleanup takes this lock. |
| `RtThread` transition/gate locks | Thread state and cooperative execution gate | Process termination requests stop/cancel and joins threads before resource teardown. |

Important observer behavior:

- `ProcessManager::terminate_process` stops and joins threads, closes the
  process handle table, releases guest memory, detaches threads, and marks the
  process terminated before it invokes observers.
- It invokes observers while holding `ProcessManager::lock_` to serialize
  callback execution with observer removal.
- `GameRuntimeService::release_process` and
  `TaskQueueService::release_process` acquire their respective service locks.
- The header contract requires observers to be short, non-throwing, and
  non-reentrant with respect to ProcessManager.

An easily missed naming detail: `ProcessManager::find_locked` does not
actually acquire `ProcessManager::lock_`; it resolves the process through
`ObjectManager::lookup_handle`. Do not infer a lock acquisition from that
helper's name.

**Conclusion:** M11 Phase 7 should establish and test a real global lock-order
policy. In particular, observer callbacks should not perform substantial
cleanup while holding the ProcessManager lock. The M11 plan's enqueue-PID,
cleanup-outside-manager-lock approach addresses this risk, but is not
implemented at this baseline.

## 6. What happens if a process terminates while a thread is blocked in a wait?

**Answer: Win32 synchronization waits are designed to observe cancellation;
task-queue dispatch has a significant cancellation gap.**

For Win32 synchronization objects:

- `ProcessManager::terminate_process` calls `request_stop()` on each owned
  thread before joining it.
- `RtThread::request_stop` sets the stop flag, cancels the cooperative
  execution gate, and invokes a registered cancellation waker when present.
- `GameRuntimeService::wait_object` resolves the managed guest thread,
  marks it Blocked when appropriate, checks the stop flag, and uses bounded
  wait slices for events, mutexes, and semaphores. The wait returns a
  thread-termination error when cancellation is observed.
- Process termination then joins each thread with a 50 ms attempt. If a thread
  has not exited, termination returns a deferred/timeout error and leaves
  process handles and guest memory intact for a retry. It does not continue
  tearing down memory underneath a live thread.
- Process-exit observers run only after the join and teardown succeed.

For task queues:

- `TaskQueueService::dispatch` can wait on `queue_cv_` for an infinite
  timeout. Its predicate checks for queued callbacks, queue termination, or
  loss of all public handles.
- The dispatch wait does not take the guest thread's stop token or register a
  cancellation waker.
- The process-exit observer that calls `TaskQueueService::release_process`
  runs only after ProcessManager has joined all process threads.
- Therefore, if a process thread is blocked indefinitely in task-queue
  dispatch with no callback arriving, termination may wait for that thread;
  the observer that would terminate and notify the queue cannot run until
  after the join. The 50 ms join attempt can return deferred, leaving the
  process in Terminating until the blocked dispatch is independently woken.

**Conclusion:** The M11 Phase 7 infinite-`WaitForSingleObject` test should be
supported by the existing cancellation polling, but it still needs an
end-to-end regression test under TSAN. The task-queue dispatch cancellation
cycle is a concrete defect to fix: process termination must wake it before
joining, or dispatch must observe the managed thread's cancellation state.

## 7. Loader performance and memory at ~600k relocations / ~180 MB images

**Answer: the code has bounded parsing and a contiguous backing mapping, but
there is no demonstrated benchmark at the proposed scale. The current
algorithm has a likely scaling hotspot.**

Memory layout:

- Each M4 `AddressSpace` reserves one host backing mapping for its configured
  capacity. Guest Xbox virtual addresses are translated to offsets within this
  host mapping; they are not directly mapped at their guest numeric address.
- The Linux PAL uses `mmap(nullptr, ...)` and applies per-range
  `mprotect`. It does not request a fixed mapping at the guest VA.
- The default `ProcessManager::create_process` address-space capacity is
  16 MiB. A roughly 180 MB image therefore requires an explicitly larger
  process capacity before section/header reservations and other allocations
  can fit.
- The loader reserves/maps image headers and sections into the existing
  address space. It does not create a native host mapping that makes guest
  addresses directly executable as-is.

Relocation behavior:

- `decode_relocations` walks the relocation directory and materializes a
  `std::vector<RelocBlock>`, with a nested vector of entries in each block.
  It enforces `limits_.max_relocations`, so parsing is bounded, but all
  decoded entries remain resident until application completes.
- `apply_relocations` validates supported relocation types before writes.
  At this revision, only ABSOLUTE padding and DIR64 are accepted; other types
  are rejected.
- For each DIR64 relocation, it linearly scans `layout.sections` to find
  the section containing the target. At approximately 600,000 entries, this
  is O(relocations × section-count) section checks, rather than a single
  indexed lookup per entry.
- The relocation path also records sections whose protection was changed so
  that protections can be restored. The image mapping itself consumes the
  process's configured backing capacity; committed pages and relocation
  metadata add further memory cost.
- A loader benchmark source exists, but this audit found no recorded result
  demonstrating a 180 MB image or approximately 600,000 relocations. No
  measured peak RSS, load time, relocation throughput, or allocation profile
  is available at this baseline.

**Conclusion:** Before claiming support for this scale, add reproducible
synthetic stress fixtures and measure peak memory and load time. The
per-relocation linear section scan is the first algorithmic hotspot to
profile. The guest-to-host address translation model is also a major
architectural constraint for direct native execution: the current guest VA
space is an abstraction over a separate host mapping.

---

## Phase 0 findings and implications

1. **Native execution is absent.** The current backend is an interpreter and
   synthetic API dispatch system.
2. **ABI marshalling exists, native thunks do not.** Preserve the M8
   validation/marshalling boundary while designing a real host transition.
3. **Windows thread/process environment is absent.** TEB/PEB, GS-relative
   addressing, implicit TLS, and automatic TLS callback lifecycle must be
   added.
4. **Guest handles are split across services.** The M4 handle table is a
   strong foundation, but task queues remain outside its namespace and
   `CloseHandle` is synchronization-only.
5. **Global lock ordering is undocumented.** Observer callbacks run under the
   ProcessManager lock; Phase 7 should move cleanup outside that lock.
6. **Task-queue waits are not termination-aware.** This is a concrete lifecycle
   issue; Win32 synchronization waits already have cooperative cancellation
   polling but need end-to-end validation.
7. **Large-image performance is unproven.** The relocation decoder retains
   all entries and application linearly scans sections for each relocation.

No feature-code or native-execution architecture decision is made by this
audit. Phase 1 test binaries and measurements should expose the remaining
behavioral gaps before the native execution design is finalized.


## Source map (line numbers at the audited M10 commit)

| Audit question | Primary source locations |
|---|---|
| PE load and execution | `src/image_loader.cpp:1399–1535`; `src/execution_context.cpp:144–235, 253–330`; `src/execution_engine.cpp:132–325` |
| API shims and ABI | `src/execution_engine.cpp:180–325, 444–560`; `src/xbox_abi.cpp:131–243, 245–310`; `src/guest_memory.cpp:1–160` |
| TEB/PEB and TLS | `src/gdk_services.cpp:2103–2185`; `docs/thread-execution.md:67–80`; the audit found no TEB/PEB or GS-base implementation |
| Handle representation | `include/xbox2pc/handle_manager.hpp:1–70`; `src/handle_manager.cpp:68–245`; `src/gdk_services.cpp:1199–1259, 1657–1698, 1795–1838` |
| Locks and observers | `include/xbox2pc/process_management.hpp:145–160`; `src/process_management.cpp:305–405, 844–850`; `include/xbox2pc/gdk_services.hpp:152–164, 220–240` |
| Wait termination | `src/gdk_services.cpp:1331–1650, 1868–1975, 1996–2023`; `src/process_management.cpp:305–368`; `src/thread_model.cpp:442–456` |
| Loader scale and memory | `src/image_loader.cpp:433–555, 867–950, 1399–1535`; `src/memory_management.cpp:117–315, 709–755`; `src/pal_linux.cpp:577–650` |

The absence findings are repository-wide source searches at the audited commit,
not claims inferred from a single missing declaration. In particular, searches
for `ARCH_SET_GS`, `wrgsbase`, `RtlLookupFunctionEntry`,
`RtlVirtualUnwind`, `SetLastError`, `GetLastError`, and `ExitProcess`
found no runtime implementations at this baseline.
