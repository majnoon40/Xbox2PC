# M3 — Process & Thread Model

## RtProcess (`process_model.*`)

An abstract Xbox-style process: a runtime object aggregating

| Member | Content |
|---|---|
| `pid` | unique uint64 (per-run counter; never 0) |
| lifecycle state | validated state machine (below) |
| executable metadata | `ModuleDescriptor` (M1/M2 integration, below) |
| runtime config | `RuntimeConfig` (subsystem, image base/size, handle cap, module-load policy) |
| memory-space interface | attached region list (id + label) |
| thread collection | registered thread object ids |
| handle table | per-process `HandleTable` |
| loaded modules | `ModuleDescriptor` vector (dependencies) |
| process services | name → object-id map |

### Process state machine

```
Created ──initialize──> Initializing ──run──> Running ──suspend/resume──> …
   │                        │                    │
   │                        │                    ├──terminate──> Terminating ──> Terminated
   └───────fail──────> Failed <──────fail───────┘
```

Transitions are table-validated (`process_transition_valid`, exposed for
tests); every illegal call returns `InvalidTransition` with a context
naming both states. `resume()` is **only** the inverse of `suspend()`
(`run()` covers Initializing→Running). `terminate()` closes the process
handle table and records the exit code; Terminated→Terminated is
idempotent. `fail(reason)` is reachable from any non-terminal state.

### M1/M2 metadata integration (no duplication)

`ModuleDescriptor::from_image(PeImage, DependencyReport, name)` copies the
*parsed facts* — machine, PE32+ flag, entry RVA, image base/size,
subsystem, section names, imported/DLL lists, delay-load lists,
forwarded exports, per-DLL M2 classification — into plain metadata
vectors. The parser and analyzer stay authoritative; the runtime never
re-parses or re-analyzes. A process receives the descriptor via
`initialize()`, dependencies via `add_loaded_module()`. **No mapping,
relocation, import resolution or execution happens in M3** — the
metadata is data only.

### Interaction with object manager / runtime core

- `RuntimeCore::create_process` registers the object in the runtime
  manager and returns a handle; all access goes through handle→manager.
- The process's own handle table resolves ids via the global manager
  (processes do not own threads' lifetimes).
- `on_destroy()` closes the table and records
  `destroyed-without-terminate` metadata when a non-terminated process
  is destroyed (teardown facts are never silently dropped).

## RtThread (`thread_model.*`)

An abstract thread wrapping a PAL host thread:

| Member | Content |
|---|---|
| `thread_id` | unique uint64 runtime id (host pthread id is backend metadata only) |
| state | validated machine (below) |
| scheduling | `ThreadScheduling` — abstract priority enum, ideal-processor and quantum hints (informational; **no scheduler in M3**) |
| TLS | per-thread slot map (uint64 key → bytes), key 0 reserved |
| exit status | exit code + exited flag (written once at termination) |
| sync integration | `block_note()`/`unblock_note()` for wait paths |

### Thread state machine

```
Created ──start──> Ready ──(dispatch)──> Running ──{block, suspend, yield}──> …
                     │                      │
                     ├──suspend/resume──────┤
                     │                      ├──terminate──> Terminated
   any pre-terminal ──fail──────> Failed    └──blocked──> (reacquire) ──> Running
```

`start()` spawns the PAL host thread (a gated trampoline eliminates the
classic pthread_create torn-read race — see
[platform-abstraction.md](platform-abstraction.md)). Join is exact-once
infinite or a bounded poll (host joins have no timeout). Terminate is
cooperative: M3 **never kills** host threads; `on_destroy()` requests a
stop and detaches if a thread was left running.

### Scheduling disclaimer

Priority is an **abstraction** (Idle/Low/Normal/High/Critical +
ideal-processor/quantum hints, stored, never enforced). M3 implements no
scheduler and does not model undocumented Xbox scheduling internals —
the host OS schedules PAL threads.

## Synchronization model (`sync_objects.*`)

Platform-independent runtime objects over PAL primitives; every value is
a `RuntimeObject` (manager-tracked, handle-issuable).

| Primitive | Semantics (deviations from naive implementations are deliberate) |
|---|---|
| `RtEvent` auto-reset | `set` wakes **one** waiter; the waiter **consumes** the signal (auto-resets); manual-reset wakes **all** and stays set until `reset()` |
| `RtEvent` timeout | `wait_ns(0)` = immediate check; `< 0` = infinite; else waits up to the deadline then `Timeout` |
| `RtMutex` | plain ownership; unlock by non-owner → `LockNotOwned` (detected **before** pthread is touched — see PAL doc); `try_lock` → `Timeout` when held |
| `RtSemaphore` | counting with explicit max; `release` past max → `InvalidState` (never silent saturation) |
| `RtCondvar` | pairs with a specific `RtMutex`; predicate loops guard spurious wakeups; waits relock the mutex (timeout path included) |

Destruction-while-waiting: `on_destroy()` hooks **wake remaining
waiters** (event set / semaphore release / condvar broadcast) so destroy()
cannot hang on PAL internals; woken waiters observe the Destroying state
through their guards and return typed errors.

Timeouts verified behaviorally: tests assert both the returned
`Timeout` code **and** elapsed wall time (e.g. ≥ 40 ms of a 50 ms
deadline).

## Confirmed vs inferred

Confirmed (public evidence):
- Win32 process/thread states and suspend/resume semantics exist as
  public concepts —
  https://learn.microsoft.com/en-us/windows/win32/procthread/processes-and-threads
- Synchronization primitives (events, mutexes, semaphores) are Win32
  kernel objects with signaling semantics —
  https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-objects
- Xbox titles run PE32+ images (parser facts feed the module
  descriptor) —
  https://learn.microsoft.com/en-us/gaming/gdk/content-certification

Inferred (architectural; Xbox Game OS process/thread internals are
proprietary and NOT reverse-engineered):
- the exact state sets and transition tables,
- per-process thread registry as object-id lists,
- TLS as a runtime-level slot map,
- process-local service map topology.
