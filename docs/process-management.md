# M4 — Process Management

## Responsibility

`process_management.hpp/.cpp` (library `xbox2pc_rt_procman`) turn the M3
process model into a functioning manager: `ProcessManager` drives creation,
initialization, startup, suspension, termination, thread spawning and
per-process memory through `ManagedProcess` objects, with resource
accounting and limits.

## Lifecycle (driven by ProcessManager)

```
create_process   -> Created   (object registered, AddressSpace allocated;
                                failure rolls back registration — no leaks)
initialize_process -> Initializing (M1/M2 ModuleDescriptor + RuntimeConfig fed;
                                failure rolls back: fail() + space release_all)
start_process    -> Running   (Created start = typed InvalidTransition)
suspend_process  -> Suspended (cooperative stop on owned threads)
resume_process    -> Running
terminate_process -> Terminated (EXACT cleanup ordering, below)
```

### Cleanup ordering (deterministic, tested)

`terminate_process(exit_code)` runs, in order:

1. **request_stop** on every owned thread (cooperative; never kill);
2. **bounded drain** — completed threads join instantly; running ones get
   up to 50 ms to observe the stop (they stay runnable; the
   never-force-kill rule);
3. **handle table close_all** — every process handle dies together;
4. **address space release_all** — all regions gone, backing to PROT_NONE;
5. **thread unregistration** — the process's thread list cleared (thread
   OBJECTS stay in the object manager; their handles are caller-owned);
6. **terminate(exit_code)** — state Terminated, exit code recorded.

Idempotent: `Terminated -> Terminated` is legal. `ProcessManager`'s
destructor terminates every remaining process (deterministic teardown;
`RuntimeShutdownWithActiveResources` proves no hangs/leaks with live
threads + regions at destruction).

### Failure rollback

- `create_process`: registration → handle issuance; any failure destroys
  the object and unmaps the space — **no partial leaks**.
- `initialize_process`: descriptor rejection fails the process AND
  releases the space (partial init must not leak regions or metadata).

## M3 state-machine change (documented)

`Created -> Terminating` and `Initializing -> Terminating` are now legal
(previously only Running/Suspended could terminate). Rationale: M4
requires ANY pre-terminal process to be terminable with deterministic
cleanup — terminating a partially initialized process is exactly the
failure-rollback path. `process_transition_valid()` covers it; the M3
suite (52 tests) still passes unchanged.

## Threads per process

`spawn_thread(process, main, arg, name)`: registers the `RtThread`
object, attaches it to the process, starts the host thread, issues a
runtime-table handle; any failure rolls back all of the above. Join
semantics, exception containment, cancellation and TLS are the thread
layer's (see [thread-execution.md](thread-execution.md)).

## Memory per process

`reserve/commit/protect/release_region(process, ...)` route through the
process's own `AddressSpace` (isolation in
[address-spaces.md](address-spaces.md)); `protect_region` additionally
enforces the global W^X policy (`allow_wx_pages`).

## Integration with M1/M2/M3

`initialize_process` consumes M3's `ModuleDescriptor` (built from M1's
`PeImage` + M2's `DependencyReport` via `ModuleDescriptor::from_image`)
— the same metadata pipeline as M3, now driving a managed process with
an image-sized reserved region (`IntegrationM4Test`). M4 does NOT map,
relocate, or execute anything (explicit exclusion).

## Known limitations

- Termination's thread drain is bounded at 50 ms per thread: a thread
  stuck in a non-cancellation-aware host wait stays runnable; its object
  remains valid (documented never-kill rule, recorded in metadata).
- No cross-process IPC or handle inheritance at spawn (inheritance
  metadata exists on handles — see
  [handle-security.md](handle-security.md) — but no spawn-time copying).
- `suspend_process` is cooperative: it does not freeze threads mid-host-
  call; the state machine records Suspended immediately and threads
  observe the stop at their safe points.

## Confirmed vs inferred

Confirmed (cited): Win32 process/thread lifecycle concepts as public
reference points —
https://learn.microsoft.com/en-us/windows/win32/procthread/processes-and-threads

Inferred (xbox2pc design): the cleanup ordering (1–6), rollback
contracts, the M3-table extension above, per-process thread registry
semantics. Xbox Game OS process internals are proprietary and NOT
reproduced.
