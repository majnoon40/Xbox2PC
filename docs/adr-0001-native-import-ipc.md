# ADR-0001: Native-backend import-call IPC design

- Status: Accepted
- Date: 2026-11-25
- Context: M11 Phase 5 (native execution with guest imports)
- Deciders: xbox2pc runtime work

## Context

The native execution backend (M11.5 first slice) runs guest entrypoints in a
forked child process. Phase 5 adds guest-visible imports: when the child hits
a thunked import (e.g. `ExitProcess`, `RaiseException`, `GetLastError`), the
call must round-trip to the parent runtime, which dispatches through the M7
`ApiRegistry` (the only sanctioned dispatch path — no host function pointers
are ever exposed to guest memory) and returns the result to the child.

Two candidate transports:

**A. Pipe pair** — child `write()`s a fixed-size request record on a pipe,
blocks in `read()` on the reply pipe; the parent does the mirror image.
Every call is two context switches plus two kernel copies of 64–256 bytes.

**B. Shared-memory ring + eventfd doorbells** — an `mmap(MAP_SHARED)` ring
of N request/reply slots; sequence counters carry ordering (release/acquire);
an eventfd per direction wakes the parked side. The data path is pure
userspace; only the wake crosses the kernel.

The requirement that decides between them: import-call *latency* under
single-threaded ping-pong (the child cannot continue until the reply
arrives; this is the exact pattern of a guest import call).

## Decision drivers

1. Round-trip latency (calls/sec) under single-threaded ping-pong.
2. Determinism: 100 consecutive runs of the same sample must behave
   identically (no timer-dependent protocol paths).
3. Robustness under the M11 sanitizers (TSan runs the parent; the child is
   outside TSan's view, but the protocol must be data-race-free by design).
4. Recovery: a child that dies mid-call must not wedge the parent.

## Measurements

Microbenchmark: `scripts/ipc_bench.c` (this repo, Phase 5 prerequisite),
500,000 round trips per design per pass, 64-byte payload both ways,
forked child, single-core ping-pong, 2-core CI-class sandbox machine
(`gcc -O2`, Linux 5.10):

| Design | pass 1 (calls/sec) | pass 2 (calls/sec) | Best |
|---|---|---|---|
| A. pipe | 98,773 | 89,203 | ~98.8K |
| B. ring + park (eventfd) | 96,584 | 92,168 | ~96.6K |
| B'. ring + host spin-then-park (~20–30 µs spin window) | 143,277 | 128,320 | ~143.3K |

Earlier 200K-round runs showed the same ordering (pipe 94–106K, ring+park
90–103K, ring+spin 119–143K).

Reading of the numbers:

- Plain pipe vs. parked ring are **within noise of each other** (~90–100K);
  the round trip is dominated by the two context switches, not the data
  path. A ring that still parks on every call buys nothing.
- The **spin-then-park host loop** is the only variant that materially wins
  (+30–45% over pipe): the parent burns a bounded spin window so the reply
  is often ready before the child's wake completes, collapsing one switch.
  This is the classic shmem-channel design used by production RPC layers
  (e.g. Wayland's) rather than a pipe.

## Decision

Adopt **B' — shared-memory ring with eventfd doorbells and a bounded
host-side spin-then-park window** — for the Phase 5 import-call transport.

Protocol sketch:

- Ring of 64 slots × 256 B (request and reply banks), sequence counters
  published with release stores / acquire loads. One in-flight call per
  child thread (Phase 5 is single-threaded; the slot count covers future
  multithreaded children without a protocol change).
- Child: write slot → release `req_seq` → `write(ev_req, 1)` → poll
  `rpl_seq` (acquire), park on `ev_rpl` only when not yet published.
  The child never spins unbounded (guest code must block; the host's
  scheduler is not the guest's).
- Parent: on wake (spin window first, then `read(ev_req)`), consume all
  published slots in order, dispatch each through `ApiRegistry`, publish
  replies with release stores, bump `ev_rpl` once per batch.
- ExitProcess and fatal-child cases: the parent detects `EPIPE`/`ECHILD`
  from the doorbell and drains; a dead child never blocks the parent
  (recovery requirement 4).
- Determinism: the spin window only affects wake timing, never the
  protocol order — the sequence counters fully order events, so 100-run
  determinism is preserved (requirement 2).

The pipe design stays as the documented fallback for a future
no-shared-memory target; nothing in the API layer references the transport.

## Consequences

- Import dispatch gains ~40% latency headroom vs. the pipe design at zero
  protocol complexity cost (the ring is already needed to avoid per-call
  kernel copies for larger payloads).
- The parent burns bounded CPU while a guest call is expected (spin window
  ~20–30 µs); with no guest running, it parks — idle cost is zero.
- The benchmark is committed (`scripts/ipc_bench.c`) so the numbers are
  reproducible on any future host; re-run before changing the transport.

## Measurement provenance

- Command: `gcc -O2 -o ipc_bench scripts/ipc_bench.c && ./ipc_bench 500000`
- Machine: 2 vCPU sandbox, Linux 5.10 (`nproc` = 2), 2026-11-25.
- Full output:

```
IPC round-trip microbenchmark (500000 rounds each, 64B payload)

pass 1  pipe :      98773 calls/sec  (5.062 s, 500000 round trips)
pass 1  ring :      96584 calls/sec  (5.177 s, 500000 round trips)
pass 1  spin :     143277 calls/sec  (3.490 s, 500000 round trips)
pass 2  pipe :      89203 calls/sec  (5.605 s, 500000 round trips)
pass 2  ring :      92168 calls/sec  (5.425 s, 500000 round trips)
pass 2  spin :     128320 calls/sec  (3.897 s, 500000 round trips)
```
