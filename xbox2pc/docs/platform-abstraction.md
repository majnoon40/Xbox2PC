# M3 — Platform Abstraction Layer

## Responsibility

`platform.hpp` defines the host-agnostic interfaces;
`pal_linux.cpp` is the only translation unit allowed to make host OS
calls (pthread, mmap, mprotect, open/read/write, clock_gettime). A future
Windows backend would be `pal_win32.cpp` behind the same header — the
layer rules forbid any other file from touching host APIs.

## Interfaces (M3 scope)

| Interface | Linux backend status |
|---|---|
| `PalThread` (start/join/detach/request_stop) | **implemented** — pthreads with a gated trampoline |
| `PalMutex` (lock/try_lock/unlock) | **implemented** — ERRORCHECK pthread mutex + race-free ownership tracking |
| `PalCondvar` (wait/wait_for_ns/notify) | **implemented** — pthread condvars, relative-timeout conversion |
| `PalSemaphore` (acquire/try/release) | **implemented** — mutex+condvar counting semaphore with max |
| `PalEvent` (set/reset/wait_ns) | **implemented** — auto/manual reset semantics over a condvar |
| `MonotonicNs` clock (`now_ns`) | **implemented** — `clock_gettime(CLOCK_MONOTONIC)` |
| `PalMemoryRegion` (reserve/commit/protect) | **implemented** — `mmap` anonymous + `mprotect` (PROT_NONE reserve) |
| `PalFile` (read/write/seek/size/close) | **implemented** — `open/read/write/lseek/fstat/close` |

`describe_backend()` reports backend identity ("linux-pthreads+mmap"),
OS, page size, clock — surfaced by the CLI `runtime-info` and the
`PlatformInfoService`.

## Design decisions worth knowing

### 1. Gated thread spawn (pthread torn-read elimination)

`pthread_create` may run the child before the parent returns; passing a
stack-allocated start record is the classic data race. `LinuxThread`
holds the trampoline on a mutex/condvar **gate** until `start()` has
fully initialized the launch record and `pthread_create` returned. The
gate is destroyed only in the thread object's destructor (after join/
detach), so the child's reads are always synchronized.

### 2. Race-free mutex ownership check

TSan's interceptor flags unlock-of-unlocked even when ERRORCHECK mutexes
would return EPERM (defined behavior for that type). Instead of relying
on pthread to catch it, `LinuxMutex` records the owning thread id on
acquire (never cleared on unlock — clearing would race with a
concurrent acquirer) and:

- unlock by a non-recorded-owner → `LockNotOwned` **before** pthread is
  touched;
- double unlock by the recorded owner is disambiguated with a
  `trylock` probe: acquiring the free mutex proves the double unlock
  (the probe releases it again and reports the error);
- condvar waits **refresh the owner** after their internal re-acquire
  (both signal and timeout paths), since they bypass `lock()`.

This keeps the error path defined, TSan-clean, and still covered by the
ERRORCHECK pthread type as second-line defense.

### 3. Relative→absolute timeout conversion

pthread condvar timed waits take **absolute** CLOCK_REALTIME deadlines;
the PAL contract is **relative** (`timeout_ns < 0` = infinite). Every
timed wait converts once per call (event and condvar paths) — a bug
class eliminated by the dedicated helper. Timeout tests assert the
elapsed wall time, not just the return code.

### 4. Reserve ≠ commit

`reserve_memory` maps PROT_NONE (address space only); `commit_memory`
maps read-write. `protect()` re-applies r/w/x per host limits; sizes are
page-aligned. M3 models the **address space** only — no Xbox memory
partition semantics (documented exclusion).

## Error discipline

Every backend call maps errno into typed results:
`PlatformError` (with `what(): strerror` context), `OutOfResources`
(mmap), `IoError` (file ops), `Timeout` (waits), `LockNotOwned`
(ownership), `InvalidState` (closed file / bad semaphore count). No
error string is dropped — the context rides along in `Result`.

## Threads and `Threads::Threads`

`xbox2pc_rt_pal` links `Threads::Threads` (CMake `find_package(Threads
REQUIRED)`); consumers of the aggregate `xbox2pc_core` get it transitively.

## Known limitations (explicit, no fake support)

- No Windows backend yet — `pal_win32.cpp` is M4+; until then the PAL is
  Linux-only by construction (the header stays platform-independent).
- `request_stop` is **cooperative**: no host forced-stop; M3 never kills
  threads (also a safety rule for teardown).
- File IO is host-filesystem only — no Xbox path translation, no
  sandbox; full Xbox filesystem emulation is an explicit later milestone.
- Virtual memory: no file mapping, no NUMA/affinity, no hugepages;
  protection granularity follows host page size.
- Timers: `MonotonicNs` provides the clock only — no timer queues or
  callbacks (later milestone).

## Confirmed vs inferred

Confirmed (public evidence):
- pthread timed waits use absolute deadlines —
  https://man7.org/linux/man-pages/man3/pthread_cond_timedwait.3.html
- pthread mutex unlock by non-owner is EPERM for ERRORCHECK mutexes —
  https://man7.org/linux/man-pages/man3/pthread_mutex_lock.3.html
- mmap PROT_NONE reservation, mprotect changes —
  https://man7.org/linux/man-pages/man2/mprotect.2.html

Inferred: the interface *shapes* (start/join/detach/stop split, reserve/
commit split, file mode enum) are architectural choices for portability
— not extracted from any Xbox documentation.
