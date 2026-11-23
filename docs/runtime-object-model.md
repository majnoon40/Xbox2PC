# M3 — Runtime Object Model

## Responsibility

`runtime_object.hpp/.cpp` define the base `RuntimeObject`, the extensible
`ObjectTypeRegistry`, and the lifetime state machine every runtime object
follows. `handle_manager.hpp/.cpp` add the `ObjectManager` (the single
owner/registry) and access pins (`RefGuard`). Together they answer:
what is an object, who owns it, when does it die, and what happens if you
touch it after death.

## Object identity

- Every object has a **manager-assigned uint64 id** (never 0; ids are
  unique for the manager's lifetime and never reused).
- Object addresses are never used as identity and never escape through
  the public interface (handles encode index+generation+type — see
  [handle-management.md](handle-management.md)).
- `name` is a mutable display string (diagnostics/CLI), not identity.
- `metadata` is a key→value map guarded by its own mutex; used for
  origin, open-mode, recorded teardown errors, etc.

## Type system

`TypeId` is a uint16 enum: built-ins 1–8 (Process, Thread, Event, Mutex,
Semaphore, File, MemoryRegion, RuntimeService), user types ≥ 1000 via
`ObjectTypeRegistry::register_user_type()` (collision-checked; the
built-in range is closed). The registry maps id→name for diagnostics and
CLI output. Condvars register the user type `condvar`
(`kUserTypeBase + 1`) — the pattern future subsystems (graphics,
audio...) will follow.

Type-safe access: `RuntimeObject::as<T>()` validates **both** the
registered TypeId **and** the C++ dynamic type (`dynamic_cast`). A class
claiming a shared TypeId (e.g. two Event wrappers) can therefore never be
confused through `as<T>()`. There are no void* accessors in the public
interface.

## Lifecycle states

```
Created ──register──> Registered ──destroy──> Destroying ──> Destroyed
   └──────────────────(self-destroy)──────────────┘
```

- `Created`: constructed, not yet manager-tracked.
- `Registered`: tracked, usable (the normal state).
- `Destroying`: teardown started — `as<T>()` refuses, `is_alive()` is
  false; memory is still valid until pins drain.
- `Destroyed`: terminal. The object shell is erased from the manager.

All transitions are atomic CAS operations (`manager_begin_destroy` is
the exactly-once guard — a second caller loses the CAS and gets a typed
`ObjectDestroyed` error).

## Ownership model (documented alternative to shared_ptr-everywhere)

The **ObjectManager is the single owner** (unique ownership; the map
owns the unique_ptr). Reference counting exists only as an **access
pin** (`RefGuard`):

- `lookup_id`/`lookup_handle` return a `RefGuard` that pins the object
  for its scope; guards are movable, not copyable.
- `ObjectManager::destroy(id)`:
  1. CAS Created/Registered → Destroying (exactly once; double destroy
     returns a typed error),
  2. drop the manager's own pin,
  3. **bounded** drain of remaining pins — destroy never blocks forever
     on a long-lived guard (design decision: no public API can deadlock
     the manager). If pins remain after the budget, the object stays in
     `Destroying` (lookups return `ObjectDestroyed`) and a later
     `destroy()` retry completes teardown.
  4. `on_destroy()` hook, `Destroyed`, erase.

Consequences (all tested):

| Misuse | Behavior |
|---|---|
| Use-after-destroy via manager/handle | typed `ObjectDestroyed`/`NotFound` error — never freed memory |
| Double destroy | typed `ObjectDestroyed` error |
| Destroy while another thread holds a guard | drain waits (bounded); guard keeps the object usable |
| Wrong-typed cast | `as<T>()` returns nullptr |

## Concurrency contract

- `type_id()`, `id()`, `state()`, `pin_count()` are lock-free atomics —
  safe concurrently.
- Metadata ops take the metadata mutex.
- Lifecycle transitions are manager-serialized (unique lock).
- Guard semantics: while any guard holds a pin the object memory is
  valid (the manager cannot free it), so `RefGuard::get()` nulls **only**
  on the terminal `Destroyed` state.

## Known limitations

- The drain budget is a spin-with-yield loop (bounded ~2×10⁷ iterations,
  unlocked every 1024 spins); a pathological long-held guard delays
  (not deadlocks) destroy and requires a retry. A condvar-based drain is
  an M4 refinement.
- Object ids are per-manager (per-run); no global cross-run identity.
- `on_destroy()` hooks run with the manager lock held — subclasses must
  not call back into the manager from `on_destroy()` (documented
  contract; none of the M3 objects do).

## Confirmed vs inferred

Confirmed (public evidence):
- Win32/NT object manager concepts — objects have types, names, and
  refcounted lifetimes —
  https://learn.microsoft.com/en-us/windows/win32/sysinfo/handles-and-objects

Inferred (architectural, chosen for xbox2pc):
- the 4-state lifecycle machine,
- pin-based access guards instead of shared_ptr graphs,
- the bounded non-blocking destroy,
- user-type id allocation scheme.


---

## M4 appendix — pin-drain refinement & race fixes

M4 replaced the bounded-spin pin drain with a **condvar drain** and fixed
two real races found by TSan (documented for posterity):

1. **Release-path use-after-free**: `RefGuard::release()` read the object
   state after unpinning — if that unpin dropped the last pin, a
   concurrent destroy could free the object between the decrement and the
   read. Fix: read state BEFORE unpin.
2. **Wake-path use-after-free**: `unpin()` read the drain-decision state
   and called back into the manager AFTER the pin decrement — same
   window. Fix: `unpin` snapshots (state, notify fn, drain context) BEFORE
   the decrement; the callback receives the snapshot (never `this`), so
   the wake path touches only the manager.

The drain itself: `ObjectManager::destroy` drops its ownership pin and
waits on a dedicated drain mutex+condvar (`unpin` of a destroying
object's last pin notifies the OWNING manager — context installed at
registration, not the global manager, so local managers in tests drain
correctly). 50 ms fallback ticks keep the drain robust against a missed
wake; a caller holding a guard across destroy can no longer deadlock the
manager (M3's hazard).

The W^X discipline, address-space model, rights metadata and the rest of
the M4 memory/handle extensions are documented in
[memory-management.md](memory-management.md) and
[handle-security.md](handle-security.md).
