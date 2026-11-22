# M3 — Handle Management

## Responsibility

`HandleTable` + `ObjectManager` (both in `handle_manager.*`) issue,
validate, duplicate and retire handles; `install_global_manager`
connects per-process tables to the runtime's object manager.

## Handle representation

A handle is an opaque **uint64** — never a pointer, never an address:

```
bits 63..40 : slot index   (24 bits, ≤ 16 777 216 slots per table)
bits 39..9  : generation   (31 bits, nonzero while the slot is in use)
bits 8..0   : type id      (9 bits, mirrors TypeId for cheap validation)
```

Layout is computed arithmetically (`Handle::from_parts` / `raw()`), so
handles are values: copyable, comparable, serializable.

## Operations and semantics

| Operation | Semantics |
|---|---|
| `create(obj)` | allocates a slot (free-list, O(1)), binds the object id + type; returns a handle with the slot's current generation |
| `lookup(h)` | validates index range → in-use → generation → type field; resolves to a **pinned** RefGuard via the object manager |
| `close(h)` | validates generation, bumps the slot generation, frees the slot; the handle value can never resolve again |
| `duplicate(h)` | resolves and issues a **new independent slot** for the same object; closing one does not invalidate the other |
| `validate_type(h, t)` | type-checked probe (used by typed close paths) |
| `close_all()` | process teardown — all slots freed, generations bumped |

## Stale-handle protection (generation counters)

Slot reuse is the classic hazard (close a handle, get the same slot for a
new object, and the OLD handle value aliases the new object). Each slot
carries a **generation counter**:

- a fresh slot starts at generation 1;
- every `close` bumps it (`… % kMaxGeneration + 1`, skipping 0);
- a reused slot's next cycle starts from the bumped generation.

A stale handle therefore fails the generation equality check and gets
`HandleStale` — it can never alias the slot's next occupant. Wraparound
(2³¹ closes per slot) skips zero and is astronomically unlikely; still
documented rather than hidden.

Test `HandleTest.GenerationProtectsAgainstStale` proves exactly this
scenario: same slot index, different generation, old handle rejected,
new handle resolves.

## Error taxonomy

| Condition | Error |
|---|---|
| null handle / index out of range / type field mismatch | `InvalidHandle` |
| slot freed (handle of a closed cycle) | `HandleStale` |
| slot live but generation differs (reused slot) | `HandleStale` |
| target object destroyed (handle not yet closed) | `ObjectDestroyed` |
| table exhausted (16M slots) | `HandleTableFull` |
| lookup before runtime init (per-process tables) | `NotInitialized` |

Destroying an object does **not** auto-close its handles: the handles
remain (closed explicitly or by process teardown) and resolve to a typed
`ObjectDestroyed` — use-after-destroy is impossible through the handle
path.

## Ownership rules

- Handles do **not** own objects. A handle is a (revocable) name; object
  lifetime belongs to the `ObjectManager` (see
  [runtime-object-model.md](runtime-object-model.md)).
- A handle slot holds only the **object id** (never a pointer) — the
  manager resolves ids, so slot contents can never dangle.
- Duplication creates sibling names, not refcount increments: closing a
  duplicate leaves the original usable and vice versa (tested in
  `HandleTest.DuplicateIndependentClosure`).

## Table topology

- The runtime's own `ObjectManager` has one table (process objects,
  runtime-wide objects).
- Each `RtProcess` owns its own `HandleTable` (Xbox-style per-process
  tables — **inferred** architectural model, see below); the table
  resolves ids through the **global** manager installed at runtime
  construction (`install_global_manager`), because processes do not own
  their threads' lifetimes.
- Process termination closes its table (`close_all`): every handle dies
  together with the process (`ProcessTest.TerminateClosesHandleTable`).

## Concurrency guarantees

- One `shared_mutex` per table: lookups run concurrently; create/close/
  close_all take the write lock.
- Lookup **pins under the read lock** before resolving, so
  lookup-vs-destroy races are closed (the object cannot be freed while a
  lookup is resolving it).
- Live-count and handle enumeration are read-locked.

Stress: 8 threads × 100 lookups on a shared handle (`ConcurrentHandleOps`),
5 repetitions, TSan-clean.

## Confirmed vs inferred

Confirmed (public evidence):
- opaque, duplicable, closable HANDLE semantics —
  https://learn.microsoft.com/en-us/windows/win32/sysinfo/handles-and-objects
- DuplicateHandle issues a new independent handle —
  https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle

Inferred (architectural choices; Xbox's actual table internals are
undocumented and are NOT reproduced):
- the 24/31/9 bit layout,
- generation counters as stale protection (Windows uses similar
  generation tricks per public documentation of its handle tables —
  cited as inspiration, not as an Xbox fact:
  https://learn.microsoft.com/en-us/sysinternals/downloads/handle —
  documents reuse/lock-free handle table behavior at a general level),
- per-process table topology in this runtime.
