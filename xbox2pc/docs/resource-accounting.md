# M4 — Resource Accounting

## Responsibility

Consistent per-process and global resource statistics for the runtime:
virtual memory (reserved/committed), threads, handles, objects, module
descriptors, processes, address spaces — plus resource-limit abstractions
with typed enforcement. `ResourceStats`/`ResourceLimits` live in
`process_management.hpp`; the accounting centers on `ProcessManager`.

## What is counted

| Field | Source |
|---|---|
| `reserved_bytes` / `committed_bytes` / `region_count` | the process's `AddressSpace::stats()` |
| `thread_count` | the process's registered thread list |
| `handle_count` | the process's handle table `live_count()` |
| `module_count` | the process's `ModuleDescriptor` list |
| `object_count` | the object manager's registry size |
| `process_count` / `address_space_count` | the manager's process map |

## Snapshot consistency

- **Per-process**: `ManagedProcess::stats()` takes the process detail
  lock once; sub-stats are read under their own locks in a fixed order
  (detail → space → handle table), documented as a per-process snapshot
  (not a global instant).
- **Global**: `ProcessManager::global_stats()` holds the manager lock
  and iterates processes in pid order — a consistent aggregate across
  processes at the manager's serialization point. Tests assert exact
  sums (`GlobalResourceAccounting`: 2 processes, 2 regions, committed =
  sum of both).

## Limits (typed enforcement)

`ResourceLimits` (documented as xbox2pc design — **not** Xbox limits):

| Limit | Enforced at | Error |
|---|---|---|
| `max_committed_bytes_total` | `ProcessManager::commit_region` (sums live spaces before committing) | `OutOfResources` |
| `max_reserved_bytes_total` | `reserve_region` (same pattern) | `OutOfResources` |
| `max_threads_total` | `spawn_thread` | `OutOfResources` |
| `max_processes` | `create_process` | `OutOfResources` |
| `max_address_spaces` | (future: reserved; spaces track processes 1:1 today) | — |
| `allow_wx_pages` | `protect_region` — gates `MemProtect::Full` | `InvalidArgument` |

Per-space `MemoryLimits` (reserved/committed/regions per process) are
enforced inside the `AddressSpace` itself. Limit checks fail closed with
typed errors carrying the offending numbers; nothing is silently clamped.

## CLI

`resource-info` reports the global snapshot (text + JSON);
`process-info` embeds per-process stats; `memory-info` reports the
memory columns. All values come from the live runtime.

## Known limitations

- Global limit checks sum live spaces while holding per-process guards
  briefly (per-process stats take locks); a concurrent commit can race
  the sum — enforcement is best-effort-bounded (documented): the check
  may allow one in-flight overshoot, never an unbounded one.
- No quota fairness or per-user accounting (single-runtime model).
- Peak metrics exist for the allocator only (`peak_used_bytes`).

## Confirmed vs inferred

Inferred entirely (xbox2pc design): the stat set, snapshot semantics,
limit set and error mapping. Xbox resource-quota internals are
proprietary and NOT modeled — the spec explicitly forbids inventing
Xbox-specific limits.
