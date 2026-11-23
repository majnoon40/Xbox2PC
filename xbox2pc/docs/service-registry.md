# M3 — Runtime Service Registry

## Responsibility

`service_registry.*` implement service registration, discovery, typed
lookup, dependency declaration/resolution, and deterministic
initialization/shutdown ordering — the extension point where later
milestones plug in Graphics, Audio, Input, Storage, Networking, GDK API
compatibility and Game runtime services.

**M3 ships exactly one built-in service**: `PlatformInfoService` (PAL
facts). No fake graphics/audio/networking services exist — the registry
is the *mechanism*, future milestones bring the subsystems.

## Service objects

`RtService : RuntimeObject` (TypeId::RuntimeService) with:

- a unique **service name** (its registry key; also the object name),
- declared **dependencies** (service names; declared at construction or
  via `declare_dependency`),
- a registry-driven **lifecycle**:
  `Registered → Initializing → Ready → ShuttingDown → Shutdown`, with
  `Failed` reachable on init/shutdown errors,
- `on_initialize()` / `on_shutdown()` hooks returning typed results,
- `last_error` recording every failure (visible in listings/CLI).

## Registration

| Call | Behavior |
|---|---|
| `register_service(unique_ptr)` | registers with the registry's object manager (assigns an object id), stores dependencies; duplicate name → `AlreadyExists`; empty name → `InvalidArgument` |
| `declare_service_name(name)` | forward-declares a service that doesn't exist yet; registering the real service later **upgrades** the declaration in place |

`find(name)` resolves to a pinned RefGuard; `find_typed<T>` adds a
`dynamic_cast` check (`ObjectTypeMismatch` when the concrete type
differs).

## Dependency resolution (before any init runs)

`initialization_order()` runs Kahn's algorithm over the declared edges:

- order is **topological and deterministic** (alphabetical seeding among
  ready nodes — stable output for tests and CLI);
- missing dependencies are reported separately by
  `missing_dependencies()` (they do not create edges);
- cycles are detected and reported as one typed `CircularDependency`
  error listing **all** cycle members.

## Initialization ordering

`initialize_all()`:

1. compute the topological order (cycles → typed error, nothing starts);
2. walk the order; a service whose dependency is **missing**,
   **declared-but-never-registered**, or **failed** is skipped and
   marked `Failed` with a per-service reason;
3. otherwise `on_initialize()` runs; failures mark the service `Failed`
   (its error string recorded) and everything depending on it cascades
   to `Failed` as unmet;
4. services with no relation to a failure still initialize
   (partial-init is observable, not hidden);
5. the aggregate result is `ServiceFailed` if anything failed, listing
   where to look (per-service `last_error`).

## Shutdown ordering

`shutdown_all()` walks the **exact reverse** of the successful
initialization order — guaranteed by storing the order at init and
reversing it; shutdown failures mark services `Failed` with a
`shutdown:` prefix on their recorded error. Idempotent: a second call is
a no-op until the next `initialize_all()`.

## Error taxonomy

| Condition | Error |
|---|---|
| duplicate registration / registration over a real service | `AlreadyExists` |
| unknown service / declared-not-registered | `NotFound` |
| cycle in dependencies | `CircularDependency` (context lists members) |
| any service failed init/shutdown | `ServiceFailed` (context points at per-service errors) |
| typed lookup mismatch | `ObjectTypeMismatch` |
| double initialize_all | `AlreadyInitialized` |

## Integration with the runtime

`RuntimeCore::initialize()` registers `PlatformInfoService` and runs
`initialize_all()`; `shutdown()` runs `shutdown_all()` then
`destroy_all()` (shutdown + object destruction). The registry owns its
`ObjectManager` (services are ordinary runtime objects — handles,
listing, pins all apply); `RtProcess::set_service` provides per-process
service maps (name → object id) for later milestones.

## Design decisions

- **Name-keyed** (not id-keyed): services are discovered by stable,
  human-readable names (like GDK subsystem names); ids remain the
  object-manager identity.
- **Skip-and-mark on failure** rather than abort-everything: independent
  services keep working; failure scope is visible per service.
- **Stored init order**: shutdown order is data, not recomputed —
  guaranteed inverse even if dependencies change mid-run.
- Registry dtor runs `shutdown_all()` — no service leaks at teardown.

## Confirmed vs inferred

Confirmed (public evidence — existence and shape of runtime
service/subsystem concepts on Xbox):
- GDK provides Game Runtime Services (XGameRuntimeInitialize & friends)
  as an explicit runtime-services layer —
  https://learn.microsoft.com/en-us/gaming/gdk/_api/gdk/xgameruntimeinitialize
- Graphics/audio/input as subsystems of the Xbox platform stack —
  https://learn.microsoft.com/en-us/gaming/gdk/

Inferred (architectural choices): name-keyed registry with topological
ordering, forward declarations, skip-and-mark failure semantics, and the
exact-reverse shutdown rule. Xbox's internal service manager is
undocumented and is NOT reproduced.
