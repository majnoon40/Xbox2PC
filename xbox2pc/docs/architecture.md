# M3 Architecture — Xbox Runtime Architecture & Object Model

**Status: M1–M8 complete.** 277 tests pass (M1–M7: 245 as shipped; M8 adds 24 execution tests + 7 fuzz harnesses at 170,400 mutations). Clean builds verified under the normal toolchain, ASan+UBSan and TSan (0 findings). M8 adds the execution foundation — `rt_cpu` (guest CPU state), `rt_abi` (documented Microsoft x64 ABI), `rt_guestmem` (safe guest memory over M4), `rt_exceptions` (structured guest faults), `rt_execution` (engine interface + deterministic bounded-subset backend + marshalling bridge + context lifecycle + TLS callback scheduling); see [execution-architecture.md](execution-architecture.md). Roadmap: instruction-set expansion / native or emulator backend next.
28 M4 + 20 M5 + 3 M5-fuzz + 34 M6 + 5 M6-fuzz + 23 M7 + 6 M7-fuzz).
Clean builds verified under the normal toolchain,
AddressSanitizer+UBSan and ThreadSanitizer (0 findings). M6 added
`rt_loader` (PE32+ executable loader: validation, mapping, DIR64
relocations, explicit import resolution, TLS metadata, execution
preparation — **no execution**; see [pe-loader.md](pe-loader.md)).
M7 adds the Xbox GDK/Game OS API compatibility foundation —
`rt_api` (evidence-cited descriptors, thread-safe registration +
dispatch, ApiResolver over M6's resolver interface, delay-load
resolution), `rt_gdk` (GDK services as M3 RtServices + per-thread
TLS init), `rt_compat_report` (stable-code import verdicts); see
[api-compat.md](api-compat.md). Roadmap: execution-context foundation
is the recommended M8 (guest marshalling, TLS callbacks, entry-point
invocation).

## Scope and framing

M3 delivers the architectural foundation of the Xbox→PC compatibility
runtime: a modular, testable model of an Xbox-style runtime environment
(object model, handle management, process/thread lifecycle,
synchronization, service registry, platform abstraction). It is an
architecture, **not** an Xbox OS implementation: no kernel emulation, no
executable execution, no GPU/audio/GDK translation (see "Explicit
exclusions").

Nothing in M3 claims to reproduce undocumented Xbox internals. Where the
design borrows Xbox concepts (per-process handle tables, object typing,
GDK-style services), the docs label each fact **confirmed** (cited public
evidence) or **inferred** (architectural model chosen for this project).

## Layered design

```
┌───────────────────────────────────────────────────────────────┐
│ 7. RuntimeCore facade (runtime_core.hpp/.cpp)                 │
│    init/shutdown sequencing, creator APIs, summary            │
├───────────────────────────────────────────────────────────────┤
│ 6. Runtime service registry (service_registry.*)             │
│    RtService, dependency resolution, init/shutdown ordering   │
├───────────────────────────────────────────────────────────────┤
│ 5. Domain object models                                       │
│    sync_objects.*   thread_model.*   process_model.*          │
│    io_objects.*     (events/mutexes/semaphores/condvars,      │
│                     threads+TLS, processes+modules, files)    │
├───────────────────────────────────────────────────────────────┤
│ 4. Handle management (handle_manager.*)                       │
│    HandleTable (generation-protected), RefGuard pins           │
├───────────────────────────────────────────────────────────────┤
│ 3. Object manager + type registry (runtime_object.*)          │
│    RuntimeObject base, ObjectTypeRegistry, ObjectManager       │
├───────────────────────────────────────────────────────────────┤
│ 2. Platform abstraction (platform.hpp / pal_linux.cpp)        │
│    threads, mutexes, condvars, events, semaphores, memory,     │
│    files, monotonic clock — host calls ONLY here               │
├───────────────────────────────────────────────────────────────┤
│ 1. Runtime error model + type ids (runtime_error.*)           │
│    RuntimeErrc, Result<T>, RuntimeError                        │
└───────────────────────────────────────────────────────────────┘
```

Milestone M1 (PE32+ parser) and M2 (dependency analyzer) remain
independent; M3 integrates their *outputs* via
`rt::ModuleDescriptor::from_image()` (see
[process-thread-model.md](process-thread-model.md)).

## Dependency rules (enforced by review + link graph)

1. **No host OS calls above layer 2.** pthread/mmap/open/clock appear
   only in `pal_linux.cpp`. Platform-independent components include
   `platform.hpp` and call the interfaces.
2. **No upward links.** Each layer links only downward
   (`src/CMakeLists.txt` mirrors the layer table above).
3. **No circular dependencies.** The object manager sits below all
   domain models; the service registry consumes the manager, never the
   reverse; the facade is the only component that sees everything.
4. **M1/M2 decoupling.** `xbox2pc_rt_process` links
   `xbox2pc_dep_analyzer` for the `ModuleDescriptor` copy — one-way,
   metadata-only.

## Ownership and lifetime rules

| Owner | Owns | Lifetime |
|---|---|---|
| `ObjectManager` | every `RuntimeObject` (unique_ptr in id map) | registration → destroy() |
| `RefGuard` | an access *pin* (not ownership) | scope of the guard |
| `HandleTable` | handle slots (never objects) | table/process lifetime |
| `ServiceRegistry` | `RtService` objects (via its manager) | registration → destroy_all |
| `RuntimeCore` | the manager, the registry, sequencing | core lifetime |

Destruction contract (details in
[runtime-object-model.md](runtime-object-model.md)):
- exactly-once teardown (`manager_begin_destroy` CAS),
- pins drained before memory release (bounded, non-blocking),
- double-destroy and use-after-destroy are **typed errors**, never UB.

## Initialization / shutdown sequences

```
RuntimeCore::initialize():
  1. (construction) PAL info captured; global object manager installed
  2. register PlatformInfoService (built-in, no dependencies)
  3. ServiceRegistry::initialize_all() — topological order, cycle and
     missing-dependency detection are typed errors
  4. state -> Running

RuntimeCore::shutdown():
  1. ServiceRegistry::shutdown_all() — exact reverse init order
  2. registry objects destroyed
  3. remaining runtime objects destroyed LIFO by the manager
  4. state -> Shutdown (any later use returns NotInitialized)
```

The destructor runs shutdown() automatically when still Running — the
core never leaks or hangs at teardown.

## Error handling

- Recoverable failures: `Result<T>` with `RuntimeErrc` codes
  (`runtime_error.hpp`); 27 codes cover objects, handles, transitions,
  sync, services, platform, IO.
- Contract violations (pin underflow, half-initialized core): typed
  `RuntimeError` exceptions.
- Nothing is silently discarded: PAL errno strings are carried in the
  result context; every teardown failure is recorded as object metadata
  or a returned error.

## Concurrency guarantees

- Shared runtime state: object map behind a `shared_mutex`
  (readers concurrent, writers exclusive); handle tables likewise.
- Lookups pin under the read lock → lookup-then-destroy races are closed.
- Object state is an atomic enum (readers never see a half state).
- Thread/pcondvar ownership rules are race-free by construction (owner
  thread id recorded on acquire, refreshed after condvar re-acquire).
- Stress suites run 4 scenarios × 5 repetitions under TSan (clean).

## Build and test

```
cmake -S xbox2pc -B xbox2pc/build -G Ninja
cmake --build xbox2pc/build
ctest --test-dir xbox2pc/build            # 129 tests, 3 suites

# sanitizers
cmake -S xbox2pc -B xbox2pc/build-asan -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"
cmake --build xbox2pc/build-asan --target runtime_test
xbox2pc/build-asan/tests/runtime_test

cmake -S xbox2pc -B xbox2pc/build-tsan -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=thread -fno-omit-frame-pointer -g"
cmake --build xbox2pc/build-tsan --target runtime_test
xbox2pc/build-tsan/tests/runtime_test
```

Toolchain: C++20, CMake ≥ 3.20, g++ 14.2 (Linux host backend).

## Library map

| Layer | CMake target | Sources |
|---|---|---|
| 1 | `xbox2pc_rt_error` | runtime_error.cpp |
| 2 | `xbox2pc_rt_pal` | pal_linux.cpp |
| 3 | `xbox2pc_rt_object` | runtime_object.cpp |
| 4 | `xbox2pc_rt_handles` | handle_manager.cpp |
| 5 | `xbox2pc_rt_sync` | sync_objects.cpp |
| 5 | `xbox2pc_rt_thread` | thread_model.cpp |
| 5 | `xbox2pc_rt_io` | io_objects.cpp |
| 5 | `xbox2pc_rt_process` | process_model.cpp |
| 5.5 | `xbox2pc_rt_memory` | memory_management.cpp (M4: virtual memory, address spaces) |
| 5.6 | `xbox2pc_rt_procman` | process_management.cpp (M4: process manager, accounting) |
| 5.7 | `xbox2pc_rt_vfs` | vfs.cpp (M5: virtual filesystem, mounts, namespaces) |
| 5.7 | `xbox2pc_rt_vfs_backends` | vfs_backends.cpp (M5: host-dir + memory backends) |
| 5.8 | `xbox2pc_rt_package` | packages.cpp (M5: bounded reader, XPK synthetic format, classification) |
| 5.8 | `xbox2pc_rt_package_vfs` | package_vfs.cpp (M5: package mounting + discovery) |
| 5.9 | `xbox2pc_rt_vfs_process` | vfs_process.cpp (M5: process namespaces, M4 bridges) |
| 5.95 | `xbox2pc_rt_loader` | image_loader.cpp (M6: PE validation, mapping, relocations, imports, TLS, lifecycle) |
| 5.96 | `xbox2pc_rt_api` | api_compat.cpp (M7: API descriptors, registry, dispatch, ApiResolver, delay-load) |
| 5.97 | `xbox2pc_rt_gdk` | gdk_services.cpp (M7: GDK services + Game OS foundation + TLS init) |
| 5.98 | `xbox2pc_rt_compat_report` | compat_report.cpp (M7: compatibility reporting) |
| 5.99 | `xbox2pc_rt_cpu` | guest_cpu_state.cpp (M8: guest CPU state) |
| 5.991 | `xbox2pc_rt_abi` | xbox_abi.cpp (M8: x64 ABI) |
| 5.992 | `xbox2pc_rt_guestmem` | guest_memory.cpp (M8: guest memory) |
| 5.993 | `xbox2pc_rt_exceptions` | guest_exceptions.cpp (M8: fault model) |
| 5.995 | `xbox2pc_rt_execution` | execution_engine.cpp + execution_context.cpp (M8: engine+bridge+context+TLS) |
| 6 | `xbox2pc_rt_services` | service_registry.cpp |
| 7 | `xbox2pc_rt_core` | runtime_core.cpp |

Aggregate `xbox2pc_core` links M1..M7; M8 libs are linked explicitly by tests/tools.

## Explicit exclusions (M4+ territory)

No Xbox kernel emulation, CPU emulation, graphics or Direct3D
translation, audio, GDK substitution, filesystem emulation, network
stack, proprietary kernel internals, undocumented scheduling behavior,
or full Xbox memory architecture. M3's PAL thread "suspension" is
cooperative; M3 does not model Xbox scheduler preemption. M6 loads and
maps executable images but does NOT execute them: entry-point execution,
Xbox ABI compatibility, and game execution remain excluded (future
milestones); GDK API compatibility is now the next planned milestone
(roadmap order changed explicitly — executable loading first).

## Evidence base

Confirmed (public sources; also cited in the per-topic docs):

- Xbox software layout / Game OS and GDK distinction — Microsoft GDK
  docs, https://learn.microsoft.com/en-us/gaming/gdk/
- Xbox titles are packaged as PE32+ executables — GDK packaging docs,
  https://learn.microsoft.com/en-us/gaming/gdk/content-certification
- HANDLE semantics (opaque, duplicable, closable) — Win32 HANDLE
  documentation,
  https://learn.microsoft.com/en-us/windows/win32/sysinfo/handles-and-objects
- DuplicateHandle semantics —
  https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
- Xbox kernel object types exist (events/mutexes/semaphores/processes/
  threads as kernel objects) — publicly documented Win32/NT object model
  the Xbox Game OS is modeled after; specific Xbox internals are NOT
  reverse-engineered here (inferred where used).

Inferred (architectural choices for this project, no Xbox source):
- generation-counter stale-handle protection,
- object lifecycle state machine shape,
- process/thread state machine shapes,
- service registry dependency ordering design.

Per-topic docs:
[execution-architecture.md](execution-architecture.md) (M8 hub) ·
[guest-cpu-state.md](guest-cpu-state.md) ·
[xbox-x64-abi.md](xbox-x64-abi.md) ·
[guest-memory.md](guest-memory.md) ·
[api-marshalling.md](api-marshalling.md) ·
[execution-engine.md](execution-engine.md) ·
[guest-exceptions.md](guest-exceptions.md) ·
[tls-execution.md](tls-execution.md) ·
[api-compat.md](api-compat.md) ·
[pe-loader.md](pe-loader.md) ·
[virtual-filesystem.md](virtual-filesystem.md) ·
[package-formats.md](package-formats.md) ·
[asset-discovery.md](asset-discovery.md) ·
[runtime-object-model.md](runtime-object-model.md) ·
[handle-management.md](handle-management.md) ·
[process-thread-model.md](process-thread-model.md) ·
[platform-abstraction.md](platform-abstraction.md) ·
[service-registry.md](service-registry.md)
