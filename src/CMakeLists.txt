# xbox2pc/src — core libraries.
#
# Components stay modular: one library target per component so later
# milestones (dependency_analyzer, xbox_api_registry, compatibility_core,
# graphics_backend) can be added without entangling pe_parser.

# ── diagnostics ──
add_library(xbox2pc_diagnostics STATIC diagnostics.cpp)
target_include_directories(xbox2pc_diagnostics PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(xbox2pc_diagnostics PUBLIC cxx_std_20)

# ── pe_parser (DOS/COFF/optional headers, sections, directories, tables) ──
add_library(xbox2pc_pe_parser STATIC pe_parser.cpp pe_tables.cpp)
target_include_directories(xbox2pc_pe_parser PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR})  # for pe_internal.hpp
target_link_libraries(xbox2pc_pe_parser PUBLIC xbox2pc_diagnostics)
target_compile_features(xbox2pc_pe_parser PUBLIC cxx_std_20)

# ── M9: structural PE validation (inspection only; never maps or executes) ──
add_library(xbox2pc_rt_binary_validation STATIC binary_validation.cpp)
target_include_directories(xbox2pc_rt_binary_validation PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_binary_validation PUBLIC
    xbox2pc_pe_parser xbox2pc_rt_loader)
target_compile_features(xbox2pc_rt_binary_validation PUBLIC cxx_std_20)

# ── M9: binary CLI/reporting support ──
add_library(xbox2pc_rt_m9_cli STATIC m9_cli.cpp)
target_include_directories(xbox2pc_rt_m9_cli PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_m9_cli PUBLIC
    xbox2pc_rt_binary_validation xbox2pc_rt_static_analysis
    xbox2pc_pe_parser xbox2pc_json xbox2pc_diagnostics)
target_compile_features(xbox2pc_rt_m9_cli PUBLIC cxx_std_20)

# ── json_writer (M2: strict JSON serialization) ──
add_library(xbox2pc_json STATIC json_writer.cpp)
target_include_directories(xbox2pc_json PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(xbox2pc_json PUBLIC cxx_std_20)

# ── api_registry (M2: evidence-based API classification DB) ──
add_library(xbox2pc_api_registry STATIC api_registry.cpp)
target_include_directories(xbox2pc_api_registry PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_api_registry PUBLIC xbox2pc_diagnostics)
target_compile_features(xbox2pc_api_registry PUBLIC cxx_std_20)

# ── compat_db (M2: compatibility status database) ──
add_library(xbox2pc_compat_db STATIC compat_db.cpp)
target_include_directories(xbox2pc_compat_db PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_compat_db PUBLIC xbox2pc_api_registry)
target_compile_features(xbox2pc_compat_db PUBLIC cxx_std_20)

# ── dep_analyzer (M2: dependency intelligence engine) ──
add_library(xbox2pc_dep_analyzer STATIC dep_analyzer.cpp)
target_include_directories(xbox2pc_dep_analyzer PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_dep_analyzer PUBLIC
    xbox2pc_pe_parser xbox2pc_api_registry xbox2pc_compat_db)
target_compile_features(xbox2pc_dep_analyzer PUBLIC cxx_std_20)

# ── dep_graph (M2: directed dependency graph) ──
add_library(xbox2pc_dep_graph STATIC dep_graph.cpp)
target_include_directories(xbox2pc_dep_graph PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_dep_graph PUBLIC
    xbox2pc_dep_analyzer xbox2pc_json xbox2pc_pe_parser xbox2pc_api_registry)
target_compile_features(xbox2pc_dep_graph PUBLIC cxx_std_20)

# ── M3: runtime_core subsystem ──────────────────────────────────────────────
#
# Layering (docs/architecture.md): runtime_error/platform at the bottom (no
# deps beyond diagnostics-free headers), object model + handle management
# above them, sync/thread/process/io objects above those, service registry
# and the facade on top. One library per layer keeps components independently
# testable; no layer links upward.

add_library(xbox2pc_rt_error STATIC runtime_error.cpp)
target_include_directories(xbox2pc_rt_error PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(xbox2pc_rt_error PUBLIC cxx_std_20)

add_library(xbox2pc_rt_pal STATIC pal_linux.cpp)
target_include_directories(xbox2pc_rt_pal PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_pal PUBLIC xbox2pc_rt_error)
target_compile_features(xbox2pc_rt_pal PUBLIC cxx_std_20)
find_package(Threads REQUIRED)
target_link_libraries(xbox2pc_rt_pal PUBLIC Threads::Threads)

add_library(xbox2pc_rt_object STATIC runtime_object.cpp)
target_include_directories(xbox2pc_rt_object PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_object PUBLIC xbox2pc_rt_error)
target_compile_features(xbox2pc_rt_object PUBLIC cxx_std_20)

add_library(xbox2pc_rt_handles STATIC handle_manager.cpp)
target_include_directories(xbox2pc_rt_handles PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_handles PUBLIC xbox2pc_rt_object)
target_compile_features(xbox2pc_rt_handles PUBLIC cxx_std_20)

add_library(xbox2pc_rt_sync STATIC sync_objects.cpp)
target_include_directories(xbox2pc_rt_sync PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_sync PUBLIC xbox2pc_rt_handles xbox2pc_rt_pal)
target_compile_features(xbox2pc_rt_sync PUBLIC cxx_std_20)

add_library(xbox2pc_rt_thread STATIC thread_model.cpp)
target_include_directories(xbox2pc_rt_thread PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_thread PUBLIC
    xbox2pc_rt_handles xbox2pc_rt_pal xbox2pc_rt_sync)
target_compile_features(xbox2pc_rt_thread PUBLIC cxx_std_20)

add_library(xbox2pc_rt_io STATIC io_objects.cpp)
target_include_directories(xbox2pc_rt_io PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_io PUBLIC xbox2pc_rt_handles xbox2pc_rt_pal)
target_compile_features(xbox2pc_rt_io PUBLIC cxx_std_20)

add_library(xbox2pc_rt_process STATIC process_model.cpp)
target_include_directories(xbox2pc_rt_process PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_process PUBLIC
    xbox2pc_rt_handles xbox2pc_rt_pal xbox2pc_dep_analyzer)
target_compile_features(xbox2pc_rt_process PUBLIC cxx_std_20)

add_library(xbox2pc_rt_services STATIC service_registry.cpp)
target_include_directories(xbox2pc_rt_services PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_services PUBLIC xbox2pc_rt_handles xbox2pc_rt_pal)
target_compile_features(xbox2pc_rt_services PUBLIC cxx_std_20)

# ── M4: runtime management layer ────────────────────────────────────────────
#
# rt_memory (virtual memory model over PAL subranges) sits above the PAL;
# rt_procman (process manager + managed processes + resource accounting)
# sits above rt_memory/rt_process/rt_thread. The facade keeps its M3
# surface and additionally exposes the manager.

add_library(xbox2pc_rt_memory STATIC memory_management.cpp xmem_allocator.cpp)
target_include_directories(xbox2pc_rt_memory PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_memory PUBLIC xbox2pc_rt_pal xbox2pc_rt_error)
target_compile_features(xbox2pc_rt_memory PUBLIC cxx_std_20)

add_library(xbox2pc_rt_procman STATIC process_management.cpp)
target_include_directories(xbox2pc_rt_procman PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_procman PUBLIC
    xbox2pc_rt_memory xbox2pc_rt_process xbox2pc_rt_thread xbox2pc_rt_handles
    xbox2pc_rt_pal)
target_compile_features(xbox2pc_rt_procman PUBLIC cxx_std_20)

# ── M5: filesystem & packages layer ─────────────────────────────────────────
#
# rt_vfs sits above rt_handles/rt_pal (file objects + PAL confinement);
# rt_vfs_backends extends it with the host-dir and memory backends;
# rt_package is standalone parser safety over raw buffers (deps: error only);
# rt_package_vfs (package mounting + discovery) above vfs + M1/M2 parsers;
# rt_vfs_process wires namespaces to the M4 process manager.

add_library(xbox2pc_rt_vfs STATIC vfs.cpp)
target_include_directories(xbox2pc_rt_vfs PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_vfs PUBLIC xbox2pc_rt_handles xbox2pc_rt_pal)
target_compile_features(xbox2pc_rt_vfs PUBLIC cxx_std_20)

add_library(xbox2pc_rt_vfs_backends STATIC vfs_backends.cpp)
target_include_directories(xbox2pc_rt_vfs_backends PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_vfs_backends PUBLIC xbox2pc_rt_vfs xbox2pc_rt_pal)
target_compile_features(xbox2pc_rt_vfs_backends PUBLIC cxx_std_20)

add_library(xbox2pc_rt_package STATIC packages.cpp)
target_include_directories(xbox2pc_rt_package PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_package PUBLIC xbox2pc_rt_error)
target_compile_features(xbox2pc_rt_package PUBLIC cxx_std_20)

add_library(xbox2pc_rt_package_vfs STATIC package_vfs.cpp)
target_include_directories(xbox2pc_rt_package_vfs PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_package_vfs PUBLIC
    xbox2pc_rt_vfs xbox2pc_rt_package xbox2pc_pe_parser xbox2pc_dep_analyzer
    xbox2pc_diagnostics)
target_compile_features(xbox2pc_rt_package_vfs PUBLIC cxx_std_20)

add_library(xbox2pc_rt_vfs_process STATIC vfs_process.cpp)
target_include_directories(xbox2pc_rt_vfs_process PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_vfs_process PUBLIC
    xbox2pc_rt_vfs_backends xbox2pc_rt_procman xbox2pc_rt_memory
    xbox2pc_rt_process xbox2pc_rt_thread xbox2pc_rt_handles)
target_compile_features(xbox2pc_rt_vfs_process PUBLIC cxx_std_20)

# ── M6: executable loader layer ─────────────────────────────────────────────
#
# rt_loader sits above rt_procman/rt_memory (mapping into managed process
# address spaces) and the M1 PE parser (validation + section/import/TLS/
# relocation decoding); rt_vfs_process is a link-only dependency for the
# process-with-VFS creation path used by tests/CLI integration.

add_library(xbox2pc_rt_loader STATIC image_loader.cpp)
target_include_directories(xbox2pc_rt_loader PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_loader PUBLIC
    xbox2pc_rt_procman xbox2pc_rt_memory xbox2pc_rt_vfs_process
    xbox2pc_pe_parser xbox2pc_diagnostics)
target_compile_features(xbox2pc_rt_loader PUBLIC cxx_std_20)

# ── M8: execution foundation ─────────────────────────────────────────────────
#
# rt_cpu (guest state) -> nothing below rt_error; rt_abi -> rt_cpu;
# rt_guestmem -> rt_memman (M4). The execution engine + context libs come
# later in the milestone and layer on top of these three.

add_library(xbox2pc_rt_cpu STATIC guest_cpu_state.cpp)
target_include_directories(xbox2pc_rt_cpu PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_cpu PUBLIC xbox2pc_rt_error)
target_compile_features(xbox2pc_rt_cpu PUBLIC cxx_std_20)

add_library(xbox2pc_rt_abi STATIC xbox_abi.cpp)
target_include_directories(xbox2pc_rt_abi PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_abi PUBLIC xbox2pc_rt_cpu)
target_compile_features(xbox2pc_rt_abi PUBLIC cxx_std_20)

add_library(xbox2pc_rt_guestmem STATIC guest_memory.cpp)
target_include_directories(xbox2pc_rt_guestmem PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_guestmem PUBLIC xbox2pc_rt_memory)
target_compile_features(xbox2pc_rt_guestmem PUBLIC cxx_std_20)

# ── M9: structured x86-64 instruction decoder (pure) ────────────────────────
#
# No runtime dependencies: bytes in -> a structured instruction out (or a
# typed reject). Shared by the interpreter (rt_execution), static analysis,
# binary validation and the CLI.

add_library(xbox2pc_rt_x64_decoder STATIC x64_decoder.cpp)
target_include_directories(xbox2pc_rt_x64_decoder PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(xbox2pc_rt_x64_decoder PUBLIC cxx_std_20)

# ── M9: conservative static instruction analysis ──
add_library(xbox2pc_rt_static_analysis STATIC static_analysis.cpp)
target_include_directories(xbox2pc_rt_static_analysis PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_static_analysis PUBLIC
    xbox2pc_pe_parser xbox2pc_rt_x64_decoder xbox2pc_rt_x86_interpreter)
target_compile_features(xbox2pc_rt_static_analysis PUBLIC cxx_std_20)

# ── M9: instruction semantics engine (arithmetic/logic first) ───────────────
#
# rt_x86_interpreter executes one decoded instruction against CpuState +
# GuestMemory (sub-register rules, flags per the SDM, typed faults).
# Layers on rt_x64_decoder + rt_cpu + rt_guestmem/rt_exceptions.

add_library(xbox2pc_rt_x86_interpreter STATIC x86_interpreter.cpp)
target_include_directories(xbox2pc_rt_x86_interpreter PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_x86_interpreter PUBLIC
    xbox2pc_rt_x64_decoder xbox2pc_rt_cpu xbox2pc_rt_guestmem xbox2pc_rt_exceptions)
target_compile_features(xbox2pc_rt_x86_interpreter PUBLIC cxx_std_20)

# ── M8: execution engine + exceptions ────────────────────────────────────────
#
# rt_exceptions -> rt_error only; rt_execution -> rt_cpu/rt_abi/rt_guestmem
# + M7 rt_api (marshalling bridge) — the top of the M8 stack.

add_library(xbox2pc_rt_exceptions STATIC guest_exceptions.cpp)
target_include_directories(xbox2pc_rt_exceptions PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_exceptions PUBLIC xbox2pc_rt_error)
target_compile_features(xbox2pc_rt_exceptions PUBLIC cxx_std_20)

add_library(xbox2pc_rt_execution STATIC execution_engine.cpp execution_context.cpp guest_environment.cpp native_execution.cpp process_tls_wiring.cpp)
target_include_directories(xbox2pc_rt_execution PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_execution PUBLIC
    xbox2pc_rt_cpu xbox2pc_rt_abi xbox2pc_rt_guestmem
    xbox2pc_rt_exceptions xbox2pc_rt_api xbox2pc_rt_loader
    xbox2pc_rt_x86_interpreter xbox2pc_rt_procman)
target_compile_features(xbox2pc_rt_execution PUBLIC cxx_std_20)

# ── M7: API compatibility layer ─────────────────────────────────────────────
#
# rt_api (api_compat) = descriptors + registry + dispatcher + ApiResolver +
# delay-load resolution; rt_gdk (gdk_services) = the RtService
# implementations (lifecycle/XSystem/XThread/XTaskQueue/timing + TLS init);
# rt_compat_report joins M1/M2/M6/M7 data into the compatibility report.
# Layering: rt_gdk -> rt_api -> (M2 registries, M6 loader); none of them
# link upward into rt_core.

add_library(xbox2pc_rt_api STATIC api_compat.cpp)
target_include_directories(xbox2pc_rt_api PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_api PUBLIC
    xbox2pc_rt_loader xbox2pc_rt_services xbox2pc_api_registry xbox2pc_compat_db)
target_compile_features(xbox2pc_rt_api PUBLIC cxx_std_20)

# M11 Phase 9: shared `xbox2pc run` entry (CLI tool + integration tests).
add_library(xbox2pc_rt_run_cli STATIC run_cli.cpp)
target_include_directories(xbox2pc_rt_run_cli PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_run_cli PUBLIC
    xbox2pc_core xbox2pc_rt_execution xbox2pc_rt_abi xbox2pc_rt_loader
    xbox2pc_rt_gdk xbox2pc_rt_procman xbox2pc_json xbox2pc_pe_parser)
target_compile_features(xbox2pc_rt_run_cli PUBLIC cxx_std_20)

add_library(xbox2pc_rt_gdk STATIC gdk_services.cpp graphics_service.cpp)
target_include_directories(xbox2pc_rt_gdk PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_gdk PUBLIC
    xbox2pc_rt_api xbox2pc_rt_procman xbox2pc_rt_thread xbox2pc_rt_pal)
target_compile_features(xbox2pc_rt_gdk PUBLIC cxx_std_20)

add_library(xbox2pc_rt_compat_report STATIC compat_report.cpp)
target_include_directories(xbox2pc_rt_compat_report PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_compat_report PUBLIC
    xbox2pc_rt_api xbox2pc_dep_analyzer)
target_compile_features(xbox2pc_rt_compat_report PUBLIC cxx_std_20)

add_library(xbox2pc_rt_core STATIC runtime_core.cpp)
target_include_directories(xbox2pc_rt_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_core PUBLIC
    xbox2pc_rt_error xbox2pc_rt_pal xbox2pc_rt_object xbox2pc_rt_handles
    xbox2pc_rt_sync xbox2pc_rt_thread xbox2pc_rt_io xbox2pc_rt_process
    xbox2pc_rt_services xbox2pc_rt_memory xbox2pc_rt_procman
    xbox2pc_rt_vfs xbox2pc_rt_vfs_backends xbox2pc_rt_package
    xbox2pc_rt_package_vfs xbox2pc_rt_vfs_process xbox2pc_rt_loader)
target_compile_features(xbox2pc_rt_core PUBLIC cxx_std_20)

# Aggregate target: everything M1..M5 needs for tools and tests.
add_library(xbox2pc_core INTERFACE)
target_link_libraries(xbox2pc_core INTERFACE
    xbox2pc_diagnostics
    xbox2pc_pe_parser
    xbox2pc_json
    xbox2pc_api_registry
    xbox2pc_compat_db
    xbox2pc_dep_analyzer
    xbox2pc_dep_graph
    xbox2pc_rt_core
    xbox2pc_rt_api
    xbox2pc_rt_gdk
    xbox2pc_rt_compat_report)
