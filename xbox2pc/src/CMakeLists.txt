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
target_link_libraries(xbox2pc_rt_thread PUBLIC xbox2pc_rt_handles xbox2pc_rt_pal)
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

add_library(xbox2pc_rt_memory STATIC memory_management.cpp)
target_include_directories(xbox2pc_rt_memory PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_memory PUBLIC xbox2pc_rt_pal xbox2pc_rt_error)
target_compile_features(xbox2pc_rt_memory PUBLIC cxx_std_20)

add_library(xbox2pc_rt_procman STATIC process_management.cpp)
target_include_directories(xbox2pc_rt_procman PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_procman PUBLIC
    xbox2pc_rt_memory xbox2pc_rt_process xbox2pc_rt_thread xbox2pc_rt_handles
    xbox2pc_rt_pal)
target_compile_features(xbox2pc_rt_procman PUBLIC cxx_std_20)

add_library(xbox2pc_rt_core STATIC runtime_core.cpp)
target_include_directories(xbox2pc_rt_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(xbox2pc_rt_core PUBLIC
    xbox2pc_rt_error xbox2pc_rt_pal xbox2pc_rt_object xbox2pc_rt_handles
    xbox2pc_rt_sync xbox2pc_rt_thread xbox2pc_rt_io xbox2pc_rt_process
    xbox2pc_rt_services xbox2pc_rt_memory xbox2pc_rt_procman)
target_compile_features(xbox2pc_rt_core PUBLIC cxx_std_20)

# Aggregate target: everything M1+M2+M3+M4 needs for tools and tests.
add_library(xbox2pc_core INTERFACE)
target_link_libraries(xbox2pc_core INTERFACE
    xbox2pc_diagnostics
    xbox2pc_pe_parser
    xbox2pc_json
    xbox2pc_api_registry
    xbox2pc_compat_db
    xbox2pc_dep_analyzer
    xbox2pc_dep_graph
    xbox2pc_rt_core)
