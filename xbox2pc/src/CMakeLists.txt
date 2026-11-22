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

# Aggregate target: everything M1+M2 needs for tools and tests.
add_library(xbox2pc_core INTERFACE)
target_link_libraries(xbox2pc_core INTERFACE
    xbox2pc_diagnostics
    xbox2pc_pe_parser
    xbox2pc_json
    xbox2pc_api_registry
    xbox2pc_compat_db
    xbox2pc_dep_analyzer
    xbox2pc_dep_graph)
