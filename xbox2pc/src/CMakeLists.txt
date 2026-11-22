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

# Aggregate target: everything M1 needs for tools and tests.
add_library(xbox2pc_core INTERFACE)
target_link_libraries(xbox2pc_core INTERFACE
    xbox2pc_diagnostics
    xbox2pc_pe_parser)
