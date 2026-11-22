# xbox2pc/tests — GoogleTest suites.

# Vendored googletest (third_party/googletest).
add_subdirectory(${PROJECT_SOURCE_DIR}/third_party/googletest googletest-build EXCLUDE_FROM_ALL)

# PE test-binary builder (test-only component, not shipped).
add_library(xbox2pc_pe_builder STATIC ../src/pe_builder.cpp)
target_include_directories(xbox2pc_pe_builder PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(xbox2pc_pe_builder PUBLIC cxx_std_20)

add_executable(pe_parser_test pe_parser_test.cpp)
target_link_libraries(pe_parser_test PRIVATE
    xbox2pc_core
    xbox2pc_pe_builder
    gtest)
target_compile_features(pe_parser_test PRIVATE cxx_std_20)

add_test(NAME pe_parser_test COMMAND pe_parser_test)

# M2: dependency intelligence suite.
add_executable(deps_test deps_test.cpp)
target_link_libraries(deps_test PRIVATE
    xbox2pc_core
    xbox2pc_pe_builder
    gtest)
target_compile_features(deps_test PRIVATE cxx_std_20)

add_test(NAME deps_test COMMAND deps_test)

# M3: runtime architecture suite.
add_executable(runtime_test runtime_test.cpp)
target_link_libraries(runtime_test PRIVATE
    xbox2pc_core
    xbox2pc_pe_builder
    gtest)
target_compile_features(runtime_test PRIVATE cxx_std_20)

add_test(NAME runtime_test COMMAND runtime_test)

# M4: runtime management suite.
add_executable(runtime_m4_test runtime_m4_test.cpp)
target_link_libraries(runtime_m4_test PRIVATE
    xbox2pc_core
    xbox2pc_pe_builder
    gtest)
target_compile_features(runtime_m4_test PRIVATE cxx_std_20)

add_test(NAME runtime_m4_test COMMAND runtime_m4_test)

# M5: filesystem + packages suite.
add_executable(vfs_packages_test vfs_packages_test.cpp)
target_link_libraries(vfs_packages_test PRIVATE
    xbox2pc_core
    xbox2pc_pe_builder
    gtest)
target_compile_features(vfs_packages_test PRIVATE cxx_std_20)

add_test(NAME vfs_packages_test COMMAND vfs_packages_test)

# M6: executable loader suite.
add_executable(loader_test loader_test.cpp)
target_link_libraries(loader_test PRIVATE
    xbox2pc_core
    xbox2pc_pe_builder
    gtest)
target_compile_features(loader_test PRIVATE cxx_std_20)

add_test(NAME loader_test COMMAND loader_test)

# M6: deterministic loader fuzz harnesses (seeded mutation).
add_executable(loader_fuzz_test loader_fuzz.cpp)
target_link_libraries(loader_fuzz_test PRIVATE
    xbox2pc_core
    xbox2pc_pe_builder
    gtest)
target_compile_features(loader_fuzz_test PRIVATE cxx_std_20)

add_test(NAME loader_fuzz_test COMMAND loader_fuzz_test)

# M6: loader phase benchmarks (not a ctest; run manually).
add_executable(loader_bench loader_bench.cpp)
target_link_libraries(loader_bench PRIVATE
    xbox2pc_core
    xbox2pc_pe_builder)
target_compile_features(loader_bench PRIVATE cxx_std_20)

# M5: deterministic fuzz harnesses (no libFuzzer; seeded mutation fuzz).
add_executable(vfs_fuzz_test vfs_fuzz.cpp)
target_link_libraries(vfs_fuzz_test PRIVATE
    xbox2pc_rt_package
    xbox2pc_rt_vfs
    xbox2pc_rt_error
    gtest)
target_compile_features(vfs_fuzz_test PRIVATE cxx_std_20)

add_test(NAME vfs_fuzz_test COMMAND vfs_fuzz_test)
