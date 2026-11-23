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

# M7: API compatibility suite.
add_executable(api_compat_test api_compat_test.cpp)
target_link_libraries(api_compat_test PRIVATE
    xbox2pc_core
    xbox2pc_rt_gdk
    xbox2pc_rt_compat_report
    xbox2pc_pe_builder
    gtest)
target_compile_features(api_compat_test PRIVATE cxx_std_20)

add_test(NAME api_compat_test COMMAND api_compat_test)

# M8: execution subsystem suite.
add_executable(execution_test execution_test.cpp)
target_link_libraries(execution_test PRIVATE
    xbox2pc_core
    xbox2pc_rt_execution
    xbox2pc_rt_gdk
    xbox2pc_rt_compat_report
    xbox2pc_pe_builder
    gtest)
target_compile_features(execution_test PRIVATE cxx_std_20)

add_test(NAME execution_test COMMAND execution_test)

# M8: execution benchmarks (manual; not a ctest target).
add_executable(execution_bench execution_bench.cpp)
target_link_libraries(execution_bench PRIVATE
    xbox2pc_core
    xbox2pc_rt_execution
    xbox2pc_rt_gdk
    xbox2pc_pe_builder)
target_compile_features(execution_bench PRIVATE cxx_std_20)

# M8: deterministic execution fuzz harnesses.
add_executable(execution_fuzz_test execution_fuzz.cpp)
target_link_libraries(execution_fuzz_test PRIVATE
    xbox2pc_core
    xbox2pc_rt_execution
    xbox2pc_rt_gdk
    xbox2pc_pe_builder
    gtest)
target_compile_features(execution_fuzz_test PRIVATE cxx_std_20)

add_test(NAME execution_fuzz_test COMMAND execution_fuzz_test)

# M7: deterministic API-compat fuzz harnesses.
add_executable(api_compat_fuzz_test api_compat_fuzz.cpp)
target_link_libraries(api_compat_fuzz_test PRIVATE
    xbox2pc_core
    xbox2pc_rt_gdk
    xbox2pc_pe_builder
    gtest)
target_compile_features(api_compat_fuzz_test PRIVATE cxx_std_20)

add_test(NAME api_compat_fuzz_test COMMAND api_compat_fuzz_test)

# M7: API-path benchmarks (not a ctest; run manually).
add_executable(api_compat_bench api_compat_bench.cpp)
target_link_libraries(api_compat_bench PRIVATE
    xbox2pc_core
    xbox2pc_rt_gdk
    xbox2pc_rt_compat_report
    xbox2pc_pe_builder)
target_compile_features(api_compat_bench PRIVATE cxx_std_20)

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

# M9: structured instruction decoder suite.
add_executable(x64_decoder_test x64_decoder_test.cpp)
target_link_libraries(x64_decoder_test PRIVATE xbox2pc_rt_x64_decoder gtest)
target_compile_features(x64_decoder_test PRIVATE cxx_std_20)

add_test(NAME x64_decoder_test COMMAND x64_decoder_test)

# M9: interpreter arithmetic/logic semantics suite (§3B).
add_executable(x86_interpreter_test x86_interpreter_test.cpp)
target_link_libraries(x86_interpreter_test PRIVATE
    xbox2pc_rt_x86_interpreter gtest)
target_compile_features(x86_interpreter_test PRIVATE cxx_std_20)

add_test(NAME x86_interpreter_test COMMAND x86_interpreter_test)

# M9: control-flow semantics suite (§3A).
add_executable(x86_control_flow_test x86_control_flow_test.cpp)
target_link_libraries(x86_control_flow_test PRIVATE
    xbox2pc_rt_x86_interpreter gtest)
target_compile_features(x86_control_flow_test PRIVATE cxx_std_20)

add_test(NAME x86_control_flow_test COMMAND x86_control_flow_test)

# M9: data movement + shifts/bit ops suite (§3C/§3D/§3E).
add_executable(x86_data_movement_test x86_data_movement_test.cpp)
target_link_libraries(x86_data_movement_test PRIVATE
    xbox2pc_rt_x86_interpreter gtest)
target_compile_features(x86_data_movement_test PRIVATE cxx_std_20)

add_test(NAME x86_data_movement_test COMMAND x86_data_movement_test)

# M9: stack/flags/conversions + extended-state matrix suite (§5).
add_executable(x86_stack_flags_test x86_stack_flags_test.cpp)
target_link_libraries(x86_stack_flags_test PRIVATE
    xbox2pc_rt_x86_interpreter gtest)
target_compile_features(x86_stack_flags_test PRIVATE cxx_std_20)

add_test(NAME x86_stack_flags_test COMMAND x86_stack_flags_test)

# M9: differential instruction testing (native hardware reference + spec
# cases; the native reference degrades to a documented skip off x86-64).
add_executable(x86_differential_test x86_differential_test.cpp)
target_link_libraries(x86_differential_test PRIVATE
    xbox2pc_rt_x86_interpreter gtest)
target_compile_features(x86_differential_test PRIVATE cxx_std_20)

add_test(NAME x86_differential_test COMMAND x86_differential_test)

# M9: advanced Xbox x64 ABI validation suite (§6).
add_executable(x86_abi_advanced_test x86_abi_advanced_test.cpp)
target_link_libraries(x86_abi_advanced_test PRIVATE
    xbox2pc_core
    xbox2pc_rt_execution
    xbox2pc_rt_gdk
    xbox2pc_rt_compat_report
    xbox2pc_pe_builder
    gtest)
target_compile_features(x86_abi_advanced_test PRIVATE cxx_std_20)

add_test(NAME x86_abi_advanced_test COMMAND x86_abi_advanced_test)

# M5: deterministic fuzz harnesses (no libFuzzer; seeded mutation fuzz).
add_executable(vfs_fuzz_test vfs_fuzz.cpp)
target_link_libraries(vfs_fuzz_test PRIVATE
    xbox2pc_rt_package
    xbox2pc_rt_vfs
    xbox2pc_rt_error
    gtest)
target_compile_features(vfs_fuzz_test PRIVATE cxx_std_20)

add_test(NAME vfs_fuzz_test COMMAND vfs_fuzz_test)

# M9: structural PE binary validation (synthetic inputs only).
add_executable(binary_validation_test binary_validation_test.cpp)
target_link_libraries(binary_validation_test PRIVATE
    xbox2pc_rt_binary_validation xbox2pc_pe_builder gtest)
target_compile_features(binary_validation_test PRIVATE cxx_std_20)
add_test(NAME binary_validation_test COMMAND binary_validation_test)



# M9: exercise every binary CLI command against a generated PE fixture.
add_executable(m9_cli_test m9_cli_test.cpp)
target_link_libraries(m9_cli_test PRIVATE
    xbox2pc_rt_m9_cli xbox2pc_pe_builder gtest)
target_compile_features(m9_cli_test PRIVATE cxx_std_20)
add_test(NAME m9_cli_test COMMAND m9_cli_test)

# M9: deterministic decoder/PE/static-analysis mutation fuzzing.
add_executable(m9_fuzz_test m9_fuzz_test.cpp)
target_link_libraries(m9_fuzz_test PRIVATE
    xbox2pc_rt_x64_decoder xbox2pc_rt_binary_validation
    xbox2pc_rt_static_analysis xbox2pc_pe_builder gtest)
target_compile_features(m9_fuzz_test PRIVATE cxx_std_20)
add_test(NAME m9_fuzz_test COMMAND m9_fuzz_test)

# M9: synthetic decoder/validation/static-analysis benchmarks (manual).
add_executable(m9_bench m9_bench.cpp)
target_link_libraries(m9_bench PRIVATE
    xbox2pc_rt_x64_decoder xbox2pc_rt_binary_validation
    xbox2pc_rt_static_analysis xbox2pc_pe_builder)
target_compile_features(m9_bench PRIVATE cxx_std_20)

# M9: conservative static instruction analysis.
add_executable(static_analysis_test static_analysis_test.cpp)
target_link_libraries(static_analysis_test PRIVATE
    xbox2pc_rt_static_analysis xbox2pc_pe_builder gtest)
target_compile_features(static_analysis_test PRIVATE cxx_std_20)
add_test(NAME static_analysis_test COMMAND static_analysis_test)
