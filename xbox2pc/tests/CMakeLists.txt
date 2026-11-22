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
