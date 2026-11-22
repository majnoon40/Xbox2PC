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
