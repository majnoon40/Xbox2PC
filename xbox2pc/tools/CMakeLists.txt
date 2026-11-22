# xbox2pc/tools — command line tools.

add_executable(xbox2pc xbox2pc_cli.cpp)
target_link_libraries(xbox2pc PRIVATE xbox2pc_core)
target_compile_features(xbox2pc PRIVATE cxx_std_20)

install(TARGETS xbox2pc RUNTIME DESTINATION bin)
