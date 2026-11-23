# xbox2pc/tools — command line tools.

add_executable(xbox2pc xbox2pc_cli.cpp)
target_link_libraries(xbox2pc PRIVATE
    xbox2pc_core
    xbox2pc_rt_execution
    xbox2pc_rt_abi
    xbox2pc_rt_cpu
    xbox2pc_rt_guestmem
    xbox2pc_rt_exceptions
    xbox2pc_pe_builder
    xbox2pc_rt_m9_cli)
target_compile_features(xbox2pc PRIVATE cxx_std_20)

install(TARGETS xbox2pc RUNTIME DESTINATION bin)
