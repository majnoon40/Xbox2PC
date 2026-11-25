# CMake generated Testfile for 
# Source directory: /tmp/x2pc-pr15/tools
# Build directory: /tmp/x2pc-pr15/build-asan-native/tools
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test("m9_interpreter_info_cli" "/tmp/x2pc-pr15/build-asan-native/tools/xbox2pc" "interpreter-info")
set_tests_properties("m9_interpreter_info_cli" PROPERTIES  _BACKTRACE_TRIPLES "/tmp/x2pc-pr15/tools/CMakeLists.txt;18;add_test;/tmp/x2pc-pr15/tools/CMakeLists.txt;0;")
add_test("m9_interpreter_test_cli" "/tmp/x2pc-pr15/build-asan-native/tools/xbox2pc" "interpreter-test")
set_tests_properties("m9_interpreter_test_cli" PROPERTIES  _BACKTRACE_TRIPLES "/tmp/x2pc-pr15/tools/CMakeLists.txt;19;add_test;/tmp/x2pc-pr15/tools/CMakeLists.txt;0;")
