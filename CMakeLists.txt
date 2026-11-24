cmake_minimum_required(VERSION 3.20)
project(xbox2pc
    VERSION 0.1.0
    DESCRIPTION "Xbox2PC — PE32+ inspection and Xbox-to-PC compatibility layer"
    LANGUAGES CXX)

# M11.5 native leaf thunk is assembled only on Linux x86-64.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
   CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
    enable_language(ASM)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Global hardening flags for all xbox2pc code (tests inherit too).
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wconversion -Wsign-conversion
    -Wshadow -Wnon-virtual-dtor -Wold-style-cast
    -Werror=return-type)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Threads REQUIRED)

add_subdirectory(src)

option(XBOX2PC_BUILD_TESTS "Build xbox2pc test suites" ON)
if(XBOX2PC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

option(XBOX2PC_BUILD_TOOLS "Build xbox2pc command line tools" ON)
if(XBOX2PC_BUILD_TOOLS)
    add_subdirectory(tools)
endif()
