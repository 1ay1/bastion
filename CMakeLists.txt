cmake_minimum_required(VERSION 3.24)
project(bastion VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BASTION_BUILD_TESTS "Build tests" ON)

# -----------------------------------------------------------------------------
# Platform backend detection. Capabilities are PROBED AT RUNTIME (Backend::probe)
# and never inferred from these flags alone — a kernel may lack Landlock even
# where the headers exist.
# -----------------------------------------------------------------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include(CheckIncludeFile)
    check_include_file("linux/landlock.h" BASTION_HAVE_LANDLOCK_H)
    check_include_file("linux/seccomp.h" BASTION_HAVE_SECCOMP_H)
    set(BASTION_PLATFORM "linux")
elseif(APPLE)
    set(BASTION_PLATFORM "darwin")
elseif(WIN32)
    set(BASTION_PLATFORM "windows")
else()
    set(BASTION_PLATFORM "generic")
endif()
message(STATUS "bastion: platform backend = ${BASTION_PLATFORM}")

add_library(bastion STATIC src/policy.cpp)
target_include_directories(bastion PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

# Hardening: these are non-negotiable for a security boundary.
target_compile_options(bastion PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    -Wold-style-cast -Wcast-qual -Wformat=2
    $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>
    -fstack-protector-strong)

if(BASTION_HAVE_LANDLOCK_H)
    target_compile_definitions(bastion PUBLIC BASTION_HAVE_LANDLOCK=1)
endif()
if(BASTION_HAVE_SECCOMP_H)
    target_compile_definitions(bastion PUBLIC BASTION_HAVE_SECCOMP=1)
endif()

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
if(BASTION_BUILD_TESTS)
    enable_testing()

    add_executable(cap_test tests/cap_test.cpp)
    target_link_libraries(cap_test PRIVATE bastion)
    add_test(NAME cap COMMAND cap_test)

    add_executable(policy_test tests/policy_test.cpp)
    target_link_libraries(policy_test PRIVATE bastion)
    add_test(NAME policy COMMAND policy_test)

    # Negative compile tests: each case MUST be rejected by the type system.
    # A "compile error" security claim is worthless if it is never verified.
    foreach(case 1 2 3 4)
        add_test(NAME negative_compile_${case}
                 COMMAND ${CMAKE_COMMAND}
                         -DTEST_CXX=${CMAKE_CXX_COMPILER}
                         -DSRC=${CMAKE_CURRENT_SOURCE_DIR}
                         -DCASE=${case}
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/negative_compile.cmake)
    endforeach()
endif()
