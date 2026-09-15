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

set(BASTION_SOURCES src/policy.cpp src/spawn.cpp src/ledger.cpp)
if(APPLE)
    list(APPEND BASTION_SOURCES src/backend/seatbelt.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND BASTION_SOURCES src/backend/landlock.cpp)
endif()

add_library(bastion STATIC ${BASTION_SOURCES})
target_include_directories(bastion PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

# Hardening: these are non-negotiable for a security boundary.
target_compile_options(bastion PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    -Wold-style-cast -Wcast-qual -Wformat=2
    $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>
    -fstack-protector-strong)

add_executable(bastion_cli src/cli.cpp)
set_target_properties(bastion_cli PROPERTIES OUTPUT_NAME bastion)
target_link_libraries(bastion_cli PRIVATE bastion)

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

    # LIVE enforcement: spawns real processes and asserts the kernel actually
    # blocked them. Without this we would only be testing that we generate
    # plausible-looking policy text.
    add_executable(live_enforcement_test tests/live_enforcement_test.cpp)
    target_link_libraries(live_enforcement_test PRIVATE bastion)
    add_test(NAME live_enforcement COMMAND live_enforcement_test)

    add_executable(ledger_test tests/ledger_test.cpp)
    target_link_libraries(ledger_test PRIVATE bastion)
    add_test(NAME ledger COMMAND ledger_test)

    # ADVERSARIAL: real escape attempts. A failure here is a sandbox escape.
    add_executable(adversarial_test tests/adversarial_test.cpp)
    target_link_libraries(adversarial_test PRIVATE bastion)
    add_test(NAME adversarial COMMAND adversarial_test)

    # Verify the Landlock backend's UAPI usage even when not on Linux.
    add_test(NAME landlock_uapi
             COMMAND ${CMAKE_COMMAND} -E env sh
                     ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_landlock.sh)

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
