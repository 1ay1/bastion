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
    # CheckIncludeFileCXX, not CheckIncludeFile: the latter compiles a .c probe
    # and this project only enables CXX, so it fails with "Unknown extension
    # .c ... try_compile() works only for enabled languages" and ABORTS the
    # configure. It went unnoticed because an already-configured build tree
    # caches the result and never re-runs the check -- only a FRESH clone hit
    # it, which is exactly what CI does.
    include(CheckIncludeFileCXX)
    check_include_file_cxx("linux/landlock.h" BASTION_HAVE_LANDLOCK_H)
    check_include_file_cxx("linux/seccomp.h" BASTION_HAVE_SECCOMP_H)
    set(BASTION_PLATFORM "linux")
elseif(APPLE)
    set(BASTION_PLATFORM "darwin")
elseif(WIN32)
    set(BASTION_PLATFORM "windows")
else()
    set(BASTION_PLATFORM "generic")
endif()
message(STATUS "bastion: platform backend = ${BASTION_PLATFORM}")

set(BASTION_SOURCES src/policy.cpp src/spawn.cpp src/ledger.cpp src/observe.cpp src/proxy.cpp src/policy_file.cpp src/signal_forward.cpp)
if(APPLE)
    list(APPEND BASTION_SOURCES src/backend/seatbelt.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND BASTION_SOURCES src/backend/landlock.cpp src/backend/seccomp_notify.cpp
                                src/backend/namespaces.cpp src/backend/cgroup.cpp)
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

    add_executable(policy_file_test tests/policy_file_test.cpp)
    target_link_libraries(policy_file_test PRIVATE bastion)
    add_test(NAME policy_file COMMAND policy_file_test)

    add_executable(ledger_test tests/ledger_test.cpp)
    target_link_libraries(ledger_test PRIVATE bastion)
    add_test(NAME ledger COMMAND ledger_test)

    # ADVERSARIAL: real escape attempts. A failure here is a sandbox escape.
    add_executable(adversarial_test tests/adversarial_test.cpp)
    target_link_libraries(adversarial_test PRIVATE bastion)
    add_test(NAME adversarial COMMAND adversarial_test)

    # Resource ceilings: fork-bomb / disk-fill backstops, and the guarantee
    # that they stay OUT OF THE WAY when not asked for.
    add_executable(rlimit_test tests/rlimit_test.cpp)
    target_link_libraries(rlimit_test PRIVATE bastion)
    add_test(NAME rlimit COMMAND rlimit_test)
    set_tests_properties(rlimit PROPERTIES TIMEOUT 120)

    # T0 observation: the mechanism `synthesize` depends on. Asserts that
    # observing does not change the workload, that grandchildren are seen, and
    # that paths/rights are recorded precisely enough to build a policy from.
    add_executable(observe_test tests/observe_test.cpp)
    target_link_libraries(observe_test PRIVATE bastion)
    add_test(NAME observe COMMAND observe_test)
    set_tests_properties(observe PROPERTIES TIMEOUT 120)

    # CLOSED LOOP: observe -> synthesize -> re-run under the derived policy.
    # Proves `bastion synthesize` emits a policy that actually WORKS, rather
    # than one that merely looks plausible.
    add_executable(closed_loop_test tests/closed_loop_test.cpp)
    target_link_libraries(closed_loop_test PRIVATE bastion)
    add_test(NAME closed_loop COMMAND closed_loop_test)
    set_tests_properties(closed_loop PROPERTIES TIMEOUT 120)

    # T3 egress: per-host allowlisting the child cannot route around.
    # Needs outbound network; skipped implicitly if the host is offline.
    add_executable(egress_test tests/egress_test.cpp)
    target_link_libraries(egress_test PRIVATE bastion)
    add_test(NAME egress COMMAND egress_test)
    set_tests_properties(egress PROPERTIES TIMEOUT 180)

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

    # Fork-safety: async-signal-safety enforced by the TYPE SYSTEM rather than
    # by a comment. The comment was already wrong once -- the child called an
    # allocating apply(), which can deadlock forever on a malloc lock held by a
    # thread that does not exist in the child.
    add_executable(forksafe_test tests/forksafe_test.cpp)
    target_link_libraries(forksafe_test PRIVATE bastion)
    add_test(NAME forksafe COMMAND forksafe_test)

    foreach(case 1 2 3 4 5)
        add_test(NAME forksafe_negative_${case}
                 COMMAND ${CMAKE_COMMAND}
                         -DTEST_CXX=${CMAKE_CXX_COMPILER}
                         -DSRC=${CMAKE_CURRENT_SOURCE_DIR}
                         -DCASE=${case}
                         -DFILE=tests/forksafe_test.cpp
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/negative_compile.cmake)
    endforeach()

    # Lifecycle: killing bastion must take the sandboxed SUBTREE with it.
    # Agent harnesses kill on timeout, so a surviving workload leaks a process
    # per attempt -- and an orphan still holds whatever the policy granted.
    add_executable(lifecycle_test tests/lifecycle_test.cpp)
    target_link_libraries(lifecycle_test PRIVATE bastion)
    target_compile_definitions(lifecycle_test PRIVATE
        BASTION_CLI="$<TARGET_FILE:bastion_cli>")
    add_dependencies(lifecycle_test bastion_cli)
    add_test(NAME lifecycle COMMAND lifecycle_test)
    set_tests_properties(lifecycle PROPERTIES TIMEOUT 120)

    # Diagnostics: does a FAILING run tell an agent enough to recover? Checks
    # both directions -- guidance on a real denial, and SILENCE on a genuine
    # test failure, because a false "maybe it was the sandbox" sends the agent
    # chasing a policy bug that does not exist.
    add_executable(diagnostics_test tests/diagnostics_test.cpp)
    target_link_libraries(diagnostics_test PRIVATE bastion)
    target_compile_definitions(diagnostics_test PRIVATE
        BASTION_CLI="$<TARGET_FILE:bastion_cli>")
    add_dependencies(diagnostics_test bastion_cli)
    add_test(NAME diagnostics COMMAND diagnostics_test)
    set_tests_properties(diagnostics PROPERTIES TIMEOUT 120)

    # ABI degradation across v1-v10, WITHOUT needing ten kernels: compile() is
    # a pure function of (policy, AbiInfo), so every version can be exercised
    # here. Development happens on v10 where every capability exists, so the
    # version-gating code is otherwise never run.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(abi_matrix_test tests/abi_matrix_test.cpp)
        target_link_libraries(abi_matrix_test PRIVATE bastion)
        add_test(NAME abi_matrix COMMAND abi_matrix_test)
    endif()

    # Invariant types: Result<T> (no unchecked failures) and UniqueFd (no
    # leaked descriptors). A leaked fd is not just a resource here -- rights
    # attach to the open file description, so it is authority.
    add_executable(invariants_test tests/invariants_test.cpp)
    target_link_libraries(invariants_test PRIVATE bastion)
    add_test(NAME invariants COMMAND invariants_test)

    foreach(case 1 2 3 4 5)
        add_test(NAME invariants_negative_${case}
                 COMMAND ${CMAKE_COMMAND}
                         -DTEST_CXX=${CMAKE_CXX_COMPILER}
                         -DSRC=${CMAKE_CURRENT_SOURCE_DIR}
                         -DCASE=${case}
                         -DFILE=tests/invariants_test.cpp
                         -DEXTRA_FLAGS=-Werror
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/negative_compile.cmake)
    endforeach()
endif()
