# Asserts that a negative case FAILS to compile. Inverts the usual test logic:
# success here means the type system rejected an unsafe program.
#
# FILE defaults to the capability suite, so existing invocations are unchanged.
if(NOT DEFINED FILE)
    set(FILE tests/cap_test.cpp)
endif()

# EXTRA_FLAGS lets a case rely on a warning being fatal -- [[nodiscard]] is a
# warning by default, and "you ignored a failure" is exactly the bug class we
# are asserting is impossible.
if(NOT DEFINED EXTRA_FLAGS)
    set(EXTRA_FLAGS "")
endif()

execute_process(
    COMMAND ${TEST_CXX} -std=c++23 -I${SRC}/include -DCASE=${CASE} ${EXTRA_FLAGS}
            -fsyntax-only ${SRC}/${FILE}
    RESULT_VARIABLE rc
    OUTPUT_QUIET ERROR_VARIABLE err)

if(rc EQUAL 0)
    message(FATAL_ERROR
        "SECURITY: negative case ${CASE} in ${FILE} COMPILED but must be "
        "rejected.\nThe type system failed to prevent an unsafe program.")
endif()

message(STATUS "negative case ${CASE} (${FILE}): correctly rejected")
