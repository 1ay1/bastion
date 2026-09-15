# Asserts that a negative case FAILS to compile. Inverts the usual test logic:
# success here means the type system rejected an unsafe program.
execute_process(
    COMMAND ${TEST_CXX} -std=c++23 -I${SRC}/include -DCASE=${CASE}
            -fsyntax-only ${SRC}/tests/cap_test.cpp
    RESULT_VARIABLE rc
    OUTPUT_QUIET ERROR_VARIABLE err)

if(rc EQUAL 0)
    message(FATAL_ERROR
        "SECURITY: negative case ${CASE} COMPILED but must be rejected.\n"
        "The capability type system failed to prevent an unsafe program.")
endif()

message(STATUS "negative case ${CASE}: correctly rejected")
