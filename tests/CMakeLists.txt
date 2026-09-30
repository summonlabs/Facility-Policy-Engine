add_library(fpe_test_support STATIC test_support.cpp)
target_link_libraries(fpe_test_support PUBLIC fpe_core)
target_include_directories(fpe_test_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(fpe_tests
    test_adversarial.cpp
    test_cli.cpp
    test_decision_store.cpp
    test_digest.cpp
    test_engine.cpp
    test_main.cpp
    test_multiprocess.cpp
    test_policy.cpp
    test_statemachine.cpp
    test_types_json.cpp
)
target_link_libraries(fpe_tests PRIVATE fpe_test_support)
add_dependencies(fpe_tests fpe_cli)

set_target_properties(fpe_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin")

# The end-to-end cases need the real command line executable, which is a
# different target, so this generator expression cannot be circular.
target_compile_definitions(fpe_tests PRIVATE
    FPE_CLI_EXECUTABLE_PATH="$<TARGET_FILE:fpe_cli>")

# No timeout is configured anywhere: a hanging case is a defect to diagnose, not
# something to mask with a watchdog.
add_test(NAME fpe.tests COMMAND fpe_tests)
set_tests_properties(fpe.tests PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
