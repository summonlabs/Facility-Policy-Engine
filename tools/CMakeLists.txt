add_executable(fpe_cli fpe/main.cpp)
target_link_libraries(fpe_cli PRIVATE fpe_core)

# A single, generator-independent location for the installed-artifact and
# end-to-end CLI tests to locate the executable.
set_target_properties(fpe_cli PROPERTIES
    OUTPUT_NAME fpe
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/bin")

install(TARGETS fpe_cli
    EXPORT FacilityPolicyEngineTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
