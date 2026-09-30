set(FPE_PLATFORM_SOURCES)
if(WIN32)
    list(APPEND FPE_PLATFORM_SOURCES platform_win32.cpp)
else()
    list(APPEND FPE_PLATFORM_SOURCES platform_posix.cpp)
endif()

add_library(fpe_core STATIC
    ${FPE_PLATFORM_SOURCES}
    decision.cpp
    digest.cpp
    engine.cpp
    input.cpp
    json.cpp
    limits.cpp
    policy_compile.cpp
    policy_json.cpp
    policy_model.cpp
    runtime.cpp
    store.cpp
    status.cpp
    types.cpp
    version.cpp
)

add_library(FacilityPolicyEngine::fpe ALIAS fpe_core)

set_target_properties(fpe_core PROPERTIES
    EXPORT_NAME fpe
    OUTPUT_NAME fpe
    POSITION_INDEPENDENT_CODE ON)

target_include_directories(fpe_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# The operating-system boundary is internal; it is deliberately not installed.
target_include_directories(fpe_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_features(fpe_core PUBLIC cxx_std_20)

install(TARGETS fpe_core
    EXPORT FacilityPolicyEngineTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../include/fpe
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
