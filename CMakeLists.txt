cmake_minimum_required(VERSION 3.20)

project(FacilityPolicyEngine
    VERSION 1.0.0
    DESCRIPTION "Deterministic facility-wide policy evaluation runtime"
    HOMEPAGE_URL "https://github.com/summonlabs/Facility-Policy-Engine"
    LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(FPE_TOP_LEVEL ON)
else()
    set(FPE_TOP_LEVEL OFF)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(FPE_BUILD_TESTS "Build the Facility Policy Engine test suite" ${FPE_TOP_LEVEL})
option(FPE_BUILD_BENCHMARKS "Build the Facility Policy Engine benchmark harness" ${FPE_TOP_LEVEL})
option(FPE_STRICT_WARNINGS "Promote first-party warnings to errors" ON)
option(FPE_ENABLE_ASAN "Build with AddressSanitizer when the toolchain supports it" OFF)
option(FPE_WARNINGS_AS_SYSTEM "Do not apply the strict warning policy to this project" OFF)

set(FPE_INSTALL_CMAKEDIR "lib/cmake/FacilityPolicyEngine"
    CACHE STRING "Directory (relative to the install prefix) that receives the CMake package files")

if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(NOT FPE_WARNINGS_AS_SYSTEM)
    if(MSVC)
        add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor /EHsc)
        if(FPE_STRICT_WARNINGS)
            add_compile_options(/WX)
        endif()
        add_compile_definitions(_CRT_SECURE_NO_WARNINGS _SCL_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
    else()
        add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wold-style-cast -Wcast-qual -Wnon-virtual-dtor -Woverloaded-virtual)
        if(FPE_STRICT_WARNINGS)
            add_compile_options(-Werror)
        endif()
    endif()
endif()

if(FPE_ENABLE_ASAN)
    if(MSVC)
        # /Zi is required: without debug information the compiler rejects the
        # build under the strict warning policy (C5072), and a sanitizer report
        # without line information is not actionable.
        add_compile_options(/fsanitize=address /Zi)
        add_link_options(/INCREMENTAL:NO /DEBUG)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

add_subdirectory(src)
add_subdirectory(tools)

if(FPE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(FPE_BUILD_BENCHMARKS)
    add_subdirectory(bench)
endif()

install(EXPORT FacilityPolicyEngineTargets
    FILE FacilityPolicyEngineTargets.cmake
    NAMESPACE FacilityPolicyEngine::
    DESTINATION ${FPE_INSTALL_CMAKEDIR})

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FacilityPolicyEngineConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/FacilityPolicyEngineConfig.cmake"
    INSTALL_DESTINATION ${FPE_INSTALL_CMAKEDIR})

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/FacilityPolicyEngineConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
    ARCH_INDEPENDENT)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/FacilityPolicyEngineConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/FacilityPolicyEngineConfigVersion.cmake"
    DESTINATION ${FPE_INSTALL_CMAKEDIR})

install(FILES README.md LICENSE NOTICE CONTRIBUTING.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR})
