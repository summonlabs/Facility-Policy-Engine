cmake_minimum_required(VERSION 3.20)

# An independent consumer of the installed Facility Policy Engine package.
# It is deliberately a separate CMake project: it is configured against an
# install prefix only, and it never sees this repository's build tree.
project(FacilityPolicyGate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(FacilityPolicyEngine CONFIG REQUIRED)

add_executable(facility_policy_gate main.cpp)
target_link_libraries(facility_policy_gate PRIVATE FacilityPolicyEngine::fpe)

enable_testing()
add_test(NAME gate.allow COMMAND facility_policy_gate allow)
add_test(NAME gate.refuse COMMAND facility_policy_gate refuse)
add_test(NAME gate.unknown COMMAND facility_policy_gate unknown)
add_test(NAME gate.stale COMMAND facility_policy_gate stale)
