cmake_minimum_required(VERSION 3.30)

include("${CMAKE_CURRENT_LIST_DIR}/cmake/OpenProofDarwinSdk.cmake")
openproof_configure_darwin_sdk()

# OpenProof is a vendor-neutral, self-hosted identity platform.
# Technical identifiers intentionally use the openproof / OPP naming consistently.
project(openproof
    VERSION 1.1.0
    DESCRIPTION "OpenProof Protocol: centralized identity, OAuth/OIDC, API gateway, proof and trust platform"
    LANGUAGES CXX
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# BLD-006/BLD-007: diagnose compiler, CMake, generator and module scanning as
# one compatibility unit, and fail configure with observed values when the
# toolchain cannot build project-owned C++ modules at C++26.
include(OpenProofToolchainGuard)
openproof_require_supported_toolchain()

include(OpenProofCompileOptions)
include(OpenProofModule)

option(OPENPROOF_BUILD_TESTS "Build the OpenProof test suites" ON)
option(OPENPROOF_BUILD_EXAMPLES "Build OpenProof integration examples" ON)
option(OPENPROOF_BUILD_COVERAGE_FUZZER
    "Build the GCC sanitizer-coverage guided boundary fuzzer" OFF)

# External dependencies. SEC-006 requires a concrete reason for each.
#   OpenSSL        cryptographic primitives; the project never implements them.
#   tomlplusplus   typed configuration parsing (brief section 42).
#   Boost.Beast    bounded HTTP/1.1 listener and reverse-proxy transport.
#   GTest          unit, integration and security test suites.
find_package(OpenSSL 3.0 REQUIRED)
find_package(tomlplusplus REQUIRED)
find_package(Boost 1.88 REQUIRED)
find_program(OPENPROOF_PG_CONFIG NAMES pg_config REQUIRED)
execute_process(COMMAND "${OPENPROOF_PG_CONFIG}" --includedir
    OUTPUT_VARIABLE OPENPROOF_LIBPQ_INCLUDEDIR OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${OPENPROOF_PG_CONFIG}" --libdir
    OUTPUT_VARIABLE OPENPROOF_LIBPQ_LIBDIR OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${OPENPROOF_PG_CONFIG}" --version
    OUTPUT_VARIABLE OPENPROOF_LIBPQ_VERSION_TEXT OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" OPENPROOF_LIBPQ_VERSION
    "${OPENPROOF_LIBPQ_VERSION_TEXT}")
if(OPENPROOF_LIBPQ_VERSION VERSION_LESS 15)
    message(FATAL_ERROR "OpenProof requires libpq >= 15; pg_config reported '${OPENPROOF_LIBPQ_VERSION_TEXT}'.")
endif()
find_library(OPENPROOF_LIBPQ_LIBRARY NAMES pq HINTS "${OPENPROOF_LIBPQ_LIBDIR}" REQUIRED)
add_library(openproof_libpq UNKNOWN IMPORTED)
set_target_properties(openproof_libpq PROPERTIES
    IMPORTED_LOCATION "${OPENPROOF_LIBPQ_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENPROOF_LIBPQ_INCLUDEDIR}")
add_library(OpenProof::libpq ALIAS openproof_libpq)

add_subdirectory(src)

if(OPENPROOF_BUILD_COVERAGE_FUZZER)
    add_subdirectory(fuzz)
endif()

add_subdirectory(apps)
add_subdirectory(sdk/cpp)

if(OPENPROOF_BUILD_EXAMPLES)
    add_subdirectory(examples/reference-client)
endif()

if(OPENPROOF_BUILD_TESTS)
    enable_testing()

    # GoogleTest is built from source rather than taken from a system package.
    #
    # A prebuilt GoogleTest may be compiled against a different C++ standard
    # library or ABI than the verified GCC 16 toolchain. Building it here keeps
    # the test framework on the same compiler/runtime ABI as OpenProof instead
    # of relying on a machine-specific prebuilt package.
    #
    # Pinned by URL and SHA-256 so the dependency is reproducible and cannot be
    # silently replaced upstream (SEC-006).
    include(FetchContent)
    FetchContent_Declare(googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz
        URL_HASH SHA256=65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_subdirectory(tests)
endif()

message(STATUS "OpenProof Protocol ${PROJECT_VERSION}")
message(STATUS "  build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  tests      : ${OPENPROOF_BUILD_TESTS}")
message(STATUS "  OpenSSL    : ${OPENSSL_VERSION}")
