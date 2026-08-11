cmake_minimum_required(VERSION 3.30)

# INI-001/INI-003: "OpenProof Protocol" is the human-approved product name
# supplied in the engagement brief. All technical identifiers below are derived
# from it rather than invented.
#
#   Display name        OpenProof Protocol
#   Short name          OpenProof
#   Abbreviation        OPP
#   CMake project       openproof
#   C++ module prefix   openproof.
#   C++ namespace       openproof::
#   Binary              opp   (single binary; `opp server` runs the daemon)
#   Cache variables     OPENPROOF_*
#
# The protocol is vendor-neutral. No deployment-specific name appears in the
# core; a particular ecosystem is at most an example deployment.
project(openproof
    VERSION 0.1.0
    DESCRIPTION "OpenProof Protocol: an open protocol for identity, proof, trust and secure access"
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
add_subdirectory(apps)

if(OPENPROOF_BUILD_TESTS)
    enable_testing()

    # GoogleTest is built from source rather than taken from a system package.
    #
    # A prebuilt GoogleTest is compiled against one standard library, and this
    # project supports two toolchains: GCC 16 with libstdc++ and Clang 22 with
    # libc++. Linking a libc++ build of GoogleTest into a libstdc++ build fails
    # with hundreds of undefined std::__1:: symbols -- an ABI mismatch, not a
    # code defect. Building it here means the test framework always matches the
    # compiler under test.
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
