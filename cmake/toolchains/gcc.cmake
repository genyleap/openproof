# Optional CMake toolchain file selecting an upstream GCC installation.
#
# GCC 16 is the project's primary toolchain because it is the only compiler on
# the supported platforms that implements the C++26 features this platform
# targets the qualified GCC 16 module/C++26 profile; experimental Contracts and Reflection are disabled by default. Historical feature probes include #embed, std::indirect/std::polymorphic,
# std::text_encoding and std::generator. See docs/03-CXX26.md.
#
# The prefix is discovered rather than hard-coded, so no machine-specific path
# is committed (SEC-001).
#
# Resolution order:
#   1. -DOPENPROOF_GCC_ROOT=<prefix>
#   2. environment variable OPENPROOF_GCC_ROOT
#   3. `brew --prefix gcc`, when Homebrew is present
#   4. a small list of conventional installation prefixes
#
# Usage:
#   cmake -S . -B build -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/gcc.cmake

if(NOT DEFINED OPENPROOF_GCC_ROOT AND DEFINED ENV{OPENPROOF_GCC_ROOT})
    set(OPENPROOF_GCC_ROOT "$ENV{OPENPROOF_GCC_ROOT}")
endif()

if(NOT DEFINED OPENPROOF_GCC_ROOT)
    find_program(OPENPROOF_BREW_EXECUTABLE brew)
    if(OPENPROOF_BREW_EXECUTABLE)
        execute_process(
            COMMAND "${OPENPROOF_BREW_EXECUTABLE}" --prefix gcc
            OUTPUT_VARIABLE OPENPROOF_BREW_GCC_PREFIX
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(OPENPROOF_BREW_GCC_PREFIX)
            set(OPENPROOF_GCC_ROOT "${OPENPROOF_BREW_GCC_PREFIX}")
        endif()
    endif()
endif()

if(NOT DEFINED OPENPROOF_GCC_ROOT)
    foreach(candidate /opt/homebrew /usr/local /usr)
        if(EXISTS "${candidate}/bin")
            set(OPENPROOF_GCC_ROOT "${candidate}")
            break()
        endif()
    endforeach()
endif()

# Homebrew and most distributions install version-suffixed drivers, and the
# unsuffixed `g++` on macOS is an Apple Clang shim rather than GCC.
foreach(version 20 19 18 17 16)
    if(NOT OPENPROOF_GCC_CXX_COMPILER AND EXISTS "${OPENPROOF_GCC_ROOT}/bin/g++-${version}")
        set(OPENPROOF_GCC_CXX_COMPILER "${OPENPROOF_GCC_ROOT}/bin/g++-${version}")
        set(OPENPROOF_GCC_C_COMPILER "${OPENPROOF_GCC_ROOT}/bin/gcc-${version}")
    endif()
endforeach()

if(NOT OPENPROOF_GCC_CXX_COMPILER AND EXISTS "${OPENPROOF_GCC_ROOT}/bin/g++")
    set(OPENPROOF_GCC_CXX_COMPILER "${OPENPROOF_GCC_ROOT}/bin/g++")
    set(OPENPROOF_GCC_C_COMPILER "${OPENPROOF_GCC_ROOT}/bin/gcc")
endif()

if(NOT OPENPROOF_GCC_CXX_COMPILER)
    message(FATAL_ERROR
        "cmake/toolchains/gcc.cmake could not locate a GCC installation.\n"
        "Remediation: pass -DOPENPROOF_GCC_ROOT=<prefix> or set the OPENPROOF_GCC_ROOT environment "
        "variable to a prefix containing bin/g++-16 (or a newer versioned driver).")
endif()

set(CMAKE_C_COMPILER "${OPENPROOF_GCC_C_COMPILER}" CACHE FILEPATH "C compiler")
set(CMAKE_CXX_COMPILER "${OPENPROOF_GCC_CXX_COMPILER}" CACHE FILEPATH "C++ compiler")
