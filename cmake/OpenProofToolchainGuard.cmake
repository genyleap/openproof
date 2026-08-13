# Toolchain compatibility gate for the OpenProof Protocol.
#
# Canonical rules: BLD-006 (compiler, CMake, generator, language standard and
# module scanning form one compatibility unit), BLD-007 (unsupported toolchains
# fail at configure time with observed values and remediation), BLD-008 (never
# silently downgrade the language standard or the module architecture), and
# BLD-012 (a newer compiler major version is not automatically supported).
#
# This file deliberately does not probe, enable, or repair experimental
# standard-library modules (BLD-005, BLD-009, BLD-011, BLD-013). The project
# builds project-owned modules only, and consumes the standard library through
# ordinary headers placed in each module's global module fragment (MOD-010).

include_guard(GLOBAL)

set(OPENPROOF_MINIMUM_CMAKE_VERSION "3.30")
set(OPENPROOF_MINIMUM_CLANG_VERSION "22.0")
set(OPENPROOF_MINIMUM_GNU_VERSION "16.0")

# Combinations that have completed configure, build and test in this project.
# BLD-012 forbids inferring support from version numbers alone, so anything
# outside this list configures with an explicit "unverified" notice.
#
# GCC 16.1 is the qualified production toolchain for the current module graph.
# Experimental C++26 Contracts and Reflection are deliberately disabled in the
# production stability profile because their interaction with project-owned
# modules has not completed qualification. See docs/03-CXX26.md.
set(OPENPROOF_VERIFIED_TOOLCHAINS
    "GNU-16.1.0-Ninja-Darwin"
)

# Renders the observed toolchain facts that every diagnostic must quote.
function(openproof_toolchain_summary out_variable)
    set(summary
        "  CMAKE_VERSION            = ${CMAKE_VERSION}\n"
        "  CMAKE_GENERATOR          = ${CMAKE_GENERATOR}\n"
        "  CMAKE_SYSTEM_NAME        = ${CMAKE_SYSTEM_NAME}\n"
        "  CMAKE_CXX_COMPILER       = ${CMAKE_CXX_COMPILER}\n"
        "  CMAKE_CXX_COMPILER_ID    = ${CMAKE_CXX_COMPILER_ID}\n"
        "  CMAKE_CXX_COMPILER_VERSION = ${CMAKE_CXX_COMPILER_VERSION}\n"
        "  Requested C++ standard   = 26 (target-local, via target_compile_features)\n"
    )
    string(JOIN "" joined ${summary})
    set(${out_variable} "${joined}" PARENT_SCOPE)
endfunction()

# Hard-fails configure when the toolchain cannot build project-owned C++ modules
# at the required language level. Never relaxes the standard to obtain a green
# build (BLD-008).
function(openproof_require_supported_toolchain)
    openproof_toolchain_summary(observed)

    # The project itself declares only CXX, but GoogleTest's own
    # `project(googletest-distribution)` names no LANGUAGES, so CMake defaults it
    # to `C CXX` and a C compiler becomes mandatory for the test build.
    #
    # IDEs commonly fill both compiler fields with the same value, which puts a
    # C++ driver in CMAKE_C_COMPILER. Left alone, that surfaces much later as
    # `#error "The CMAKE_C_COMPILER is set to a C++ compiler"` from inside a
    # dependency, which points at the wrong project entirely. Catch it here.
    if(CMAKE_C_COMPILER)
        get_filename_component(c_compiler_name "${CMAKE_C_COMPILER}" NAME)
        if(c_compiler_name MATCHES "^(g\\+\\+|c\\+\\+|clang\\+\\+)")
            string(REGEX REPLACE "^g\\+\\+" "gcc" suggested "${c_compiler_name}")
            string(REGEX REPLACE "^c\\+\\+" "gcc" suggested "${suggested}")
            string(REGEX REPLACE "^clang\\+\\+" "clang" suggested "${suggested}")
            get_filename_component(c_compiler_dir "${CMAKE_C_COMPILER}" DIRECTORY)

            message(FATAL_ERROR
                "CMAKE_C_COMPILER is set to a C++ compiler.\n"
                "  CMAKE_C_COMPILER   = ${CMAKE_C_COMPILER}\n"
                "  CMAKE_CXX_COMPILER = ${CMAKE_CXX_COMPILER}\n"
                "A C compiler is required because GoogleTest enables the C language.\n"
                "Remediation: set the C compiler to '${c_compiler_dir}/${suggested}', or "
                "configure with a preset that sets both consistently:\n"
                "  cmake --preset gcc-debug\n"
                "In CLion: Settings > Build > CMake > Toolchain, set 'C Compiler' to the "
                "gcc driver rather than the g++ driver, or select a CMake profile that uses "
                "the 'gcc-debug' preset.")
        endif()
    endif()

    if(CMAKE_VERSION VERSION_LESS OPENPROOF_MINIMUM_CMAKE_VERSION)
        message(FATAL_ERROR
            "OpenProof Protocol requires CMake ${OPENPROOF_MINIMUM_CMAKE_VERSION} or newer for "
            "project-owned C++ module dependency scanning.\n"
            "Observed toolchain:\n${observed}"
            "Remediation: install CMake ${OPENPROOF_MINIMUM_CMAKE_VERSION}+ and reconfigure in a "
            "clean build directory.")
    endif()

    if(NOT CMAKE_GENERATOR MATCHES "Ninja")
        message(FATAL_ERROR
            "OpenProof Protocol requires the Ninja generator. Module dependency scanning "
            "(CXX_SCAN_FOR_MODULES) is not supported by the configured generator.\n"
            "Observed toolchain:\n${observed}"
            "Remediation: reconfigure a clean build directory with -G Ninja.")
    endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
        message(FATAL_ERROR
            "Apple Clang is not a supported toolchain for this project.\n"
            "Observed toolchain:\n${observed}"
            "Apple Clang version numbers are not comparable to upstream LLVM releases and the "
            "shipped release does not meet the project's C++ module requirements.\n"
            "Remediation: install upstream LLVM (Clang ${OPENPROOF_MINIMUM_CLANG_VERSION}+) and "
            "configure with -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/llvm.cmake, or set "
            "GIP_LLVM_ROOT to an LLVM installation prefix.")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR
            "Clang cannot build this project.\n"
            "Observed toolchain:\n${observed}"
            "The project uses C++26 contracts (P2900) and reflection (P2996) through standard "
            "syntax. Clang 22.1.8 implements neither: __cpp_contracts and __cpp_impl_reflection "
            "are both undefined, so `pre`, `post`, `contract_assert` and `^^` do not parse.\n"
            "Remediation: build with GCC 16 or newer, for example "
            "-DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/gcc.cmake. These features will not be "
            "wrapped in a portability macro to accommodate a compiler that lacks them; see "
            "docs/03-CXX26.md.")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS OPENPROOF_MINIMUM_GNU_VERSION)
            message(FATAL_ERROR
                "GCC ${OPENPROOF_MINIMUM_GNU_VERSION} or newer is required.\n"
                "Observed toolchain:\n${observed}"
                "Remediation: install a newer GCC. The language standard will not be lowered "
                "to accommodate an older compiler.")
        endif()
    else()
        message(FATAL_ERROR
            "Compiler '${CMAKE_CXX_COMPILER_ID}' has not been qualified for project-owned C++ "
            "modules in this project.\n"
            "Observed toolchain:\n${observed}"
            "Remediation: build with upstream Clang ${OPENPROOF_MINIMUM_CLANG_VERSION}+ or GCC "
            "${OPENPROOF_MINIMUM_GNU_VERSION}+, or qualify this compiler by completing a clean "
            "configure, full build and full test run before adding it to "
            "OPENPROOF_VERIFIED_TOOLCHAINS.")
    endif()

    string(REGEX REPLACE " .*" "" generator_key "${CMAKE_GENERATOR}")
    set(combination
        "${CMAKE_CXX_COMPILER_ID}-${CMAKE_CXX_COMPILER_VERSION}-${generator_key}-${CMAKE_SYSTEM_NAME}")
    if(NOT combination IN_LIST OPENPROOF_VERIFIED_TOOLCHAINS)
        message(STATUS
            "OpenProof: toolchain combination '${combination}' meets the minimum requirements but has "
            "not yet completed a recorded configure/build/test run in this project (BLD-012). "
            "Treat its results as unverified until recorded.")
    else()
        message(STATUS "OpenProof: using verified toolchain combination '${combination}'.")
    endif()
endfunction()
