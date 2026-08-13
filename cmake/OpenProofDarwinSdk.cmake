# Resolve one canonical macOS SDK before project() initializes the compiler.
#
# GCC C++ modules cannot safely mix declarations imported from different Apple
# SDK roots in one BMI. In particular, Xcode and CommandLineTools ship headers
# with the same logical names but different availability/counting annotations.
# A target that sees both roots can fail with conflicting Darwin typedefs or
# missing wint_t declarations while loading an otherwise valid module.

include_guard(GLOBAL)

function(openproof_configure_darwin_sdk)
    if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
        return()
    endif()

    set(candidate "")

    if(DEFINED CMAKE_OSX_SYSROOT AND NOT CMAKE_OSX_SYSROOT STREQUAL "")
        if(IS_ABSOLUTE "${CMAKE_OSX_SYSROOT}")
            set(candidate "${CMAKE_OSX_SYSROOT}")
        endif()
    endif()

    if(candidate STREQUAL "" AND DEFINED ENV{OPENPROOF_MACOS_SDKROOT}
       AND NOT "$ENV{OPENPROOF_MACOS_SDKROOT}" STREQUAL "")
        set(candidate "$ENV{OPENPROOF_MACOS_SDKROOT}")
    endif()

    if(candidate STREQUAL "")
        find_program(OPENPROOF_XCRUN_EXECUTABLE NAMES xcrun PATHS /usr/bin NO_DEFAULT_PATH)
        if(NOT OPENPROOF_XCRUN_EXECUTABLE)
            message(FATAL_ERROR
                "OpenProof requires xcrun to resolve one canonical macOS SDK. "
                "Set OPENPROOF_MACOS_SDKROOT to an absolute MacOSX.sdk path if xcrun is unavailable.")
        endif()

        execute_process(
            COMMAND "${OPENPROOF_XCRUN_EXECUTABLE}" --sdk macosx --show-sdk-path
            OUTPUT_VARIABLE candidate
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_VARIABLE xcrun_error
            RESULT_VARIABLE xcrun_result
        )
        if(NOT xcrun_result EQUAL 0 OR candidate STREQUAL "")
            message(FATAL_ERROR
                "OpenProof could not resolve the active macOS SDK with xcrun.\n"
                "xcrun output: ${xcrun_error}\n"
                "Remediation: select the intended Xcode with xcode-select or set "
                "OPENPROOF_MACOS_SDKROOT to its MacOSX.sdk path.")
        endif()
    endif()

    file(REAL_PATH "${candidate}" canonical_sdk)
    if(NOT IS_DIRECTORY "${canonical_sdk}")
        message(FATAL_ERROR "OpenProof macOS SDK does not exist: ${canonical_sdk}")
    endif()

    # Enterprise LDAP support requires the SDK framework. Refuse to silently
    # fall back to another developer tree because that recreates mixed SDK BMIs.
    if(NOT IS_DIRECTORY "${canonical_sdk}/System/Library/Frameworks/LDAP.framework")
        message(FATAL_ERROR
            "The selected macOS SDK does not contain LDAP.framework:\n  ${canonical_sdk}\n"
            "OpenProof will not mix this SDK with a second Xcode/CommandLineTools SDK.\n"
            "Remediation: select a full Xcode installation with xcode-select, or set "
            "OPENPROOF_MACOS_SDKROOT to the MacOSX.sdk inside that Xcode installation.")
    endif()

    set(CMAKE_OSX_SYSROOT "${canonical_sdk}" CACHE PATH
        "Canonical macOS SDK used by every OpenProof target" FORCE)
    set(OPENPROOF_MACOS_SDKROOT "${canonical_sdk}" CACHE INTERNAL
        "Canonical macOS SDK root selected by OpenProof")

    message(STATUS "OpenProof: canonical macOS SDK = ${canonical_sdk}")
endfunction()

function(openproof_require_path_in_macos_sdk label path)
    if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
        return()
    endif()
    if(NOT DEFINED OPENPROOF_MACOS_SDKROOT OR OPENPROOF_MACOS_SDKROOT STREQUAL "")
        message(FATAL_ERROR "OpenProof macOS SDK guard was not initialized before resolving ${label}.")
    endif()

    file(REAL_PATH "${path}" resolved)
    string(FIND "${resolved}" "${OPENPROOF_MACOS_SDKROOT}/" prefix_position)
    if(NOT prefix_position EQUAL 0 AND NOT resolved STREQUAL OPENPROOF_MACOS_SDKROOT)
        message(FATAL_ERROR
            "${label} resolved outside the canonical macOS SDK.\n"
            "  canonical SDK : ${OPENPROOF_MACOS_SDKROOT}\n"
            "  resolved path : ${resolved}\n"
            "Mixing Xcode and CommandLineTools SDK headers is unsupported with GCC C++ modules.")
    endif()
endfunction()
