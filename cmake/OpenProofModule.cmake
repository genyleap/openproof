# Helper for declaring project-owned C++ module targets.
#
# Canonical rules: BLD-001 (target-based CMake), BLD-002 (module interfaces are
# declared through target_sources(... FILE_SET CXX_MODULES ...)), BLD-004
# (CXX_SCAN_FOR_MODULES enabled for targets producing or consuming project
# modules), MOD-002/MOD-003 (exported declarations in .cppm; non-trivial
# implementation normally in .cpp, with private .cppm partitions reserved for
# compiler-boundary cases where a primary implementation unit is not reliable).
#
# The helper exists so that every module target is registered identically. It
# does not hide the module architecture: MODULES are public .cppm interface
# units, PRIVATE_MODULES are non-exported .cppm partitions, and SOURCES are
# ordinary private implementation units.

include_guard(GLOBAL)

# GCC's C++ module reader/writer is sensitive to concurrent BMI production on
# Darwin.  CMake correctly computes import ordering, but serializing the actual
# compile actions removes a second source of nondeterminism: a consumer cannot
# observe a partially written or concurrently replaced .gcm.  This is limited
# to the qualified GNU/Darwin profile; other platforms retain normal parallel
# compilation.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_property(GLOBAL APPEND PROPERTY JOB_POOLS openproof_gnu_darwin_modules=1)
endif()

# openproof_add_module(<target>
#     MODULES      <interface .cppm units, at least one>
#     [PRIVATE_MODULES <non-exported module partition .cppm units>]
#     [SOURCES     <implementation .cpp units>]
#     [LINK_PUBLIC <targets whose modules this target's interface imports>]
#     [LINK_PRIVATE <targets used only by the implementation>]
# )
#
# Creates a static library plus a `openproof::`-prefixed alias derived from the
# target name (openproof_identity_provider -> openproof::identity::provider).
function(openproof_add_module TARGET)
    cmake_parse_arguments(PARSE_ARGV 1 ARG "" "" "MODULES;PRIVATE_MODULES;SOURCES;LINK_PUBLIC;LINK_PRIVATE")

    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "openproof_add_module(${TARGET}): unexpected arguments '${ARG_UNPARSED_ARGUMENTS}'.")
    endif()
    if(NOT ARG_MODULES)
        message(FATAL_ERROR
            "openproof_add_module(${TARGET}): at least one MODULES entry is required. A OpenProof module "
            "target always owns its .cppm interface units.")
    endif()

    foreach(interface_unit IN LISTS ARG_MODULES ARG_PRIVATE_MODULES)
        if(NOT interface_unit MATCHES "\\.cppm$")
            message(FATAL_ERROR
                "openproof_add_module(${TARGET}): '${interface_unit}' is listed as a module interface/partition "
                "unit but does not use the .cppm extension (MOD-002).")
        endif()
    endforeach()

    add_library(${TARGET} STATIC)

    string(REPLACE "_" "::" target_alias "${TARGET}")
    add_library(${target_alias} ALIAS ${TARGET})

    target_compile_features(${TARGET} PUBLIC cxx_std_26)

    target_sources(${TARGET}
        PUBLIC
            FILE_SET CXX_MODULES
            BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
            FILES ${ARG_MODULES}
    )

    if(ARG_PRIVATE_MODULES)
        target_sources(${TARGET}
            PRIVATE
                FILE_SET openproof_private_modules TYPE CXX_MODULES
                BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
                FILES ${ARG_PRIVATE_MODULES}
        )
    endif()

    if(ARG_SOURCES)
        target_sources(${TARGET} PRIVATE ${ARG_SOURCES})
    endif()

    set_target_properties(${TARGET} PROPERTIES
        CXX_SCAN_FOR_MODULES ON
        CXX_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
    )

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set_property(TARGET ${TARGET} PROPERTY JOB_POOL_COMPILE
            openproof_gnu_darwin_modules)
    endif()

    target_link_libraries(${TARGET} PRIVATE openproof_compile_options)

    if(ARG_LINK_PUBLIC)
        target_link_libraries(${TARGET} PUBLIC ${ARG_LINK_PUBLIC})
    endif()
    if(ARG_LINK_PRIVATE)
        target_link_libraries(${TARGET} PRIVATE ${ARG_LINK_PRIVATE})
    endif()
endfunction()
