# Target-local compile options for the OpenProof Protocol.
#
# BLD-003 requires target-local options rather than mutation of global compiler
# flags, so the project exposes an INTERFACE target that individual targets link
# privately. Nothing here touches CMAKE_CXX_FLAGS.
#
# Warnings are errors. VER-004 makes any warning introduced by a change part of
# the change, and a security platform cannot afford a warning backlog that hides
# a genuine defect.

include_guard(GLOBAL)

add_library(openproof_compile_options INTERFACE)
add_library(openproof::compile_options ALIAS openproof_compile_options)

# GCC module BMIs are binary compiler state, not portable object files.  A BMI
# produced with a different compiler build, SDK root, architecture, generator,
# or module-cache schema can fail later with opaque diagnostics such as
# "failed to read compiled module cluster ...: Bad file data".  CMake tracks
# ordinary command-line changes, but a previously interrupted/stale BMI may
# still survive in an IDE build tree.  Stamp every compile command with a
# deterministic toolchain fingerprint and purge project-owned GCC CMIs when the
# fingerprint changes.  OPENPROOF_MODULE_CACHE_EPOCH is bumped only when the
# module build contract itself changes.
# Epoch 3 adds source-sensitive invalidation.  A C++ module BMI can remain
# semantically stale even when the source file shown in a diagnostic has
# changed: GCC stores declaration state in the .gcm while diagnostics reopen
# the current source text for line rendering.  Make every project module
# interface an explicit CMake configure dependency and fold its content hash
# into the build fingerprint so an interface edit forces reconfigure, purges
# old .gcm files, and changes every module consumer command line.
set(OPENPROOF_MODULE_CACHE_EPOCH 3)

file(GLOB_RECURSE _openproof_module_interface_sources
    CONFIGURE_DEPENDS
    LIST_DIRECTORIES FALSE
    "${CMAKE_SOURCE_DIR}/src/*.cppm"
    "${CMAKE_SOURCE_DIR}/sdk/*.cppm"
    "${CMAKE_SOURCE_DIR}/apps/*.cppm"
    "${CMAKE_SOURCE_DIR}/examples/*.cppm"
    "${CMAKE_SOURCE_DIR}/tests/*.cppm")
list(SORT _openproof_module_interface_sources)
if(_openproof_module_interface_sources)
    set_property(DIRECTORY "${CMAKE_SOURCE_DIR}" APPEND PROPERTY
        CMAKE_CONFIGURE_DEPENDS ${_openproof_module_interface_sources})
endif()

set(_openproof_module_source_material "")
foreach(_openproof_module_source IN LISTS _openproof_module_interface_sources)
    file(SHA256 "${_openproof_module_source}" _openproof_module_source_sha256)
    file(RELATIVE_PATH _openproof_module_source_relative
        "${CMAKE_SOURCE_DIR}" "${_openproof_module_source}")
    string(APPEND _openproof_module_source_material
        "${_openproof_module_source_relative}=${_openproof_module_source_sha256};")
endforeach()
string(SHA256 OPENPROOF_MODULE_SOURCE_FINGERPRINT
    "${_openproof_module_source_material}")
string(SUBSTRING "${OPENPROOF_MODULE_SOURCE_FINGERPRINT}" 0 16
    OPENPROOF_MODULE_SOURCE_FINGERPRINT_SHORT)
set(_openproof_module_fingerprint_material
    "epoch=${OPENPROOF_MODULE_CACHE_EPOCH};"
    "compiler=${CMAKE_CXX_COMPILER};"
    "compiler_id=${CMAKE_CXX_COMPILER_ID};"
    "compiler_version=${CMAKE_CXX_COMPILER_VERSION};"
    "generator=${CMAKE_GENERATOR};"
    "system=${CMAKE_SYSTEM_NAME};"
    "system_version=${CMAKE_SYSTEM_VERSION};"
    "sysroot=${CMAKE_OSX_SYSROOT};"
    "architectures=${CMAKE_OSX_ARCHITECTURES};"
    "cmake=${CMAKE_VERSION};"
    "module_sources=${OPENPROOF_MODULE_SOURCE_FINGERPRINT}")
string(SHA256 OPENPROOF_MODULE_BUILD_FINGERPRINT
    "${_openproof_module_fingerprint_material}")
string(SUBSTRING "${OPENPROOF_MODULE_BUILD_FINGERPRINT}" 0 16
    OPENPROOF_MODULE_BUILD_FINGERPRINT_SHORT)
set(OPENPROOF_MODULE_BUILD_FINGERPRINT
    "${OPENPROOF_MODULE_BUILD_FINGERPRINT}" CACHE INTERNAL
    "OpenProof C++ module toolchain fingerprint" FORCE)

set(_openproof_module_stamp
    "${CMAKE_BINARY_DIR}/.openproof-module-fingerprint")
set(_openproof_previous_module_fingerprint "")
if(EXISTS "${_openproof_module_stamp}")
    file(READ "${_openproof_module_stamp}"
        _openproof_previous_module_fingerprint)
    string(STRIP "${_openproof_previous_module_fingerprint}"
        _openproof_previous_module_fingerprint)
endif()

if(NOT _openproof_previous_module_fingerprint STREQUAL
       OPENPROOF_MODULE_BUILD_FINGERPRINT)
    file(GLOB_RECURSE _openproof_stale_gcms LIST_DIRECTORIES FALSE
        "${CMAKE_BINARY_DIR}/*.gcm")
    list(LENGTH _openproof_stale_gcms _openproof_stale_gcm_count)
    if(_openproof_stale_gcm_count GREATER 0)
        file(REMOVE ${_openproof_stale_gcms})
        message(STATUS
            "OpenProof: invalidated ${_openproof_stale_gcm_count} stale GCC module BMI(s) after toolchain/module fingerprint change.")
    endif()
    file(WRITE "${_openproof_module_stamp}"
        "${OPENPROOF_MODULE_BUILD_FINGERPRINT}\n")
endif()

target_compile_definitions(openproof_compile_options INTERFACE
    OPENPROOF_MODULE_BUILD_FINGERPRINT=0x${OPENPROOF_MODULE_BUILD_FINGERPRINT_SHORT}ULL)

message(STATUS
    "OpenProof: module source fingerprint = ${OPENPROOF_MODULE_SOURCE_FINGERPRINT_SHORT}")
message(STATUS
    "OpenProof: module build fingerprint = ${OPENPROOF_MODULE_BUILD_FINGERPRINT_SHORT} (epoch ${OPENPROOF_MODULE_CACHE_EPOCH})")

option(OPENPROOF_ENABLE_SANITIZERS
    "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(openproof_compile_options INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wcast-qual
        -Wunused
        -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wdouble-promotion
        -Wformat=2
        -Wimplicit-fallthrough
        -Wextra-semi
        -Wundef
        -Werror
    )

    # Defence in depth at the compiler level. These are cheap and apply to every
    # translation unit that links this INTERFACE target.
    target_compile_options(openproof_compile_options INTERFACE
        -fstack-protector-strong
        -fno-common
    )
    target_compile_definitions(openproof_compile_options INTERFACE
        $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>
    )
endif()

if(OPENPROOF_ENABLE_SANITIZERS)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        message(FATAL_ERROR "OPENPROOF_ENABLE_SANITIZERS is verified only with the required GNU toolchain.")
    endif()
    target_compile_options(openproof_compile_options INTERFACE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer)
    target_link_options(openproof_compile_options INTERFACE
        -fsanitize=address,undefined)
endif()

# C++26 contracts (P2900) -- experimental opt-in only.
#
# GCC 16.1 ships Contracts as an experimental feature. In combination with
# project-owned C++ modules on Darwin it can trigger front-end ICEs while
# compiling otherwise ordinary exported value types. OpenProof therefore keeps
# production builds off the experimental compiler path and enforces internal
# invariants through foundation::requireInvariant instead.
#
# This option exists only for compiler qualification/research. Enabling it does
# not change the source-level invariant mechanism and is not a production
# configuration until a complete clean build/test qualification is recorded.
option(OPENPROOF_ENABLE_EXPERIMENTAL_CONTRACTS
    "Enable GCC's experimental C++26 Contracts implementation" OFF)

set(OPENPROOF_CONTRACT_SEMANTIC "enforce" CACHE STRING
    "Experimental C++26 contract evaluation semantic: ignore, observe, enforce, quick_enforce")
set_property(CACHE OPENPROOF_CONTRACT_SEMANTIC PROPERTY STRINGS
    ignore observe enforce quick_enforce)

if(NOT OPENPROOF_CONTRACT_SEMANTIC MATCHES "^(ignore|observe|enforce|quick_enforce)$")
    message(FATAL_ERROR
        "OPENPROOF_CONTRACT_SEMANTIC is '${OPENPROOF_CONTRACT_SEMANTIC}'. "
        "Use ignore, observe, enforce, or quick_enforce.")
endif()

if(OPENPROOF_ENABLE_EXPERIMENTAL_CONTRACTS)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        message(FATAL_ERROR
            "OPENPROOF_ENABLE_EXPERIMENTAL_CONTRACTS is supported only for GCC qualification builds.")
    endif()
    target_compile_options(openproof_compile_options INTERFACE
        -fcontracts
        "-fcontract-evaluation-semantic=${OPENPROOF_CONTRACT_SEMANTIC}"
    )
    target_link_options(openproof_compile_options INTERFACE -fcontracts)
    message(WARNING
        "OpenProof: experimental GCC Contracts are ENABLED. This configuration is not production-qualified.")
else()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        # Be explicit so user/toolchain environment flags cannot accidentally
        # re-enable the experimental front-end path.
        target_compile_options(openproof_compile_options INTERFACE -fno-contracts)
    endif()
    message(STATUS
        "OpenProof: production stability profile enabled; experimental C++26 Contracts are disabled.")
endif()

# Internal invariant failures always terminate under the production stability
# profile. Keep the definition for compatibility with existing tests/tools.
target_compile_definitions(openproof_compile_options INTERFACE
    OPENPROOF_CONTRACTS_TERMINATE=1
    OPENPROOF_EXPERIMENTAL_CONTRACTS=$<BOOL:${OPENPROOF_ENABLE_EXPERIMENTAL_CONTRACTS}>
)

# C++26 reflection (P2996, GCC PR120775) is NOT enabled, and the reason is a
# compiler defect rather than a preference.
#
# Reflection itself works on this toolchain: `^^E`, std::meta::enumerators_of,
# std::meta::identifier_of and `template for` all compile and run correctly in an
# ordinary translation unit under -std=c++26 -freflection.
#
# But -freflection breaks this project's module build. Reduced to a minimal case
# on GCC 16.1.0 / aarch64-apple-darwin: a module *partition* that includes a
# standard header in its global module fragment and imports a sibling partition
# fails with "conflicting imported declaration" for libstdc++ and SDK typedefs
# (__mbstate_t, std::streampos, ...). Zero errors without the flag, six with it,
# and no reflection used anywhere in the source.
#
#   module;  #include <string>
#   export module part.m:error;   // partition A
#
#   module;  #include <expected>
#   export module part.m:result;  // partition B
#   import :error;                // <-- fails only when -freflection is on
#
# openproof.foundation, openproof.observability, openproof.security, openproof.storage and
# openproof.identity.provider are all built from partitions, so enabling the flag
# breaks the build globally. Turning it on for only some targets would leave the
# codebase compiled two different ways, which is worse than not using it.
#
# Revisit when the defect is fixed. Nothing in the source depends on reflection,
# so enabling it later is a one-line change plus the enum-name rewrite described
# in docs/CXX26.md.

message(STATUS
    "OpenProof: C++26 reflection is available on this compiler but is NOT enabled; -freflection "
    "miscompiles module partitions on GCC 16.1.0 (see cmake/OpenProofCompileOptions.cmake).")

# Relaxations that apply only to test translation units. GoogleTest's macros
# expand to constructs that a project-strict warning set rejects, and rewriting
# a third-party macro expansion is not a useful defect signal.
add_library(openproof_test_compile_options INTERFACE)
add_library(openproof::test_compile_options ALIAS openproof_test_compile_options)

target_link_libraries(openproof_test_compile_options INTERFACE openproof_compile_options)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(openproof_test_compile_options INTERFACE
        -Wno-used-but-marked-unused
        -Wno-global-constructors
        -Wno-exit-time-destructors
    )
endif()
