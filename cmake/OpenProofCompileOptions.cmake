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

# C++26 contracts (P2900).
#
# `enforce` is the default and the recommended production setting. Contracts in
# this project guard internal invariants only -- never untrusted input, which is
# handled by openproof::foundation::Result -- so a violation means the platform's own
# state is corrupt. For an identity platform, stopping is safer than continuing
# to answer authorization questions from state known to be broken (secure
# default over convenient default).
#
# `observe` is offered for staged rollout: violations are reported by the
# handler and execution continues. It weakens the fail-closed guarantee and
# should not be used in production.
set(OPENPROOF_CONTRACT_SEMANTIC "enforce" CACHE STRING
    "C++26 contract evaluation semantic: ignore, observe, enforce, quick_enforce")
set_property(CACHE OPENPROOF_CONTRACT_SEMANTIC PROPERTY STRINGS
    ignore observe enforce quick_enforce)

if(NOT OPENPROOF_CONTRACT_SEMANTIC MATCHES "^(ignore|observe|enforce|quick_enforce)$")
    message(FATAL_ERROR
        "OPENPROOF_CONTRACT_SEMANTIC is '${OPENPROOF_CONTRACT_SEMANTIC}', which is not a C++26 contract "
        "evaluation semantic.\n"
        "Remediation: use one of ignore, observe, enforce, quick_enforce.")
endif()

# Contracts are used through standard syntax -- `pre`, `post`, `contract_assert`
# -- with no project macro facade, and violations are reported by the standard
# handler GCC links in. The project deliberately does not define
# ::handle_contract_violation: replacing it would substitute a bespoke diagnostic
# for the standard one, and the standard one already names the function, source
# location, predicate, assertion kind and evaluation semantic.
#
# -fcontracts must be passed at BOTH compile and link time. At compile time it
# enables the checks; at link time it pulls in the runtime support. Passing it
# only to the compiler yields an undefined reference to
# handle_contract_violation, which looks like a missing user handler and is not
# one -- it is a missing link flag.
target_compile_options(openproof_compile_options INTERFACE
    -fcontracts
    "-fcontract-evaluation-semantic=${OPENPROOF_CONTRACT_SEMANTIC}"
)

target_link_options(openproof_compile_options INTERFACE
    -fcontracts
)

# Whether a violated contract stops the process under the configured semantic.
# Tests that assert termination must not run under `observe`, where the contract
# reports and execution continues by design. Deriving this from the semantic
# keeps the two from drifting apart.
if(OPENPROOF_CONTRACT_SEMANTIC MATCHES "^(enforce|quick_enforce)$")
    set(OPENPROOF_CONTRACTS_TERMINATE 1)
else()
    set(OPENPROOF_CONTRACTS_TERMINATE 0)
endif()

target_compile_definitions(openproof_compile_options INTERFACE
    OPENPROOF_CONTRACTS_TERMINATE=${OPENPROOF_CONTRACTS_TERMINATE}
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
# in docs/03-CXX26.md.

message(STATUS "OpenProof: C++26 contracts enabled, semantic '${OPENPROOF_CONTRACT_SEMANTIC}'.")
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
