# Native socket-driven libpq implementation, independent of the legacy
# synchronous repository SPI until transaction and lease lifetimes are migrated.
# Build it as a normal translation unit to avoid leaking Boost.Asio types
# through the OpenProof C++ module interfaces.
add_library(openproof_postgres_async_io STATIC
    async_connection.cpp
    async_pool.cpp
    async_session.cpp)
target_compile_features(openproof_postgres_async_io PUBLIC cxx_std_26)
target_include_directories(openproof_postgres_async_io PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(openproof_postgres_async_io
    PUBLIC Boost::headers OpenProof::libpq
    PRIVATE openproof_compile_options)
target_compile_definitions(openproof_postgres_async_io PRIVATE
    BOOST_HAS_LONG_LONG=1)
set_target_properties(openproof_postgres_async_io PROPERTIES
    POSITION_INDEPENDENT_CODE ON)
# GCC 16.2 incorrectly diagnoses Boost.Asio's aligned awaitable allocation
# when the new replacement coroutine is inlined into the surrounding SQL
# adapter. Preserve -Werror (including mismatched-new-delete) instead of
# suppressing any diagnostic. No application or protocol module is affected.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(async_session.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()

openproof_add_module(openproof_storage_postgres
    MODULES
        postgres.cppm
    SOURCES
        postgres.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_account
        openproof_administration
        openproof_audit
        openproof_security
        openproof_identity_core
        openproof_identity_provider
        openproof_identity_profile
        openproof_application
        openproof_client
        openproof_resource
        openproof_consent
        openproof_evidence
        openproof_evidence_verifiers
        openproof_enterprise_scim
        openproof_oauth
        openproof_token
        openproof_session
        openproof_credentials
        openproof_provider_local
        openproof_provider_passkey
        openproof_organization
        openproof_policy
    LINK_PRIVATE
        OpenProof::libpq
        openproof_postgres_async_io
)

# Keep native Asio types in ordinary C++ translation units rather than
# attaching their Boost headers (and thread-local template definitions) to
# the exported storage module. GCC 16 otherwise produces duplicate symbols
# when a test/executable uses both imports and Boost.Asio includes.
add_library(openproof_postgres_async_repository STATIC
    session_domain.cpp
    coroutine_session_repository.cpp
    coroutine_session_authenticator.cpp
    coroutine_session_service.cpp)
target_compile_features(openproof_postgres_async_repository PUBLIC cxx_std_26)
target_include_directories(openproof_postgres_async_repository PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(openproof_postgres_async_repository PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_postgres_async_repository PRIVATE
    BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_postgres_async_repository
    PUBLIC openproof_storage_postgres openproof_postgres_async_io
        openproof_session openproof_foundation Boost::headers
    PRIVATE openproof_compile_options)

# GCC 16.2 misidentifies Boost.Asio's own aligned coroutine-frame
# allocator as mismatched new/delete when inlining the session service and
# repository replacement awaitable frames. Preserve -Werror and diagnostic
# coverage; disable inlining only for these transitional storage units.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(
        coroutine_session_repository.cpp coroutine_session_service.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()

# Authentication/session HTTP routes are a separate, opt-in coroutine
# transport facade; production's synchronous auth handler is not rewired.
add_library(openproof_postgres_async_http STATIC coroutine_session_http.cpp)
target_compile_features(openproof_postgres_async_http PUBLIC cxx_std_26)
target_include_directories(openproof_postgres_async_http PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(openproof_postgres_async_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_postgres_async_http PRIVATE
    BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_postgres_async_http
    PUBLIC openproof_postgres_async_repository
        openproof_gateway openproof_foundation Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # GCC 16 misattributes aligned allocations in Boost.Asio awaitable frames.
    # Do not remove -Werror or the allocation diagnostic.
    set_source_files_properties(coroutine_session_http.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()

# Explicit opt-in network listener bridge. Production does not link this
# target until the authenticated request chain is fully coroutine-driven.
add_library(openproof_postgres_async_listener STATIC coroutine_session_listener.cpp)
target_compile_features(openproof_postgres_async_listener PUBLIC cxx_std_26)
target_include_directories(openproof_postgres_async_listener PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(openproof_postgres_async_listener PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_postgres_async_listener PRIVATE
    BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_postgres_async_listener
    PUBLIC openproof_postgres_async_http openproof_gateway_http
        openproof_gateway openproof_foundation Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_session_listener.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
