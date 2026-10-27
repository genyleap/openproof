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

openproof_add_module(openproof_storage_postgres
    MODULES
        postgres.cppm
    SOURCES
        postgres.cpp
        session_domain.cpp
        coroutine_session_repository.cpp
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

# The exported coroutine repository now names Boost.Asio awaitables in the
# storage module's global fragment, just like openproof_gateway_http.
# Keep the Darwin/GCC Boost.Config long-long correction target-local.
target_compile_definitions(openproof_storage_postgres PRIVATE
    BOOST_HAS_LONG_LONG=1)
