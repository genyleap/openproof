# One test executable covers the public module interfaces. Tests import the
# same module surface used by downstream consumers rather than implementation units.
add_executable(openproof_tests
    foundation/error_test.cpp
    foundation/result_test.cpp
    foundation/json_test.cpp
    foundation/encoding_test.cpp
    foundation/secret_test.cpp
    foundation/id_test.cpp
    foundation/time_test.cpp
    security/security_test.cpp
    observability/log_test.cpp
    audit/audit_test.cpp
    telemetry/telemetry_test.cpp
    hardening/hardening_test.cpp
    operations/health_test.cpp
    config/config_test.cpp
    identity/repository_test.cpp
    identity/provider_test.cpp
    identity/core_test.cpp
    policy/decision_test.cpp
    identity/transaction_test.cpp
    authentication/service_test.cpp
    authentication/http_test.cpp
    account/account_test.cpp
    administration/administration_test.cpp
    administration/http_test.cpp
    session/session_test.cpp
    credentials/credentials_test.cpp
    providers/local_test.cpp
    providers/oidc_test.cpp
    providers/enterprise_test.cpp
    providers/github_test.cpp
    providers/x_test.cpp
    providers/passkey_test.cpp
    providers/web3_test.cpp
    gateway/gateway_test.cpp
    # The Beast wire suite has its own executable below. Compiling it into
    # the umbrella binary duplicates GCC16/Boost.Asio TSS definitions when
    # linked with independent OAuth provider objects.
    storage/postgres_integration_test.cpp
    identity/merge_test.cpp
    organization/organization_test.cpp
    platform/identity_platform_test.cpp
    enterprise/scim_test.cpp
    evidence/verification_test.cpp
)

target_compile_features(openproof_tests PRIVATE cxx_std_26)

# Homebrew dependencies contribute `/opt/homebrew/include` for OpenSSL/libpq.
# That broad directory may also contain an unrelated system GoogleTest version;
# if it precedes the pinned FetchContent headers, test objects compile against a
# different ABI than libgtest.a. Put the pinned headers first explicitly.
target_include_directories(openproof_tests BEFORE PRIVATE
    "${googletest_SOURCE_DIR}/googletest/include"
    "${googletest_SOURCE_DIR}/googletest")

# Same Boost.Config Darwin/GCC correction as the HTTP adapter target.
# The Beast wire tests are compiled exclusively by openproof_gateway_http_tests.
target_compile_definitions(openproof_tests PRIVATE BOOST_HAS_LONG_LONG=1)
target_compile_definitions(openproof_tests PRIVATE
    OPENPROOF_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

set_target_properties(openproof_tests PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF
)

# CI uses a private GCC 16 runtime that is newer than Ubuntu 24.04's system
# libstdc++. Link the test runner's C++ runtime statically so CTest does not
# depend on the runner's older dynamic libstdc++ after compilation succeeds.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND UNIX AND NOT APPLE)
    target_link_options(openproof_tests PRIVATE -static-libstdc++ -static-libgcc)
endif()

target_link_libraries(openproof_tests
    PRIVATE
        openproof_foundation
        openproof_administration
        openproof_security
        openproof_observability
        openproof_audit
        openproof_telemetry
        openproof_config
        openproof_identity_provider
        openproof_authentication
        openproof_authentication_http
        openproof_account
        openproof_session
        openproof_credentials
        openproof_provider_local
        openproof_provider_oidc
        openproof_provider_enterprise
        openproof_provider_github
        openproof_provider_x
        openproof_provider_passkey
        openproof_provider_web3
        openproof_gateway
        openproof_gateway_http
        Boost::headers
        openproof_storage_postgres
        openproof_operations_http
        openproof_credentials
        OpenProof::libpq
        openproof_identity_core
        openproof_identity_profile
        openproof_policy
        openproof_organization
        openproof_application
        openproof_client
        openproof_oauth
        openproof_token
        openproof_oidc
        openproof_evidence
        openproof_evidence_verifiers
        openproof_enterprise_scim
        openproof_trust
        openproof_sdk_cpp
        GTest::gtest
        GTest::gtest_main
        openproof_test_compile_options
)

include(GoogleTest)

# TST-006: a run that discovers zero tests is a failed run, not a passing one.
# PRE_TEST discovery runs `--gtest_list_tests` when the suite is invoked rather
# than at build time. Listing takes ~0.1s here, but the default 5s budget is
# shared with process startup and has been observed to expire on a machine busy
# with a parallel build, turning a green suite into a spurious CTest error. The
# generous timeout costs nothing on a healthy run.
gtest_discover_tests(openproof_tests
    DISCOVERY_MODE PRE_TEST
    DISCOVERY_TIMEOUT 120
    PROPERTIES LABELS "unit"
)

# Lightweight validation target for the HTTP concurrency/overload boundary.
# Does not require compiling the PostgreSQL, OAuth or provider integration suite.
add_executable(openproof_gateway_http_tests gateway/http_integration_test.cpp)
target_compile_features(openproof_gateway_http_tests PRIVATE cxx_std_26)
target_include_directories(openproof_gateway_http_tests BEFORE PRIVATE
    "${googletest_SOURCE_DIR}/googletest/include"
    "${googletest_SOURCE_DIR}/googletest")
target_compile_definitions(openproof_gateway_http_tests PRIVATE BOOST_HAS_LONG_LONG=1)
set_target_properties(openproof_gateway_http_tests PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 16)
    set_source_files_properties(gateway/http_integration_test.cpp PROPERTIES
        COMPILE_OPTIONS "-Wno-error=array-bounds")
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND UNIX AND NOT APPLE)
    target_link_options(openproof_gateway_http_tests PRIVATE -static-libstdc++ -static-libgcc)
endif()
target_link_libraries(openproof_gateway_http_tests PRIVATE
    openproof_gateway_http
    openproof_gateway
    openproof_foundation
    openproof_session
    openproof_policy
    openproof_security
    Boost::headers
    GTest::gtest_main
    openproof_test_compile_options)
gtest_discover_tests(openproof_gateway_http_tests
    TEST_PREFIX "FocusedGateway."
    DISCOVERY_MODE PRE_TEST
    DISCOVERY_TIMEOUT 120
    PROPERTIES LABELS "gateway")

# Direct C++ module boundary test for the native PostgreSQL session adapter.
# This intentionally links the real domain module, not a duplicate model.
add_executable(openproof_postgres_domain_tests
    storage/postgres_async_domain_test.cpp
    storage/postgres_coroutine_repository_integration_test.cpp)
target_compile_features(openproof_postgres_domain_tests PRIVATE cxx_std_26)
target_compile_definitions(openproof_postgres_domain_tests PRIVATE
    BOOST_HAS_LONG_LONG=1
    OPENPROOF_SOURCE_DIR=\"${PROJECT_SOURCE_DIR}\")
set_target_properties(openproof_postgres_domain_tests PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF)
target_link_libraries(openproof_postgres_domain_tests PRIVATE
    openproof_storage_postgres openproof_session openproof_foundation
    Boost::headers OpenProof::libpq GTest::gtest_main openproof_test_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND UNIX AND NOT APPLE)
    target_link_options(openproof_postgres_domain_tests PRIVATE
        -static-libstdc++ -static-libgcc)
endif()
gtest_discover_tests(openproof_postgres_domain_tests
    TEST_PREFIX "NativePostgresDomain."
    DISCOVERY_MODE PRE_TEST
    DISCOVERY_TIMEOUT 120
    PROPERTIES LABELS "postgres;async;domain")

# Native libpq coroutine adapter, isolated from existing synchronous repositories
# until transaction ownership and async repository APIs are fully migrated.
add_executable(openproof_postgres_async_tests
    storage/postgres_async_test.cpp
    storage/postgres_async_pool_test.cpp
    storage/postgres_async_session_test.cpp)
target_compile_features(openproof_postgres_async_tests PRIVATE cxx_std_26)
target_include_directories(openproof_postgres_async_tests PRIVATE
    "${PROJECT_SOURCE_DIR}/src/storage/postgres"
    "${googletest_SOURCE_DIR}/googletest/include")
target_compile_definitions(openproof_postgres_async_tests PRIVATE BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_postgres_async_tests PRIVATE
    openproof_postgres_async_io GTest::gtest_main
    openproof_test_compile_options)
# GCC 16 -O2 can mistake Boost.Asio's custom aligned coroutine-frame
# allocator for a mismatched new/delete when it inlines long test coroutines.
# Demote only this warning in this one TEST translation unit; all production
# sources and other diagnostics retain -Werror, and the warning stays visible.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(storage/postgres_async_session_test.cpp
        PROPERTIES COMPILE_OPTIONS "-Wno-error=mismatched-new-delete")
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND UNIX AND NOT APPLE)
    target_link_options(openproof_postgres_async_tests PRIVATE
        -static-libstdc++ -static-libgcc)
endif()
gtest_discover_tests(openproof_postgres_async_tests
    TEST_PREFIX "NativePostgres."
    DISCOVERY_MODE PRE_TEST
    DISCOVERY_TIMEOUT 120
    PROPERTIES LABELS "postgres;async")
