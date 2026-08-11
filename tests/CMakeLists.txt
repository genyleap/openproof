# One test executable covering every Phase 1 module. Tests consume the public
# module interfaces (`import openproof.foundation;`) and never the implementation
# units, so they exercise the same surface a downstream product would (TST-002).
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
    config/config_test.cpp
    identity/repository_test.cpp
    identity/provider_test.cpp
    identity/core_test.cpp
    policy/decision_test.cpp
    identity/transaction_test.cpp
    authentication/service_test.cpp
    session/session_test.cpp
    credentials/credentials_test.cpp
    providers/local_test.cpp
    gateway/gateway_test.cpp
    gateway/http_integration_test.cpp
    storage/postgres_integration_test.cpp
    identity/merge_test.cpp
    organization/organization_test.cpp
)

target_compile_features(openproof_tests PRIVATE cxx_std_26)

# Same Boost.Config Darwin/GCC correction as the HTTP adapter target. This test
# includes Beast directly to exercise the wire boundary.
target_compile_definitions(openproof_tests PRIVATE BOOST_HAS_LONG_LONG=1)
target_compile_definitions(openproof_tests PRIVATE
    OPENPROOF_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

set_target_properties(openproof_tests PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(openproof_tests
    PRIVATE
        openproof_foundation
        openproof_security
        openproof_observability
        openproof_audit
        openproof_telemetry
        openproof_config
        openproof_identity_provider
        openproof_authentication
        openproof_session
        openproof_credentials
        openproof_provider_local
        openproof_gateway
        openproof_gateway_http
        Boost::headers
        openproof_storage_postgres
        openproof_credentials
        OpenProof::libpq
        openproof_identity_core
        openproof_policy
        openproof_organization
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
