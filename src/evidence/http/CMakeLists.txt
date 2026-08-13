openproof_add_module(openproof_evidence_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_evidence
        openproof_evidence_verifiers
        openproof_trust
        openproof_session
        openproof_gateway
        openproof_identity_core
        openproof_identity_provider
    LINK_PRIVATE
        Boost::headers
)

target_compile_definitions(openproof_evidence_http PRIVATE BOOST_HAS_LONG_LONG=1)
