openproof_add_module(openproof_evidence_verifiers
    MODULES
        verifiers.cppm
    SOURCES
        verifiers.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_evidence
        openproof_identity_core
        openproof_identity_provider
    LINK_PRIVATE
        openproof_security
        Boost::headers
        OpenSSL::Crypto
)

target_compile_definitions(openproof_evidence_verifiers PRIVATE BOOST_HAS_LONG_LONG=1)
