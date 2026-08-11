openproof_add_module(openproof_gateway
    MODULES
        gateway.cppm
    SOURCES
        gateway.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_core
        openproof_identity_provider
        openproof_organization
        openproof_policy
        openproof_session
        openproof_security
)

openproof_add_module(openproof_gateway_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_gateway
    LINK_PRIVATE
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
        openproof_security
)

# Boost.Config 1.90 suppresses BOOST_HAS_LONG_LONG on Darwin whenever strict
# conformance is enabled, mistaking modern GCC for legacy Apple GCC. GCC 16
# supports long long; without this target-local correction Boost.System cannot
# declare its error-category identifier type.
target_compile_definitions(openproof_gateway_http PRIVATE BOOST_HAS_LONG_LONG=1)
