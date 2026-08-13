openproof_add_module(openproof_provider_github
    MODULES
        github.cppm
    SOURCES
        github.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_provider
    LINK_PRIVATE
        openproof_security
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
)

target_compile_definitions(openproof_provider_github PRIVATE BOOST_HAS_LONG_LONG=1)
