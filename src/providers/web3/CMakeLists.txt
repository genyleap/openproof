openproof_add_module(openproof_provider_web3
    MODULES
        web3.cppm
    SOURCES
        web3.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_provider
    LINK_PRIVATE
        openproof_security
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
)

target_compile_definitions(openproof_provider_web3 PRIVATE BOOST_HAS_LONG_LONG=1)
