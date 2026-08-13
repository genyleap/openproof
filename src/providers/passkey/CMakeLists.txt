openproof_add_module(openproof_provider_passkey
    MODULES
        passkey.cppm
    SOURCES
        passkey.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_core
        openproof_identity_provider
    LINK_PRIVATE
        openproof_security
        Boost::headers
        OpenSSL::Crypto
)

# Boost.Config on Darwin/GNU strict mode can suppress long long detection.
# Boost.System requires boost::ulong_long_type, so restore the capability
# explicitly for this Boost-consuming target.
target_compile_definitions(openproof_provider_passkey PRIVATE BOOST_HAS_LONG_LONG=1)
