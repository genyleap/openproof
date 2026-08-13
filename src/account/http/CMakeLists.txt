openproof_add_module(openproof_account_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
        boost_json.cpp
    LINK_PUBLIC
        openproof_account
        openproof_foundation
        openproof_gateway
        openproof_identity_core
        openproof_identity_profile
        openproof_session
    LINK_PRIVATE
        Boost::headers
)

# Boost.Config on Darwin/GNU strict mode can suppress long long detection.
# Boost.System requires boost::ulong_long_type, so restore the capability
# explicitly for this Boost-consuming target.
target_compile_definitions(openproof_account_http PRIVATE BOOST_HAS_LONG_LONG=1)
