openproof_add_module(openproof_authentication_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
        boost_json.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_security
        openproof_identity_provider
        openproof_authentication
        openproof_session
        openproof_credentials
        openproof_gateway
    LINK_PRIVATE
        Boost::headers
)

target_compile_definitions(openproof_authentication_http PRIVATE BOOST_HAS_LONG_LONG=1)
