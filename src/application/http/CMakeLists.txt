openproof_add_module(openproof_application_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
        boost_json.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_application
        openproof_client
        openproof_identity_provider
        openproof_identity_core
        openproof_organization
        openproof_oauth
        openproof_resource
        openproof_security
        openproof_session
        openproof_gateway
    LINK_PRIVATE
        Boost::headers
)

target_compile_definitions(openproof_application_http PRIVATE BOOST_HAS_LONG_LONG=1)
