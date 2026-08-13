openproof_add_module(openproof_enterprise_scim_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_enterprise_scim
        openproof_gateway
        openproof_identity_core
    LINK_PRIVATE
        openproof_security
        Boost::headers
)

target_compile_definitions(openproof_enterprise_scim_http PRIVATE BOOST_HAS_LONG_LONG=1)
