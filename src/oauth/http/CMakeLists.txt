openproof_add_module(openproof_oauth_http
    MODULES
        http.cppm
        sender.cppm
    SOURCES
        http.cpp
        sender.cpp
        coroutine_discovery_http.cpp
        coroutine_consent_http.cpp
        boost_json.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_security
        openproof_gateway
        openproof_gateway_http
        openproof_client
        openproof_consent
        openproof_resource
        openproof_identity_provider
        openproof_authentication
        openproof_session
        openproof_oauth
        openproof_token
        openproof_oidc
    LINK_PRIVATE
        Boost::headers
)

target_compile_definitions(openproof_oauth_http PRIVATE BOOST_HAS_LONG_LONG=1)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_consent_http.cpp PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
