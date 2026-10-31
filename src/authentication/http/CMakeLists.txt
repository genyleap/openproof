openproof_add_module(openproof_authentication_http
    MODULES
        http.cppm
        admin.cppm
        federated.cppm
        passkey.cppm
        web3.cppm
        enterprise.cppm
    SOURCES
        http.cpp
        admin.cpp
        federated.cpp
        passkey.cpp
        web3.cpp
        enterprise.cpp
        boost_json.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_administration
        openproof_security
        openproof_identity_provider
        openproof_identity_core
        openproof_authentication
        openproof_session
        openproof_credentials
        openproof_organization
        openproof_provider_passkey
        openproof_provider_local
        openproof_gateway
        openproof_gateway_http
    LINK_PRIVATE
        Boost::headers
)

target_compile_definitions(openproof_authentication_http PRIVATE BOOST_HAS_LONG_LONG=1)

# GCC16 can incorrectly diagnose Boost.Asio's aligned coroutine frame
# allocation when inlining named module implementations. Preserve -Werror
# and disable only this TU's allocator inlining.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(web3.cpp PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
