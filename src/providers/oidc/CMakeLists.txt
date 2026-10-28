openproof_add_module(openproof_provider_oidc
    MODULES
        oidc.cppm
    SOURCES
        oidc.cpp
        ${PROJECT_SOURCE_DIR}/src/gateway/asio_thread_context.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_provider
    LINK_PRIVATE
        openproof_security
        openproof_provider_async_https
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
)

target_compile_definitions(openproof_provider_oidc PRIVATE BOOST_HAS_LONG_LONG=1)
# GCC16 falsely identifies Boost.Asio's aligned coroutine-frame allocation
# as mismatched new/delete. Keep -Werror; limit inlining in this TU only.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(oidc.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
