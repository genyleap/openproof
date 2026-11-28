openproof_add_module(openproof_gateway
    MODULES
        gateway.cppm
    SOURCES
        gateway.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_core
        openproof_identity_provider
        openproof_organization
        openproof_policy
        openproof_session
        openproof_security
)

openproof_add_module(openproof_gateway_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
        http_proxy.cpp
        http_coroutine.cpp
        asio_thread_context.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_gateway
    LINK_PRIVATE
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
        openproof_security
)

# Boost.Config 1.90 suppresses BOOST_HAS_LONG_LONG on Darwin whenever strict
# conformance is enabled, mistaking modern GCC for legacy Apple GCC. GCC 16
# supports long long; without this target-local correction Boost.System cannot
# declare its error-category identifier type.
target_compile_definitions(openproof_gateway_http PRIVATE BOOST_HAS_LONG_LONG=1)

# GCC 16.2 can misdiagnose Boost.Asio's matching aligned coroutine-frame
# allocator/deallocator when handleAsync() is inlined at -O2. Avoid the
# inlining only for this small dispatch implementation, preserving -Werror
# and all other diagnostics for the whole project and TLS/listener units.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
   AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "16"
   AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "17")
    set_source_files_properties(
        http_coroutine.cpp http_proxy.cpp http.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
    # Opt-in qualification only: previous CI compiled these two real units
    # at -O2 with narrower flags. Keep the full workaround on middleware.
    option(OPENPROOF_EXPERIMENTAL_GATEWAY_LIMITED_INLINING
        "Qualify narrower Gateway listener/proxy inlining flags" OFF)
    if(OPENPROOF_EXPERIMENTAL_GATEWAY_LIMITED_INLINING)
        if(NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
            message(FATAL_ERROR "Gateway inlining qualification requires RelWithDebInfo")
        endif()
        set_source_files_properties(http_proxy.cpp http.cpp PROPERTIES COMPILE_OPTIONS
            "-fno-inline-small-functions;-fno-inline-functions-called-once;-fno-early-inlining")
    endif()
endif()
