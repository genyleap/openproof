openproof_add_module(openproof_provider_github
    MODULES
        github.cppm
    SOURCES
        github.cpp
        # Shared explicit Asio TSS instantiation, also used by Gateway.
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

target_compile_definitions(openproof_provider_github PRIVATE BOOST_HAS_LONG_LONG=1)

# GCC 16.2 inlines Boost.Asio's aligned coroutine-frame allocator and
# incorrectly reports a mismatched new/delete in completeAuthenticationAsync.
# Preserve -Werror and all warnings; limit inlining to this provider TU.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(github.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
