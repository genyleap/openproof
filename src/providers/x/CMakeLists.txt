openproof_add_module(openproof_provider_x
    MODULES
        x.cppm
    SOURCES
        x.cpp
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

target_compile_definitions(openproof_provider_x PRIVATE BOOST_HAS_LONG_LONG=1)

# Work around GCC16's false positive on Boost.Asio coroutine frame allocation,
# retaining all diagnostics as errors and limiting the flag to this source.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(x.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
