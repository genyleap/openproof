openproof_add_module(openproof_provider_web3
    MODULES
        web3.cppm
    SOURCES
        web3.cpp
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

target_compile_definitions(openproof_provider_web3 PRIVATE BOOST_HAS_LONG_LONG=1)

# GCC16 inlines Boost.Asio's aligned coroutine-frame allocator into named
# module bodies and emits an incorrect mismatched-new-delete diagnostic.
# Keep -Werror; scope the workaround to the Web3 implementation TU.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(web3.cpp PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
