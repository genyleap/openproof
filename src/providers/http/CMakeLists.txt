# Shared native outbound HTTPS adapter for coroutine provider migrations.
# Deliberately outside the public OpenProof protocol module graph; no vendor
# or particular OAuth provider is imported here.
add_library(openproof_provider_async_https STATIC async_https.cpp)
target_compile_features(openproof_provider_async_https PUBLIC cxx_std_26)
target_include_directories(openproof_provider_async_https PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(openproof_provider_async_https
    PUBLIC Boost::headers OpenSSL::SSL OpenSSL::Crypto
    PRIVATE openproof_compile_options)
target_compile_definitions(openproof_provider_async_https PRIVATE
    BOOST_HAS_LONG_LONG=1)
set_target_properties(openproof_provider_async_https PROPERTIES
    POSITION_INDEPENDENT_CODE ON)
# GCC16 inlines Boost.Asio's aligned awaitable allocation and resolver
# sockaddr copies into false mismatched-new-delete/array-bounds diagnostics.
# Keep -Werror and all warnings active by limiting inlining in this one TU.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(async_https.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
