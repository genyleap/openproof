openproof_add_module(openproof_account_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
        boost_json.cpp
    LINK_PUBLIC
        openproof_account
        openproof_authentication
        openproof_foundation
        openproof_gateway
        openproof_identity_core
        openproof_identity_profile
        openproof_identity_provider
        openproof_session
    LINK_PRIVATE
        Boost::headers
)

# Boost.Config on Darwin/GNU strict mode can suppress long long detection.
# Boost.System requires boost::ulong_long_type, so restore the capability
# explicitly for this Boost-consuming target.
target_compile_definitions(openproof_account_http PRIVATE BOOST_HAS_LONG_LONG=1)

# Provider-neutral, opt-in coroutine facade for account session endpoints.
# Existing synchronous account lifecycle ABI and live wiring are unchanged.
add_library(openproof_account_async_http STATIC coroutine_session_http.cpp)
target_compile_features(openproof_account_async_http PUBLIC cxx_std_26)
target_include_directories(openproof_account_async_http PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(openproof_account_async_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_account_async_http PRIVATE
    BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_account_async_http
    PUBLIC openproof_gateway_http openproof_gateway
        openproof_session openproof_foundation openproof_identity_provider
        Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_session_http.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
