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

# This opt-in remains OFF while the full GCC native gateway/module build
# and end-to-end route tests are pending. Do not place experimental HTTP
# objects in the default production graph or silently change live routing.
option(OPENPROOF_EXPERIMENTAL_ASYNC_RECOVERY_HTTP
    "Build the experimental native recovery-code HTTP route" OFF)
if(OPENPROOF_EXPERIMENTAL_ASYNC_RECOVERY_HTTP)
# Native recovery-code issuance route. This separate, provider-neutral
# coroutine adapter does not import synchronous local-account/storage SPIs
# or alter the production AuthenticationHttpApi until complete integration.
add_library(openproof_authentication_async_recovery_http STATIC
    coroutine_recovery_code_http.cpp)
target_compile_features(openproof_authentication_async_recovery_http PUBLIC cxx_std_26)
target_include_directories(openproof_authentication_async_recovery_http PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/src/credentials")
set_target_properties(openproof_authentication_async_recovery_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_authentication_async_recovery_http PRIVATE
    BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_authentication_async_recovery_http
    PUBLIC openproof_credentials_async openproof_gateway_http
        openproof_gateway openproof_session openproof_foundation
        openproof_identity_core openproof_identity_provider
        Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_recovery_code_http.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
endif()
