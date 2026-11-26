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

# Standalone, optional runtime adapter with only gateway dependencies.
# This does not import the blocking federated AuthenticationHttpApi or SQL.
add_library(openproof_authentication_async_catalog_http STATIC
    coroutine_provider_catalog_http.cpp)
target_compile_features(openproof_authentication_async_catalog_http PUBLIC cxx_std_26)
target_include_directories(openproof_authentication_async_catalog_http PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(openproof_authentication_async_catalog_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_authentication_async_catalog_http
    PRIVATE BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_authentication_async_catalog_http
    PUBLIC openproof_gateway_http openproof_gateway
        openproof_foundation Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
   AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "16"
   AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "17")
    set_source_files_properties(coroutine_provider_catalog_http.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()

# Native, opt-in federated login start. The callback remains on the
# compatibility worker until native callback + session issuance are E2E tested.
add_library(openproof_authentication_async_federated_start_http STATIC
    coroutine_federated_start_http.cpp
    coroutine_federated_callback_http.cpp)
target_compile_features(openproof_authentication_async_federated_start_http PUBLIC cxx_std_26)
target_include_directories(openproof_authentication_async_federated_start_http PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(openproof_authentication_async_federated_start_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_authentication_async_federated_start_http
    PRIVATE BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_authentication_async_federated_start_http
    PUBLIC openproof_authentication openproof_identity_provider
        openproof_session openproof_gateway_http openproof_gateway
        openproof_foundation openproof_security Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
   AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "16"
   AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "17")
    set_source_files_properties(
        coroutine_federated_start_http.cpp
        coroutine_federated_callback_http.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()

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

# Provider-neutral, read-only owner-authorized administration boundary.
add_library(openproof_administration_async_http STATIC
    coroutine_admin_read_http.cpp
    boost_json.cpp)
target_compile_features(openproof_administration_async_http PUBLIC cxx_std_26)
target_include_directories(openproof_administration_async_http PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(openproof_administration_async_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_administration_async_http PRIVATE BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_administration_async_http PUBLIC
    openproof_administration openproof_foundation openproof_gateway openproof_gateway_http
    openproof_identity_core openproof_identity_provider openproof_organization openproof_session
    Boost::headers PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_admin_read_http.cpp PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
