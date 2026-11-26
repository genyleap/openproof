openproof_add_module(openproof_application_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
        boost_json.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_application
        openproof_client
        openproof_identity_provider
        openproof_identity_core
        openproof_organization
        openproof_oauth
        openproof_resource
        openproof_security
        openproof_session
        openproof_gateway
    LINK_PRIVATE
        Boost::headers
)

target_compile_definitions(openproof_application_http PRIVATE BOOST_HAS_LONG_LONG=1)

add_library(openproof_application_async_http STATIC coroutine_management_read_http.cpp)
target_compile_features(openproof_application_async_http PUBLIC cxx_std_26)
set_target_properties(openproof_application_async_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_application_async_http PRIVATE BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_application_async_http PUBLIC
    openproof_application openproof_foundation openproof_gateway openproof_gateway_http
    openproof_identity_core openproof_identity_provider openproof_session openproof_security
    openproof_application_http Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_management_read_http.cpp PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
