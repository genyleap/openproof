openproof_add_module(openproof_enterprise_scim_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_enterprise_scim
        openproof_gateway
        openproof_identity_core
    LINK_PRIVATE
        openproof_security
        Boost::headers
)

target_compile_definitions(openproof_enterprise_scim_http PRIVATE BOOST_HAS_LONG_LONG=1)

add_library(openproof_enterprise_scim_async_http STATIC coroutine_read_http.cpp)
target_compile_features(openproof_enterprise_scim_async_http PUBLIC cxx_std_26)
set_target_properties(openproof_enterprise_scim_async_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_enterprise_scim_async_http PRIVATE BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_enterprise_scim_async_http PUBLIC
    openproof_enterprise_scim_http openproof_enterprise_scim openproof_foundation
    openproof_gateway openproof_gateway_http openproof_security Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_read_http.cpp PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
