openproof_add_module(openproof_operations_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_gateway
        openproof_security
        openproof_storage_postgres
        openproof_telemetry
)

add_library(openproof_operations_async_http STATIC coroutine_health_http.cpp)
target_compile_features(openproof_operations_async_http PUBLIC cxx_std_26)
set_target_properties(openproof_operations_async_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_operations_async_http PRIVATE BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_operations_async_http PUBLIC
    openproof_foundation openproof_gateway openproof_gateway_http Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_health_http.cpp PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
