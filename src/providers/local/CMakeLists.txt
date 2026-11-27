openproof_add_module(openproof_provider_local
    MODULES
        local.cppm
    SOURCES
        local.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_security
        openproof_credentials
        openproof_identity_provider
        openproof_identity_core
)

add_library(openproof_provider_local_async STATIC coroutine_local_provider.cpp)
target_compile_features(openproof_provider_local_async PUBLIC cxx_std_26)
target_include_directories(openproof_provider_local_async PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(openproof_provider_local_async PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_provider_local_async PRIVATE BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_provider_local_async PUBLIC
    openproof_provider_local openproof_identity_provider openproof_foundation
    openproof_security Boost::headers PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_local_provider.cpp PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
