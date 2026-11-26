openproof_add_module(openproof_evidence_http
    MODULES
        http.cppm
    SOURCES
        http.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_evidence
        openproof_evidence_verifiers
        openproof_trust
        openproof_session
        openproof_gateway
        openproof_identity_core
        openproof_identity_provider
    LINK_PRIVATE
        Boost::headers
)

target_compile_definitions(openproof_evidence_http PRIVATE BOOST_HAS_LONG_LONG=1)

add_library(openproof_evidence_async_http STATIC coroutine_evidence_http.cpp)
target_compile_features(openproof_evidence_async_http PUBLIC cxx_std_26)
set_target_properties(openproof_evidence_async_http PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_evidence_async_http PRIVATE BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_evidence_async_http PUBLIC
    openproof_evidence openproof_evidence_verifiers openproof_trust openproof_foundation
    openproof_gateway openproof_gateway_http openproof_session openproof_identity_core
    openproof_identity_provider openproof_security Boost::headers PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_evidence_http.cpp PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
