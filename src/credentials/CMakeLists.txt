openproof_add_module(openproof_credentials
    MODULES
        credentials.cppm
    SOURCES
        credentials.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_security
        openproof_identity_core
    LINK_PRIVATE
        OpenSSL::Crypto

)

# Optional at build time for legacy-only deployments; required if Argon2id is selected.
if(OPENPROOF_SODIUM_LIBRARY AND OPENPROOF_SODIUM_INCLUDE_DIR)
    target_compile_definitions(openproof_credentials PRIVATE OPENPROOF_HAS_LIBSODIUM=1)
    target_include_directories(openproof_credentials PRIVATE "${OPENPROOF_SODIUM_INCLUDE_DIR}")
    target_link_libraries(openproof_credentials PRIVATE "${OPENPROOF_SODIUM_LIBRARY}")
endif()

# Storage-neutral native coroutine API. Only the repository SPI uses awaitable;
# none of the CSPRNG/HMAC domain logic calls synchronous persistence.
add_library(openproof_credentials_async STATIC coroutine_recovery_codes.cpp)
target_compile_features(openproof_credentials_async PUBLIC cxx_std_26)
target_include_directories(openproof_credentials_async PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(openproof_credentials_async PROPERTIES
    CXX_SCAN_FOR_MODULES ON CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(openproof_credentials_async PRIVATE
    BOOST_HAS_LONG_LONG=1)
target_link_libraries(openproof_credentials_async
    PUBLIC openproof_credentials openproof_foundation openproof_identity_core
        openproof_security Boost::headers
    PRIVATE openproof_compile_options)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(coroutine_recovery_codes.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
