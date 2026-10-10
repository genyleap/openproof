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
