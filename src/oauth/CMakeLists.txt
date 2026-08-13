openproof_add_module(openproof_oauth
    MODULES
        oauth.cppm
        model.cppm
        repository.cppm
        service.cppm
        device.cppm
        par.cppm
        jar.cppm
        dpop.cppm
    SOURCES
        model.cpp
        repository.cpp
        service.cpp
        device.cpp
        par.cpp
        jar.cpp
        dpop.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_security
        openproof_application
        openproof_client
        openproof_identity_core
        openproof_identity_provider
        openproof_session
)

# Force GCC module BMI invalidation whenever the OAuth module ABI changes.
target_compile_definitions(openproof_oauth PRIVATE OPENPROOF_OAUTH_MODULE_ABI_REV=3)
