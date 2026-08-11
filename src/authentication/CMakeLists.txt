# Trusted authentication orchestration. Concrete providers remain behind the
# provider SPI; transport code depends on this target, not on provider methods.
openproof_add_module(openproof_authentication
    MODULES
        authentication.cppm
        service.cppm
    SOURCES
        service.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_security
        openproof_identity_provider
        openproof_identity_core
)
