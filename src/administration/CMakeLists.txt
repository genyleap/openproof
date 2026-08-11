# Offline administrative ceremonies. This layer owns validated commands and
# ports; concrete persistence remains in storage adapters.
openproof_add_module(openproof_administration
    MODULES
        administration.cppm
    SOURCES
        administration.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_credentials
        openproof_identity_core
        openproof_identity_provider
        openproof_organization
)
