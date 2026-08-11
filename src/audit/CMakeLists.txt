openproof_add_module(openproof_audit
    MODULES audit.cppm
    SOURCES audit.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_security
        openproof_identity_core
)
