# Revocable opaque sessions. Raw bearer tokens never enter persistence; the
# repository stores only server-keyed HMAC digests.
openproof_add_module(openproof_session
    MODULES
        session.cppm
        model.cppm
        repository.cppm
        service.cppm
    SOURCES
        model.cpp
        repository.cpp
        service.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_security
        openproof_identity_core
        openproof_identity_provider
        openproof_authentication
)
