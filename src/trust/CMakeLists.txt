openproof_add_module(openproof_trust
    MODULES trust.cppm model.cppm engine.cppm
    SOURCES model.cpp engine.cpp
    LINK_PUBLIC openproof_foundation openproof_identity_core openproof_evidence
)
