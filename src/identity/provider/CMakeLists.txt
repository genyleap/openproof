# Deliberately links only openproof_foundation. If this target ever needs to link a
# concrete provider, the provider-agnostic boundary has been broken.
openproof_add_module(openproof_identity_provider
    MODULES
        provider.cppm
        assurance.cppm
        outcome.cppm
        authenticator.cppm
        transaction.cppm
        registry.cppm
    SOURCES
        assurance.cpp
        outcome.cpp
        authenticator.cpp
        transaction.cpp
        registry.cpp
    LINK_PUBLIC
        openproof_foundation
        # openproof_security is a downward, non-domain dependency: the transaction
        # model compares nonces and bindings in constant time, and that check
        # belongs with the invariant rather than duplicated in every provider.
        openproof_security
)
