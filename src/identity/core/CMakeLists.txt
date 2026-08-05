# The canonical identity domain.
#
# Links the provider SPI, never a concrete provider. If a provider
# implementation ever appears among these dependencies, the boundary that keeps
# protocol knowledge out of the domain has been broken.
openproof_add_module(openproof_identity_core
    MODULES
        core.cppm
        identity.cppm
        link.cppm
        repository.cppm
    SOURCES
        identity.cpp
        link.cpp
        repository.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_provider
)
