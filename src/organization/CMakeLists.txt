# Multi-tenancy: organizations, memberships and role assignment.
#
# Owns the organization-scoped Role vocabulary. Policy depends on this module to
# interpret memberships; organization never depends upward on authorization.
openproof_add_module(openproof_organization_membership
    MODULES
        membership.cppm
    SOURCES
        membership.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_core
)

openproof_add_module(openproof_organization
    MODULES
        organization_module.cppm
        organization.cppm
        repository.cppm
    SOURCES
        organization.cpp
        repository.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_core
        openproof_organization_membership
)
