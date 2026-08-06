# Multi-tenancy: organizations, memberships and role assignment.
#
# Depends on policy for the Role vocabulary only. Policy never depends on this
# module: a caller resolves memberships into roles and supplies them to an
# authorization request, which keeps the dependency graph acyclic.
openproof_add_module(openproof_organization
    MODULES
        organization_module.cppm
        organization.cppm
        membership.cppm
        repository.cppm
    SOURCES
        organization.cpp
        membership.cpp
        repository.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_core
        openproof_policy
)
