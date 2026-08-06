/**
 * @file
 * @brief Primary interface of openproof.organization.
 *
 * Owns multi-tenancy: the tenant itself, who belongs to it, and which roles they
 * hold there.
 *
 * The split from the identity domain is deliberate. An identity exists
 * independently of any organization -- a person is not created by joining a
 * company -- so membership is a separate aggregate that references both. That
 * is also what makes one identity able to hold different roles in different
 * tenants without either leaking into the other.
 *
 * This module assigns roles; it never interprets them. What a role permits is
 * decided by openproof.policy, and keeping that boundary is what stops
 * authorization rules from accumulating in the membership aggregate.
 *
 * Dependency direction: organization -> policy -> identity.core -> foundation.
 * Policy is depended upon only for the `Role` vocabulary, and policy never
 * queries organizations back: a caller resolves memberships into roles and
 * supplies them to an authorization request. That keeps the graph acyclic.
 */
export module openproof.organization;

export import :organization;
export import :membership;
export import :repository;
