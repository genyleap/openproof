/**
 * @file
 * @brief Primary interface of openproof.policy -- the authorization decision contract.
 *
 * Authentication and authorization are separate subsystems and separate
 * questions. Authentication answers "who are you"; this module answers "may you
 * do this, under these conditions". Neither implies the other: a valid session
 * grants nothing by itself, and a policy that permits an action does not
 * establish who the subject is.
 *
 * This module owns only the contract in Phase 1: request, decision, and the
 * engine interface. RBAC, ABAC and entitlement evaluation are implementations
 * that arrive in M7, and they will satisfy this interface rather than replace it.
 *
 * The dependency direction is:
 *
 * @verbatim
 *   the OpenProof gateway ──> openproof.policy ──> openproof.authentication
 *                            ├─> openproof.organization.membership
 *                            └─> openproof.identity.core
 * @endverbatim
 *
 * openproof.policy never depends on the OpenProof gateway, and never on a concrete provider.
 */
export module openproof.policy;

export import :decision;
