/**
 * @file
 * @brief Primary interface of openproof.identity.core -- the canonical identity domain.
 *
 * This module owns the canonical OpenProof Identity and the associations attached to
 * it. It is the layer every other identity capability is defined against.
 *
 * It deliberately does not know:
 *
 *   - any authentication protocol (OIDC, OAuth 2.0, WebAuthn, SIWE, SAML, USSD),
 *   - any provider (Google, Apple, GitHub, Farcaster, ENS, an operator desk),
 *   - any transport (HTTP, gateway routing, request or response shapes),
 *   - any storage technology (PostgreSQL, Redis, SQL of any kind).
 *
 * The dependency direction is:
 *
 * @verbatim
 *   concrete providers ──> openproof.identity.provider (SPI) ──> openproof.identity.core
 * @endverbatim
 *
 * The core depends on the *abstraction* a provider satisfies -- ProviderId and
 * ExternalSubject -- and never on a provider. That is what allows a protocol
 * invented after this code was written to be added without editing this module.
 *
 * the OpenProof gateway, when it exists, will depend on this module. This module will never
 * depend on the OpenProof gateway.
 */
export module openproof.identity.core;

export import :identity;
export import :link;
export import :repository;
