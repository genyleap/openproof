/**
 * @file
 * @brief Primary interface of openproof.security.
 *
 * Owns the platform's cryptographic boundary. The project does not implement
 * cryptographic primitives; this layer adapts an audited provider and exposes
 * it behind OpenProof types, so that no OpenSSL type ever appears in a domain
 * signature.
 *
 * What this layer is not: it is not a key-custody service. The platform accepts
 * signatures and verifies them. It never accepts, stores or transmits a private
 * key, and that is an architectural prohibition rather than a configuration
 * choice.
 */
export module openproof.security;

export import :random;
export import :hash;
export import :aead;
