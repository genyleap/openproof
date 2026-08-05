/**
 * @file
 * @brief Primary interface of openproof.identity.provider -- the authentication SPI.
 *
 * This module is the seam that keeps the identity domain free of protocol
 * knowledge. It declares what an authentication provider is and what it must
 * produce; it contains no provider implementation and imports none.
 *
 * The dependency direction is one-way and must stay that way:
 *
 *     openproof.identity.oidc ─┐
 *     openproof.identity.webauthn ─┤
 *     openproof.identity.wallet ───┼──> openproof.identity.provider ──> openproof.identity.core
 *     openproof.identity.farcaster ┤          (this module)
 *     ... future providers ───┘
 *
 * Providers depend on this SPI. The SPI depends on nothing but openproof.foundation.
 * The identity core consumes AuthenticationOutcome and never learns which
 * protocol produced it. If a change here requires naming a specific provider,
 * the change belongs in that provider instead.
 *
 * The module is a separate dotted module rather than a partition of a larger
 * identity module precisely because providers are meant to be added, swapped
 * and deployed independently.
 */
export module openproof.identity.provider;

export import :assurance;
export import :outcome;
export import :authenticator;
export import :transaction;
export import :registry;
