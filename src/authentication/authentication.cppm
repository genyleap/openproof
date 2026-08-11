/**
 * @file
 * @brief Primary interface of the trusted authentication orchestration layer.
 *
 * Concrete providers implement openproof.identity.provider. Application and
 * transport code use this module instead of invoking providers directly. This
 * is the boundary that turns the provider SPI's documented obligations into
 * centrally enforced invariants.
 */
export module openproof.authentication;

export import :service;
