module;

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

export module openproof.security:hash;

import openproof.foundation;

export namespace openproof::security {

/** @brief A SHA-256 digest: 32 octets. */
using Sha256Digest = std::array<std::byte, 32>;

/**
 * @brief Computes the SHA-256 digest of @p data.
 *
 * @return The digest, or ErrorCode::Internal if the cryptographic provider
 *         fails. The failure is reported rather than reduced to a zero digest,
 *         which would compare equal to another failed computation.
 */
[[nodiscard]] foundation::Result<Sha256Digest> sha256(std::span<const std::byte> data);

/** @brief Computes the SHA-256 digest of the octets of @p data. */
[[nodiscard]] foundation::Result<Sha256Digest> sha256(std::string_view data);

/**
 * @brief Computes HMAC-SHA-256 over @p data using secret @p key.
 *
 * The key remains a SecretString throughout the API, so it cannot be formatted
 * or logged accidentally. Empty keys are rejected rather than interpreted as a
 * valid but unkeyed construction.
 */
[[nodiscard]] foundation::Result<Sha256Digest>
hmacSha256(const foundation::SecretString& key, std::string_view data);

/**
 * @brief Compares two byte sequences in time independent of their contents.
 *
 * Required whenever one side is a secret: a session token, a digest, a MAC, a
 * recovery code. An ordinary comparison returns as soon as it finds a
 * difference, and that timing difference lets an attacker recover the expected
 * value one position at a time.
 *
 * Length is treated as non-secret: differing lengths return false immediately.
 * That is correct for this platform's uses, where the expected length is a
 * fixed public parameter of the credential format.
 */
[[nodiscard]] bool constantTimeEquals(std::span<const std::byte> left,
                                      std::span<const std::byte> right) noexcept;

/** @brief Constant-time comparison over the octets of two strings. */
[[nodiscard]] bool constantTimeEquals(std::string_view left, std::string_view right) noexcept;

}
