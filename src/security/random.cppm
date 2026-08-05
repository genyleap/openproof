module;

#include <cstddef>
#include <string>
#include <vector>

export module openproof.security:random;

import openproof.foundation;

export namespace openproof::security {

/**
 * @brief Returns @p count cryptographically secure random bytes.
 *
 * Backed by the audited CSPRNG of the linked cryptographic provider. The
 * platform never derives randomness from the system clock, a process
 * identifier, or a general-purpose pseudo-random generator: every nonce,
 * challenge, session identifier and token in this system depends on this being
 * unpredictable.
 *
 * @return The requested bytes, or ErrorCode::Internal when the underlying
 *         generator reports failure. A failure is never silently downgraded to
 *         weaker randomness.
 */
[[nodiscard]] foundation::Result<std::vector<std::byte>> randomBytes(std::size_t count);

/**
 * @brief Returns @p byteCount random bytes rendered as unpadded base64url.
 *
 * The parameter counts bytes of entropy, not output characters, so that a
 * caller reasons about entropy rather than string length. 32 bytes (256 bits)
 * is the platform default for session identifiers and challenge nonces.
 */
[[nodiscard]] foundation::Result<std::string> randomTokenBase64Url(std::size_t byteCount);

}
