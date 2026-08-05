module;

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

export module openproof.foundation:encoding;

import :result;

export namespace openproof::foundation {

/**
 * @brief Encodes @p bytes as lowercase hexadecimal.
 */
[[nodiscard]] std::string toHex(std::span<const std::byte> bytes);

/**
 * @brief Decodes lowercase or uppercase hexadecimal @p text.
 *
 * @return The decoded bytes, or ErrorCode::InvalidArgument when @p text has an
 *         odd length or contains a non-hexadecimal character.
 */
[[nodiscard]] Result<std::vector<std::byte>> fromHex(std::string_view text);

/**
 * @brief Encodes @p bytes using base64url without padding (RFC 4648 section 5).
 *
 * The unpadded URL-safe alphabet is what the platform's tokens, challenges and
 * JOSE structures require, so it is the default rather than standard base64.
 */
[[nodiscard]] std::string toBase64Url(std::span<const std::byte> bytes);

/**
 * @brief Decodes base64url @p text, with or without trailing padding.
 *
 * The decoder is strict: an invalid character, an impossible length, or non-zero
 * unused trailing bits are all rejected. Accepting non-canonical encodings would
 * let the same logical value be presented in several textual forms, which
 * defeats replay caches and single-use nonce checks that key on the string.
 *
 * @return The decoded bytes, or ErrorCode::InvalidArgument.
 */
[[nodiscard]] Result<std::vector<std::byte>> fromBase64Url(std::string_view text);

}
