module;

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

module openproof.foundation;

namespace openproof::foundation {

namespace {

constexpr std::string_view kHexDigitsLower = "0123456789abcdef";

constexpr std::string_view kBase64UrlAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

using DecodeTable = std::array<std::int8_t, 256>;

consteval DecodeTable makeHexDecodeTable()
{
    DecodeTable table{};
    table.fill(-1);
    for (std::size_t index = 0; index < 10U; ++index) {
        table[static_cast<std::size_t>('0') + index] = static_cast<std::int8_t>(index);
    }
    for (std::size_t index = 0; index < 6U; ++index) {
        table[static_cast<std::size_t>('a') + index] = static_cast<std::int8_t>(10U + index);
        table[static_cast<std::size_t>('A') + index] = static_cast<std::int8_t>(10U + index);
    }
    return table;
}

consteval DecodeTable makeBase64UrlDecodeTable()
{
    DecodeTable table{};
    table.fill(-1);
    for (std::size_t index = 0; index < kBase64UrlAlphabet.size(); ++index) {
        const auto symbol = static_cast<unsigned char>(kBase64UrlAlphabet[index]);
        table[static_cast<std::size_t>(symbol)] = static_cast<std::int8_t>(index);
    }
    return table;
}

constexpr DecodeTable kHexDecodeTable = makeHexDecodeTable();
constexpr DecodeTable kBase64UrlDecodeTable = makeBase64UrlDecodeTable();

[[nodiscard]] std::int8_t lookup(const DecodeTable& table, char symbol) noexcept
{
    return table[static_cast<std::size_t>(static_cast<unsigned char>(symbol))];
}

[[nodiscard]] std::uint32_t byteValue(std::byte value) noexcept
{
    return static_cast<std::uint32_t>(std::to_integer<unsigned char>(value));
}

}

std::string toHex(std::span<const std::byte> bytes)
{
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const std::byte value : bytes) {
        const std::uint32_t raw = byteValue(value);
        out.push_back(kHexDigitsLower[(raw >> 4U) & 0x0FU]);
        out.push_back(kHexDigitsLower[raw & 0x0FU]);
    }
    return out;
}

Result<std::vector<std::byte>> fromHex(std::string_view text)
{
    if ((text.size() % 2U) != 0U) {
        return fail(ErrorCode::InvalidArgument, "Hexadecimal input must have an even length.");
    }

    std::vector<std::byte> out;
    out.reserve(text.size() / 2U);

    for (std::size_t index = 0; index < text.size(); index += 2U) {
        const std::int8_t high = lookup(kHexDecodeTable, text[index]);
        const std::int8_t low = lookup(kHexDecodeTable, text[index + 1U]);
        if (high < 0 || low < 0) {
            return fail(ErrorCode::InvalidArgument,
                        "Hexadecimal input contains a non-hexadecimal character.");
        }
        const auto combined =
            static_cast<unsigned char>((static_cast<unsigned>(high) << 4U)
                                       | static_cast<unsigned>(low));
        out.push_back(static_cast<std::byte>(combined));
    }

    return out;
}

std::string toBase64Url(std::span<const std::byte> bytes)
{
    std::string out;
    out.reserve(((bytes.size() + 2U) / 3U) * 4U);

    std::size_t index = 0;
    while ((index + 3U) <= bytes.size()) {
        const std::uint32_t triple = (byteValue(bytes[index]) << 16U)
                                     | (byteValue(bytes[index + 1U]) << 8U)
                                     | byteValue(bytes[index + 2U]);
        out.push_back(kBase64UrlAlphabet[(triple >> 18U) & 0x3FU]);
        out.push_back(kBase64UrlAlphabet[(triple >> 12U) & 0x3FU]);
        out.push_back(kBase64UrlAlphabet[(triple >> 6U) & 0x3FU]);
        out.push_back(kBase64UrlAlphabet[triple & 0x3FU]);
        index += 3U;
    }

    const std::size_t remaining = bytes.size() - index;
    if (remaining == 1U) {
        const std::uint32_t first = byteValue(bytes[index]);
        out.push_back(kBase64UrlAlphabet[(first >> 2U) & 0x3FU]);
        out.push_back(kBase64UrlAlphabet[(first << 4U) & 0x3FU]);
    } else if (remaining == 2U) {
        const std::uint32_t first = byteValue(bytes[index]);
        const std::uint32_t second = byteValue(bytes[index + 1U]);
        out.push_back(kBase64UrlAlphabet[(first >> 2U) & 0x3FU]);
        out.push_back(kBase64UrlAlphabet[((first << 4U) | (second >> 4U)) & 0x3FU]);
        out.push_back(kBase64UrlAlphabet[(second << 2U) & 0x3FU]);
    }

    return out;
}

Result<std::vector<std::byte>> fromBase64Url(std::string_view text)
{
    std::string_view trimmed = text;
    while (!trimmed.empty() && trimmed.back() == '=') {
        trimmed.remove_suffix(1U);
    }

    if ((trimmed.size() % 4U) == 1U) {
        return fail(ErrorCode::InvalidArgument, "Base64url input has an impossible length.");
    }

    std::vector<std::byte> out;
    out.reserve((trimmed.size() * 3U) / 4U);

    std::uint32_t accumulator = 0;
    unsigned int pendingBits = 0;

    for (const char symbol : trimmed) {
        const std::int8_t decoded = lookup(kBase64UrlDecodeTable, symbol);
        if (decoded < 0) {
            return fail(ErrorCode::InvalidArgument,
                        "Base64url input contains an invalid character.");
        }

        accumulator = (accumulator << 6U) | static_cast<std::uint32_t>(decoded);
        pendingBits += 6U;

        if (pendingBits >= 8U) {
            pendingBits -= 8U;
            // Only whole bytes are emitted, and never more than the input can
            // justify; a drift here would silently fabricate output bytes.
            foundation::requireInvariant(pendingBits < 8U, "base64 decoder retained an invalid pending bit count");
            const auto emitted =
                static_cast<unsigned char>((accumulator >> pendingBits) & 0xFFU);
            out.push_back(static_cast<std::byte>(emitted));
        }
    }

    // Reject non-canonical encodings: the bits that do not form a whole byte
    // must be zero. Without this check one value has several textual spellings,
    // which breaks any replay cache or single-use nonce keyed on the string.
    if (pendingBits > 0U) {
        const std::uint32_t mask = (1U << pendingBits) - 1U;
        if ((accumulator & mask) != 0U) {
            return fail(ErrorCode::InvalidArgument,
                        "Base64url input is not canonically encoded.");
        }
    }

    return out;
}

}
