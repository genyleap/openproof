#include <gtest/gtest.h>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

import openproof.foundation;

namespace fnd = openproof::foundation;

namespace {

[[nodiscard]] std::vector<std::byte> bytesOf(std::string_view text)
{
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (const char character : text) {
        out.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
    }
    return out;
}

TEST(EncodingTest, HexEncodesLowercase)
{
    const std::vector<std::byte> input{std::byte{0x00}, std::byte{0xab}, std::byte{0xff}};
    EXPECT_EQ(fnd::toHex(input), "00abff");
    EXPECT_EQ(fnd::toHex(std::vector<std::byte>{}), "");
}

TEST(EncodingTest, HexRoundTrips)
{
    const std::vector<std::byte> input = bytesOf("openproof identity");
    const auto decoded = fnd::fromHex(fnd::toHex(input));

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), input);
}

TEST(EncodingTest, HexAcceptsUppercase)
{
    const auto decoded = fnd::fromHex("00ABFF");
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(fnd::toHex(decoded.value()), "00abff");
}

TEST(EncodingTest, HexRejectsMalformedInput)
{
    EXPECT_FALSE(fnd::fromHex("abc").has_value());
    EXPECT_FALSE(fnd::fromHex("zz").has_value());
    EXPECT_EQ(fnd::fromHex("zz").error().code(), fnd::ErrorCode::InvalidArgument);
}

// RFC 4648 section 10 vectors, in the URL-safe unpadded alphabet.
TEST(EncodingTest, Base64UrlMatchesKnownVectors)
{
    EXPECT_EQ(fnd::toBase64Url(bytesOf("")), "");
    EXPECT_EQ(fnd::toBase64Url(bytesOf("f")), "Zg");
    EXPECT_EQ(fnd::toBase64Url(bytesOf("fo")), "Zm8");
    EXPECT_EQ(fnd::toBase64Url(bytesOf("foo")), "Zm9v");
    EXPECT_EQ(fnd::toBase64Url(bytesOf("foob")), "Zm9vYg");
    EXPECT_EQ(fnd::toBase64Url(bytesOf("fooba")), "Zm9vYmE");
    EXPECT_EQ(fnd::toBase64Url(bytesOf("foobar")), "Zm9vYmFy");
}

TEST(EncodingTest, Base64UrlUsesUrlSafeAlphabet)
{
    // 0xFB 0xFF encodes to characters that differ between standard and URL-safe
    // base64; the URL-safe alphabet must never emit '+' or '/'.
    const std::vector<std::byte> input{std::byte{0xfb}, std::byte{0xff}, std::byte{0xbf}};
    const std::string encoded = fnd::toBase64Url(input);

    EXPECT_EQ(encoded.find('+'), std::string::npos);
    EXPECT_EQ(encoded.find('/'), std::string::npos);
    EXPECT_EQ(encoded.find('='), std::string::npos);
}

TEST(EncodingTest, Base64UrlRoundTrips)
{
    for (std::size_t length = 0; length < 32U; ++length) {
        std::vector<std::byte> input;
        input.reserve(length);
        for (std::size_t index = 0; index < length; ++index) {
            input.push_back(static_cast<std::byte>(index * 7U));
        }

        const auto decoded = fnd::fromBase64Url(fnd::toBase64Url(input));
        ASSERT_TRUE(decoded.has_value()) << "length " << length;
        EXPECT_EQ(decoded.value(), input) << "length " << length;
    }
}

TEST(EncodingTest, Base64UrlAcceptsOptionalPadding)
{
    const auto padded = fnd::fromBase64Url("Zg==");
    const auto unpadded = fnd::fromBase64Url("Zg");

    ASSERT_TRUE(padded.has_value());
    ASSERT_TRUE(unpadded.has_value());
    EXPECT_EQ(padded.value(), unpadded.value());
}

TEST(EncodingTest, Base64UrlRejectsInvalidCharacters)
{
    EXPECT_FALSE(fnd::fromBase64Url("Zg9v+A").has_value());
    EXPECT_FALSE(fnd::fromBase64Url("Zg9v/A").has_value());
    EXPECT_FALSE(fnd::fromBase64Url("Zg 9v").has_value());
}

TEST(EncodingTest, Base64UrlRejectsImpossibleLength)
{
    EXPECT_FALSE(fnd::fromBase64Url("Z").has_value());
    EXPECT_FALSE(fnd::fromBase64Url("Zm9vZ").has_value());
}

// Two spellings of one value would let an attacker slip a replayed nonce past a
// single-use cache that keys on the encoded string.
TEST(EncodingTest, Base64UrlRejectsNonCanonicalTrailingBits)
{
    const auto canonical = fnd::fromBase64Url("Zg");
    ASSERT_TRUE(canonical.has_value());

    const auto nonCanonical = fnd::fromBase64Url("Zh");
    ASSERT_FALSE(nonCanonical.has_value());
    EXPECT_EQ(nonCanonical.error().code(), fnd::ErrorCode::InvalidArgument);
}

}
