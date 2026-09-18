#include <gtest/gtest.h>

#include <cstddef>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

import openproof.foundation;
import openproof.security;

namespace fnd = openproof::foundation;
namespace sec = openproof::security;

namespace {

constexpr std::string_view kTestRsaPublicKey = R"PEM(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxQQ9mwfAEgVMWUY1rcqU
Q4YMPqUwXvppmoB2ffh5TXTN2YGR14AmL5wcCvxvA/LdmJ55vLWryzt6CBjp+1Ym
1pkT5jKpfKGPF+BC4PmqHo7SSR/Hr/e9lHHVQr1BHvxPHw8tC6jOWueB6HrZLUar
+xg6ix+x/mJmB85zL2C21LgKzLbiIOkPWpOE29CQ4RgnpFLtUegBFJTn+7op70O1
MfwasR7O/YMVe/Hq/LLhoVh64Il+6aLNgSSuU6wEvmAMRPJi6JYH4GhUsKaXvy+W
7D1jmGHYDJZCA2E/GuOinFTHuQIHt/dQtJ73GX2SH+TniwPrYZQmJbPS1QQxdJeb
2wIDAQAB
-----END PUBLIC KEY-----
)PEM";

TEST(JoseTest, ExportsPreviousPublicKeyAsPublishableJwk)
{
    auto jwk = sec::rsaPublicJwkJson(kTestRsaPublicKey, "previous-2026-08");
    ASSERT_TRUE(jwk.has_value());
    EXPECT_NE(jwk->find(R"("kid":"previous-2026-08")"), std::string::npos);
    EXPECT_NE(jwk->find(R"("alg":"RS256")"), std::string::npos);
    EXPECT_NE(jwk->find(R"("kty":"RSA")"), std::string::npos);
    EXPECT_EQ(jwk->find("PRIVATE"), std::string::npos);
}

TEST(JoseTest, RejectsInvalidPreviousVerificationKeys)
{
    EXPECT_FALSE(sec::rsaPublicJwkJson("not a key", "previous").has_value());
    EXPECT_FALSE(sec::rsaPublicJwkJson(kTestRsaPublicKey, "").has_value());
}

TEST(RandomTest, ReturnsTheRequestedNumberOfBytes)
{
    for (const std::size_t count : {std::size_t{0}, std::size_t{1}, std::size_t{32},
                                    std::size_t{1024}}) {
        const auto bytes = sec::randomBytes(count);
        ASSERT_TRUE(bytes.has_value()) << "count " << count;
        EXPECT_EQ(bytes.value().size(), count);
    }
}

// Not a statistical test of the generator, which is the provider's
// responsibility. This catches the specific catastrophic failure of a constant
// or zero-filled buffer being returned as "random".
TEST(RandomTest, SuccessiveCallsDifferAndAreNotAllZero)
{
    std::set<std::string> seen;
    for (int attempt = 0; attempt < 16; ++attempt) {
        const auto bytes = sec::randomBytes(32U);
        ASSERT_TRUE(bytes.has_value());

        const std::string hex = fnd::toHex(bytes.value());
        EXPECT_NE(hex, std::string(64U, '0'));
        EXPECT_TRUE(seen.insert(hex).second) << "repeated random output";
    }
}

TEST(RandomTest, TokenIsUrlSafeAndDerivedFromRequestedEntropy)
{
    const auto token = sec::randomTokenBase64Url(32U);
    ASSERT_TRUE(token.has_value());

    // 32 bytes -> 43 unpadded base64url characters.
    EXPECT_EQ(token.value().size(), 43U);
    EXPECT_EQ(token.value().find('+'), std::string::npos);
    EXPECT_EQ(token.value().find('/'), std::string::npos);
    EXPECT_EQ(token.value().find('='), std::string::npos);
}

TEST(RandomTest, RejectsAnImpossiblyLargeRequest)
{
    const auto bytes = sec::randomBytes(static_cast<std::size_t>(-1));
    ASSERT_FALSE(bytes.has_value());
    EXPECT_EQ(bytes.error().code(), fnd::ErrorCode::InvalidArgument);
}

// FIPS 180-4 test vectors.
TEST(HashTest, Sha256MatchesKnownVectors)
{
    const auto empty = sec::sha256(std::string_view{""});
    ASSERT_TRUE(empty.has_value());
    EXPECT_EQ(fnd::toHex(empty.value()),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const auto abc = sec::sha256(std::string_view{"abc"});
    ASSERT_TRUE(abc.has_value());
    EXPECT_EQ(fnd::toHex(abc.value()),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(HashTest, HmacSha256MatchesKnownVector)
{
    const fnd::SecretString key{"key"};
    const auto digest = sec::hmacSha256(key, "The quick brown fox jumps over the lazy dog");

    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(fnd::toHex(*digest),
              "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}

TEST(HashTest, HmacSha256RejectsAnEmptyKey)
{
    const fnd::SecretString key;
    const auto digest = sec::hmacSha256(key, "data");

    ASSERT_FALSE(digest.has_value());
    EXPECT_EQ(digest.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(HashTest, Sha256IsDeterministicAndSizeCorrect)
{
    const auto first = sec::sha256(std::string_view{"openproof protocol"});
    const auto second = sec::sha256(std::string_view{"openproof protocol"});

    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first.value(), second.value());
    EXPECT_EQ(first.value().size(), 32U);
}

TEST(HashTest, Sha256DiffersForDifferentInput)
{
    const auto left = sec::sha256(std::string_view{"a"});
    const auto right = sec::sha256(std::string_view{"b"});

    ASSERT_TRUE(left.has_value());
    ASSERT_TRUE(right.has_value());
    EXPECT_NE(left.value(), right.value());
}

TEST(ConstantTimeEqualsTest, MatchesOnlyIdenticalContent)
{
    EXPECT_TRUE(sec::constantTimeEquals(std::string_view{"token"}, std::string_view{"token"}));
    EXPECT_FALSE(sec::constantTimeEquals(std::string_view{"token"}, std::string_view{"tokeN"}));
    EXPECT_FALSE(sec::constantTimeEquals(std::string_view{"token"}, std::string_view{"token "}));
}

TEST(ConstantTimeEqualsTest, TreatsEmptyInputsConsistently)
{
    EXPECT_TRUE(sec::constantTimeEquals(std::string_view{""}, std::string_view{""}));
    EXPECT_FALSE(sec::constantTimeEquals(std::string_view{""}, std::string_view{"x"}));
}

TEST(ConstantTimeEqualsTest, ComparesByteSpans)
{
    const std::vector<std::byte> left{std::byte{1}, std::byte{2}};
    const std::vector<std::byte> right{std::byte{1}, std::byte{2}};
    const std::vector<std::byte> different{std::byte{1}, std::byte{3}};

    EXPECT_TRUE(sec::constantTimeEquals(left, right));
    EXPECT_FALSE(sec::constantTimeEquals(left, different));
}

// A digest comparison is the canonical place where an ordinary == leaks the
// expected value one byte at a time.
TEST(ConstantTimeEqualsTest, ComparesDigests)
{
    const auto expected = sec::sha256(std::string_view{"session-token"});
    const auto presented = sec::sha256(std::string_view{"session-token"});
    const auto wrong = sec::sha256(std::string_view{"other-token"});

    ASSERT_TRUE(expected.has_value());
    ASSERT_TRUE(presented.has_value());
    ASSERT_TRUE(wrong.has_value());

    EXPECT_TRUE(sec::constantTimeEquals(expected.value(), presented.value()));
    EXPECT_FALSE(sec::constantTimeEquals(expected.value(), wrong.value()));
}

TEST(AeadTest, RoundTripsWithAssociatedDataAndRejectsTampering)
{
    auto key = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"});
    ASSERT_TRUE(key.has_value());
    auto envelope = sec::sealAes256Gcm(
        key.value(), fnd::SecretString{"credential-secret"}, "identity-1");
    ASSERT_TRUE(envelope.has_value());
    auto opened = sec::openAes256Gcm(key.value(), envelope.value(), "identity-1");
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(opened->expose(), "credential-secret");
    EXPECT_FALSE(sec::openAes256Gcm(key.value(), envelope.value(), "identity-2"));
    envelope->back() ^= std::byte{0x01};
    EXPECT_FALSE(sec::openAes256Gcm(key.value(), envelope.value(), "identity-1"));
}

TEST(AeadTest, ComparesKeyMaterialWithoutExposingIt)
{
    auto first = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"});
    auto same = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"});
    auto different = sec::AeadKey::create(
        fnd::SecretString{"fedcba9876543210fedcba9876543210"});
    ASSERT_TRUE(first && same && different);
    EXPECT_TRUE(first->matches(same.value()));
    EXPECT_FALSE(first->matches(different.value()));
}

}
