module;

#include <algorithm>
#include <cstddef>
#include <memory>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

module openproof.security;

namespace openproof::security {
namespace {

struct BioDeleter final { void operator()(BIO* value) const noexcept { BIO_free(value); } };
struct PkeyDeleter final { void operator()(EVP_PKEY* value) const noexcept { EVP_PKEY_free(value); } };
struct ContextDeleter final { void operator()(EVP_MD_CTX* value) const noexcept { EVP_MD_CTX_free(value); } };
struct BigNumDeleter final { void operator()(BIGNUM* value) const noexcept { BN_free(value); } };
struct PkeyContextDeleter final { void operator()(EVP_PKEY_CTX* value) const noexcept { EVP_PKEY_CTX_free(value); } };
struct ParamBuildDeleter final { void operator()(OSSL_PARAM_BLD* value) const noexcept { OSSL_PARAM_BLD_free(value); } };
struct ParamsDeleter final { void operator()(OSSL_PARAM* value) const noexcept { OSSL_PARAM_free(value); } };
using BioPointer = std::unique_ptr<BIO, BioDeleter>;
using PkeyPointer = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using ContextPointer = std::unique_ptr<EVP_MD_CTX, ContextDeleter>;
using BigNumPointer = std::unique_ptr<BIGNUM, BigNumDeleter>;
using PkeyContextPointer = std::unique_ptr<EVP_PKEY_CTX, PkeyContextDeleter>;
using ParamBuildPointer = std::unique_ptr<OSSL_PARAM_BLD, ParamBuildDeleter>;
using ParamsPointer = std::unique_ptr<OSSL_PARAM, ParamsDeleter>;

[[nodiscard]] std::span<const std::byte> bytes(std::string_view value) noexcept
{
    return std::as_bytes(std::span{value.data(), value.size()});
}

[[nodiscard]] foundation::Result<std::string> encodeBigNum(const BIGNUM* number)
{
    if (number == nullptr || BN_is_negative(number) != 0) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The RSA public key is invalid.");
    }
    const int length = BN_num_bytes(number);
    if (length <= 0) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The RSA public key is invalid.");
    }
    std::vector<std::byte> raw(static_cast<std::size_t>(length));
    if (BN_bn2bin(number, reinterpret_cast<unsigned char*>(raw.data())) != length) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The RSA public key could not be encoded.");
    }
    return foundation::toBase64Url(raw);
}

[[nodiscard]] foundation::Result<PkeyPointer> rsaPublicKeyFromJwk(
    std::string_view modulusBase64Url, std::string_view exponentBase64Url)
{
    auto modulusBytes = foundation::fromBase64Url(modulusBase64Url);
    auto exponentBytes = foundation::fromBase64Url(exponentBase64Url);
    if (!modulusBytes || !exponentBytes || modulusBytes->empty() || exponentBytes->empty()
        || modulusBytes->size() > 1024U || exponentBytes->size() > 16U
        || foundation::toBase64Url(modulusBytes.value()) != modulusBase64Url
        || foundation::toBase64Url(exponentBytes.value()) != exponentBase64Url) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The RSA JWK encoding is invalid.");
    }
    BigNumPointer modulus{BN_bin2bn(
        reinterpret_cast<const unsigned char*>(modulusBytes->data()),
        static_cast<int>(modulusBytes->size()), nullptr)};
    BigNumPointer exponent{BN_bin2bn(
        reinterpret_cast<const unsigned char*>(exponentBytes->data()),
        static_cast<int>(exponentBytes->size()), nullptr)};
    BigNumPointer minimumExponent{BN_new()};
    if (!modulus || !exponent || !minimumExponent
        || BN_set_word(minimumExponent.get(), 3UL) != 1
        || BN_num_bits(modulus.get()) < 2048
        || BN_cmp(exponent.get(), minimumExponent.get()) < 0
        || BN_is_odd(exponent.get()) != 1) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The RSA JWK parameters are invalid.");
    }
    ParamBuildPointer builder{OSSL_PARAM_BLD_new()};
    if (!builder
        || OSSL_PARAM_BLD_push_BN(builder.get(), OSSL_PKEY_PARAM_RSA_N, modulus.get()) != 1
        || OSSL_PARAM_BLD_push_BN(builder.get(), OSSL_PKEY_PARAM_RSA_E, exponent.get()) != 1) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The RSA JWK could not be prepared.");
    }
    ParamsPointer parameters{OSSL_PARAM_BLD_to_param(builder.get())};
    PkeyContextPointer context{EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)};
    EVP_PKEY* rawKey = nullptr;
    if (!parameters || !context || EVP_PKEY_fromdata_init(context.get()) != 1
        || EVP_PKEY_fromdata(context.get(), &rawKey, EVP_PKEY_PUBLIC_KEY,
                             parameters.get()) != 1
        || rawKey == nullptr) {
        if (rawKey != nullptr) EVP_PKEY_free(rawKey);
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The RSA JWK public key is invalid.");
    }
    return PkeyPointer{rawKey};
}

[[nodiscard]] foundation::Result<std::string> exportPublicJwkJson(
    EVP_PKEY* key, std::string_view keyId)
{
    if (key == nullptr || keyId.empty() || keyId.size() > 128U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The JWK key identifier is invalid.");
    }
    BIGNUM* modulusRaw = nullptr;
    BIGNUM* exponentRaw = nullptr;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &modulusRaw) != 1
        || EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &exponentRaw) != 1) {
        if (modulusRaw != nullptr) BN_free(modulusRaw);
        if (exponentRaw != nullptr) BN_free(exponentRaw);
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The RSA public key could not be exported.");
    }
    BigNumPointer modulus{modulusRaw};
    BigNumPointer exponent{exponentRaw};
    auto encodedModulus = encodeBigNum(modulus.get());
    auto encodedExponent = encodeBigNum(exponent.get());
    if (!encodedModulus || !encodedExponent) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The RSA public key could not be encoded.");
    }
    foundation::JsonObjectWriter jwk;
    jwk.add("kty", "RSA")
        .add("use", "sig")
        .add("alg", "RS256")
        .add("kid", keyId)
        .add("n", encodedModulus.value())
        .add("e", encodedExponent.value());
    return jwk.build();
}

[[nodiscard]] foundation::Result<VerifiedCompactJws> verifyRs256WithKey(
    EVP_PKEY* key, std::string_view compactJwt)
{
    if (key == nullptr || compactJwt.empty() || compactJwt.size() > 16U * 1024U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The compact JWS input is invalid.");
    }
    const auto firstDot = compactJwt.find('.');
    const auto secondDot = firstDot == std::string_view::npos
        ? std::string_view::npos : compactJwt.find('.', firstDot + 1U);
    if (firstDot == std::string_view::npos || secondDot == std::string_view::npos
        || compactJwt.find('.', secondDot + 1U) != std::string_view::npos
        || firstDot == 0U || secondDot == firstDot + 1U || secondDot + 1U >= compactJwt.size()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The compact JWS is malformed.");
    }
    auto headerBytes = foundation::fromBase64Url(compactJwt.substr(0U, firstDot));
    auto payloadBytes = foundation::fromBase64Url(
        compactJwt.substr(firstDot + 1U, secondDot - firstDot - 1U));
    auto signature = foundation::fromBase64Url(compactJwt.substr(secondDot + 1U));
    if (!headerBytes || !payloadBytes || !signature || signature->empty()
        || headerBytes->size() > 4096U || payloadBytes->size() > 12U * 1024U) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The compact JWS encoding is invalid.");
    }
    ContextPointer context{EVP_MD_CTX_new()};
    const auto signingInput = compactJwt.substr(0U, secondDot);
    if (!context
        || EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, key) != 1
        || EVP_DigestVerifyUpdate(context.get(), signingInput.data(), signingInput.size()) != 1
        || EVP_DigestVerifyFinal(
               context.get(), reinterpret_cast<const unsigned char*>(signature->data()),
               signature->size()) != 1) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The compact JWS signature is invalid.");
    }
    const auto toString = [](const std::vector<std::byte>& value) {
        return std::string{reinterpret_cast<const char*>(value.data()), value.size()};
    };
    return VerifiedCompactJws{toString(headerBytes.value()), toString(payloadBytes.value())};
}

}

class RsaSha256Signer::Implementation final {
public:
    Implementation(PkeyPointer key, std::string keyId)
        : m_key(std::move(key)), m_keyId(std::move(keyId))
    {
    }

    PkeyPointer m_key;
    std::string m_keyId;
};

RsaSha256Signer::RsaSha256Signer(std::unique_ptr<Implementation> implementation)
    : m_implementation(std::move(implementation))
{
}

RsaSha256Signer::RsaSha256Signer(RsaSha256Signer&&) noexcept = default;
RsaSha256Signer& RsaSha256Signer::operator=(RsaSha256Signer&&) noexcept = default;
RsaSha256Signer::~RsaSha256Signer() = default;

foundation::Result<RsaSha256Signer> RsaSha256Signer::create(
    foundation::SecretString privateKeyPem, std::string keyId)
{
    if (privateKeyPem.empty() || keyId.empty() || keyId.size() > 128U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OIDC signing key configuration is invalid.");
    }
    if (privateKeyPem.expose().size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The OIDC signing key configuration is invalid.");
    }
    BioPointer input{BIO_new_mem_buf(privateKeyPem.expose().data(),
                                     static_cast<int>(privateKeyPem.expose().size()))};
    if (!input) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The OIDC signing key could not be loaded.");
    }
    PkeyPointer key{PEM_read_bio_PrivateKey(input.get(), nullptr, nullptr, nullptr)};
    if (!key || EVP_PKEY_base_id(key.get()) != EVP_PKEY_RSA
        || EVP_PKEY_bits(key.get()) < 2048) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "OIDC requires an RSA private key of at least 2048 bits.");
    }
    return RsaSha256Signer{std::make_unique<Implementation>(
        std::move(key), std::move(keyId))};
}

foundation::Result<std::string> RsaSha256Signer::signJwt(
    std::string_view payloadJson) const
{
    foundation::JsonObjectWriter header;
    header.add("alg", "RS256").add("typ", "JWT").add("kid", m_implementation->m_keyId);
    const std::string encodedHeader = foundation::toBase64Url(bytes(header.build()));
    const std::string encodedPayload = foundation::toBase64Url(bytes(payloadJson));
    const std::string signingInput = encodedHeader + "." + encodedPayload;

    ContextPointer context{EVP_MD_CTX_new()};
    if (!context
        || EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr,
                              m_implementation->m_key.get()) != 1
        || EVP_DigestSignUpdate(context.get(), signingInput.data(), signingInput.size()) != 1) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The ID Token signature could not be initialized.");
    }
    std::size_t signatureSize = 0U;
    if (EVP_DigestSignFinal(context.get(), nullptr, &signatureSize) != 1
        || signatureSize == 0U) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The ID Token signature size could not be determined.");
    }
    std::vector<std::byte> signature(signatureSize);
    if (EVP_DigestSignFinal(context.get(),
            reinterpret_cast<unsigned char*>(signature.data()), &signatureSize) != 1) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The ID Token could not be signed.");
    }
    signature.resize(signatureSize);
    return signingInput + "." + foundation::toBase64Url(signature);
}

foundation::Result<std::string> RsaSha256Signer::publicJwkJson() const
{
    return exportPublicJwkJson(m_implementation->m_key.get(), m_implementation->m_keyId);
}

std::string_view RsaSha256Signer::keyId() const noexcept
{ return m_implementation->m_keyId; }

VerifiedCompactJws::VerifiedCompactJws(std::string headerJson, std::string payloadJson)
    : m_headerJson(std::move(headerJson)), m_payloadJson(std::move(payloadJson)) {}
std::string_view VerifiedCompactJws::headerJson() const noexcept { return m_headerJson; }
std::string_view VerifiedCompactJws::payloadJson() const noexcept { return m_payloadJson; }


foundation::Status validateRs256PublicKey(std::string_view publicKeyPem)
{
    if (publicKeyPem.empty()
        || publicKeyPem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The registered JWS verification key is invalid.");
    }
    BioPointer input{BIO_new_mem_buf(publicKeyPem.data(), static_cast<int>(publicKeyPem.size()))};
    PkeyPointer key{input ? PEM_read_bio_PUBKEY(input.get(), nullptr, nullptr, nullptr) : nullptr};
    if (!key || EVP_PKEY_base_id(key.get()) != EVP_PKEY_RSA || EVP_PKEY_bits(key.get()) < 2048) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The registered JWS verification key must be RSA with at least 2048 bits.");
    }
    return foundation::ok();
}

foundation::Result<std::string> rsaPublicJwkJson(
    std::string_view publicKeyPem, std::string keyId)
{
    if (publicKeyPem.empty() || keyId.empty() || keyId.size() > 128U
        || publicKeyPem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The published RSA verification key is invalid.");
    }
    BioPointer input{BIO_new_mem_buf(publicKeyPem.data(), static_cast<int>(publicKeyPem.size()))};
    PkeyPointer key{input ? PEM_read_bio_PUBKEY(input.get(), nullptr, nullptr, nullptr) : nullptr};
    if (!key || EVP_PKEY_base_id(key.get()) != EVP_PKEY_RSA || EVP_PKEY_bits(key.get()) < 2048) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A published OIDC verification key must be RSA with at least 2048 bits.");
    }
    return exportPublicJwkJson(key.get(), keyId);
}

foundation::Result<VerifiedCompactJws> verifyRs256Jwt(
    std::string_view publicKeyPem, std::string_view compactJwt)
{
    if (publicKeyPem.empty() || publicKeyPem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())
        || compactJwt.empty() || compactJwt.size() > 16U * 1024U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The compact JWS input is invalid.");
    }
    const auto firstDot = compactJwt.find('.');
    const auto secondDot = firstDot == std::string_view::npos
        ? std::string_view::npos : compactJwt.find('.', firstDot + 1U);
    if (firstDot == std::string_view::npos || secondDot == std::string_view::npos
        || compactJwt.find('.', secondDot + 1U) != std::string_view::npos
        || firstDot == 0U || secondDot == firstDot + 1U || secondDot + 1U >= compactJwt.size()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The compact JWS is malformed.");
    }
    auto headerBytes = foundation::fromBase64Url(compactJwt.substr(0U, firstDot));
    auto payloadBytes = foundation::fromBase64Url(
        compactJwt.substr(firstDot + 1U, secondDot - firstDot - 1U));
    auto signature = foundation::fromBase64Url(compactJwt.substr(secondDot + 1U));
    if (!headerBytes || !payloadBytes || !signature || signature->empty()
        || headerBytes->size() > 4096U || payloadBytes->size() > 12U * 1024U) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The compact JWS encoding is invalid.");
    }
    BioPointer input{BIO_new_mem_buf(publicKeyPem.data(), static_cast<int>(publicKeyPem.size()))};
    PkeyPointer key{input ? PEM_read_bio_PUBKEY(input.get(), nullptr, nullptr, nullptr) : nullptr};
    if (!key || EVP_PKEY_base_id(key.get()) != EVP_PKEY_RSA || EVP_PKEY_bits(key.get()) < 2048) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The registered JWS verification key is invalid.");
    }
    ContextPointer context{EVP_MD_CTX_new()};
    const auto signingInput = compactJwt.substr(0U, secondDot);
    if (!context
        || EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1
        || EVP_DigestVerifyUpdate(context.get(), signingInput.data(), signingInput.size()) != 1
        || EVP_DigestVerifyFinal(
               context.get(), reinterpret_cast<const unsigned char*>(signature->data()),
               signature->size()) != 1) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The compact JWS signature is invalid.");
    }
    const auto toString = [](const std::vector<std::byte>& bytesValue) {
        return std::string{reinterpret_cast<const char*>(bytesValue.data()), bytesValue.size()};
    };
    return VerifiedCompactJws{toString(headerBytes.value()), toString(payloadBytes.value())};
}

foundation::Result<VerifiedCompactJws> verifyRs256Jwk(
    std::string_view modulusBase64Url, std::string_view exponentBase64Url,
    std::string_view compactJwt)
{
    auto key = rsaPublicKeyFromJwk(modulusBase64Url, exponentBase64Url);
    if (!key) return foundation::fail(key.error());
    return verifyRs256WithKey(key->get(), compactJwt);
}

foundation::Result<std::string> rsaJwkThumbprint(
    std::string_view modulusBase64Url, std::string_view exponentBase64Url)
{
    auto key = rsaPublicKeyFromJwk(modulusBase64Url, exponentBase64Url);
    if (!key) return foundation::fail(key.error());
    (void)key;
    const std::string canonical = std::string{"{\"e\":\""}
        + std::string{exponentBase64Url} + "\",\"kty\":\"RSA\",\"n\":\""
        + std::string{modulusBase64Url} + "\"}";
    auto digest = sha256(canonical);
    if (!digest) return foundation::fail(digest.error());
    return foundation::toBase64Url(digest.value());

}

}
