module;

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/json.hpp>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

module openproof.provider.passkey;

import openproof.security;

namespace openproof::provider::passkey {
namespace {

namespace json = boost::json;
namespace idp = identity::provider;

constexpr std::uint8_t kUserPresent = 0x01U;
constexpr std::uint8_t kUserVerified = 0x04U;
constexpr std::uint8_t kAttestedCredentialData = 0x40U;
constexpr std::uint8_t kExtensionData = 0x80U;
constexpr std::size_t kMaximumClientData = 16U * 1024U;
constexpr std::size_t kMaximumAttestation = 64U * 1024U;
constexpr std::size_t kMaximumCredentialIdBytes = 1023U;

[[nodiscard]] foundation::Error failure(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

[[nodiscard]] bool safeText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] foundation::Result<std::string> challengeFor(
    const PasskeyConfig& config, std::string_view purpose, const idp::ChallengeId& id)
{
    std::string material{purpose};
    material.push_back(':');
    material.append(id.value());
    auto digest = security::hmacSha256(config.derivationKey(), material);
    if (!digest) return foundation::fail(digest.error());
    return foundation::toBase64Url(digest.value());
}

[[nodiscard]] foundation::Result<std::vector<std::byte>> decodeCanonical(
    std::string_view encoded, std::size_t maximum)
{
    if (encoded.empty() || encoded.size() > maximum * 2U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    auto decoded = foundation::fromBase64Url(encoded);
    if (!decoded || decoded->empty() || decoded->size() > maximum
        || foundation::toBase64Url(decoded.value()) != encoded) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    return decoded.value();
}

class CborReader final {
public:
    explicit CborReader(std::span<const std::byte> input) : m_input(input) {}

    struct Head final { std::uint8_t major{}; std::uint64_t value{}; };

    [[nodiscard]] foundation::Result<Head> head()
    {
        if (m_offset >= m_input.size()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
        const auto first = std::to_integer<std::uint8_t>(m_input[m_offset++]);
        const auto major = static_cast<std::uint8_t>(first >> 5U);
        const auto additional = static_cast<std::uint8_t>(first & 0x1FU);
        if (additional == 31U) return foundation::fail(foundation::ErrorCode::InvalidArgument);
        std::uint64_t value{};
        if (additional < 24U) value = additional;
        else {
            const std::size_t bytes = additional == 24U ? 1U : additional == 25U ? 2U
                : additional == 26U ? 4U : additional == 27U ? 8U : 0U;
            if (bytes == 0U || m_offset + bytes > m_input.size()) {
                return foundation::fail(foundation::ErrorCode::InvalidArgument);
            }
            for (std::size_t index = 0U; index < bytes; ++index) {
                value = (value << 8U) | std::to_integer<std::uint8_t>(m_input[m_offset++]);
            }
            if ((bytes == 1U && value < 24U) || (bytes == 2U && value <= 0xFFU)
                || (bytes == 4U && value <= 0xFFFFU)
                || (bytes == 8U && value <= 0xFFFFFFFFULL)) {
                return foundation::fail(foundation::ErrorCode::InvalidArgument);
            }
        }
        return Head{major, value};
    }

    [[nodiscard]] foundation::Result<std::int64_t> integer()
    {
        auto value = head();
        if (!value || (value->major != 0U && value->major != 1U)
            || value->value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument);
        }
        return value->major == 0U ? static_cast<std::int64_t>(value->value)
                                  : -1 - static_cast<std::int64_t>(value->value);
    }

    [[nodiscard]] foundation::Result<std::string> text(std::size_t maximum)
    {
        auto value = head();
        if (!value || value->major != 3U || value->value > maximum
            || m_offset + value->value > m_input.size()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument);
        }
        const auto length = static_cast<std::size_t>(value->value);
        std::string output{reinterpret_cast<const char*>(m_input.data() + m_offset), length};
        m_offset += length;
        return output;
    }

    [[nodiscard]] foundation::Result<std::vector<std::byte>> bytes(std::size_t maximum)
    {
        auto value = head();
        if (!value || value->major != 2U || value->value > maximum
            || m_offset + value->value > m_input.size()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument);
        }
        const auto length = static_cast<std::size_t>(value->value);
        std::vector<std::byte> output(m_input.begin() + static_cast<std::ptrdiff_t>(m_offset),
                                      m_input.begin() + static_cast<std::ptrdiff_t>(m_offset + length));
        m_offset += length;
        return output;
    }

    [[nodiscard]] foundation::Status skip(unsigned int depth = 0U)
    {
        if (depth > 12U) return foundation::fail(foundation::ErrorCode::InvalidArgument);
        auto value = head();
        if (!value) return foundation::fail(value.error());
        if (value->major == 0U || value->major == 1U || value->major == 7U) return foundation::ok();
        if (value->major == 2U || value->major == 3U) {
            if (value->value > m_input.size() - m_offset) return foundation::fail(foundation::ErrorCode::InvalidArgument);
            m_offset += static_cast<std::size_t>(value->value);
            return foundation::ok();
        }
        if (value->major == 4U) {
            if (value->value > 256U) return foundation::fail(foundation::ErrorCode::InvalidArgument);
            for (std::uint64_t index = 0U; index < value->value; ++index) {
                auto status = skip(depth + 1U); if (!status) return status;
            }
            return foundation::ok();
        }
        if (value->major == 5U) {
            if (value->value > 256U) return foundation::fail(foundation::ErrorCode::InvalidArgument);
            for (std::uint64_t index = 0U; index < value->value; ++index) {
                auto key = skip(depth + 1U); if (!key) return key;
                auto item = skip(depth + 1U); if (!item) return item;
            }
            return foundation::ok();
        }
        if (value->major == 6U) return skip(depth + 1U);
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }

    [[nodiscard]] std::size_t offset() const noexcept { return m_offset; }
    [[nodiscard]] bool done() const noexcept { return m_offset == m_input.size(); }

private:
    std::span<const std::byte> m_input;
    std::size_t m_offset{};
};

struct ClientData final {
    std::vector<std::byte> raw;
};

[[nodiscard]] foundation::Result<ClientData> verifyClientData(
    std::string_view encoded, std::string_view expectedType,
    std::string_view expectedChallenge, std::string_view expectedOrigin)
{
    auto raw = decodeCanonical(encoded, kMaximumClientData);
    if (!raw) return foundation::fail(failure("WebAuthn client data encoding is invalid."));
    boost::system::error_code error;
    auto parsed = json::parse(std::string_view{reinterpret_cast<const char*>(raw->data()), raw->size()}, error);
    if (error || !parsed.is_object()) return foundation::fail(failure("WebAuthn client data is malformed."));
    const auto& object = parsed.as_object();
    const auto* type = object.if_contains("type");
    const auto* challenge = object.if_contains("challenge");
    const auto* origin = object.if_contains("origin");
    const auto* crossOrigin = object.if_contains("crossOrigin");
    if (type == nullptr || !type->is_string() || type->as_string() != expectedType
        || challenge == nullptr || !challenge->is_string()
        || !security::constantTimeEquals(std::string_view{challenge->as_string()}, expectedChallenge)
        || origin == nullptr || !origin->is_string() || origin->as_string() != expectedOrigin
        || (crossOrigin != nullptr && (!crossOrigin->is_bool() || crossOrigin->as_bool()))) {
        return foundation::fail(failure("WebAuthn client data binding failed."));
    }
    return ClientData{std::move(raw).value()};
}

struct ParsedAuthenticator final {
    std::uint8_t flags{};
    std::uint32_t signCount{};
    std::span<const std::byte> trailing;
};

[[nodiscard]] foundation::Result<ParsedAuthenticator> verifyAuthenticatorPrefix(
    std::span<const std::byte> data, std::string_view relyingPartyId,
    bool requireAttestedData)
{
    if (data.size() < 37U) return foundation::fail(failure("WebAuthn authenticator data is truncated."));
    auto expectedHash = security::sha256(relyingPartyId);
    if (!expectedHash || !std::ranges::equal(expectedHash.value(), data.first<32>())) {
        return foundation::fail(failure("WebAuthn RP ID hash is invalid."));
    }
    const auto flags = std::to_integer<std::uint8_t>(data[32]);
    if ((flags & kUserPresent) == 0U || (flags & kUserVerified) == 0U
        || (requireAttestedData && (flags & kAttestedCredentialData) == 0U)) {
        return foundation::fail(failure("WebAuthn user presence or verification is missing."));
    }
    const auto count = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[33])) << 24U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[34])) << 16U)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[35])) << 8U)
        | static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[36]));
    return ParsedAuthenticator{flags, count, data.subspan(37U)};
}

struct ParsedCoseKey final { std::string x; std::string y; std::size_t consumed{}; };

[[nodiscard]] foundation::Result<ParsedCoseKey> parseEs256Key(std::span<const std::byte> input)
{
    CborReader reader{input};
    auto map = reader.head();
    if (!map || map->major != 5U || map->value < 5U || map->value > 16U) {
        return foundation::fail(failure("WebAuthn COSE key is invalid."));
    }
    std::optional<std::int64_t> kty, alg, crv;
    std::optional<std::vector<std::byte>> x, y;
    for (std::uint64_t index = 0U; index < map->value; ++index) {
        auto key = reader.integer();
        if (!key) {
            return foundation::fail(failure("WebAuthn COSE key is malformed."));
        }
        if (*key == 1 || *key == 3 || *key == -1) {
            auto value = reader.integer();
            if (!value) {
                return foundation::fail(failure("WebAuthn COSE key parameter is malformed."));
            }
            if (*key == 1) kty = *value; else if (*key == 3) alg = *value; else crv = *value;
        } else if (*key == -2 || *key == -3) {
            auto value = reader.bytes(64U);
            if (!value || value->size() != 32U) {
                return foundation::fail(failure("WebAuthn EC coordinate is invalid."));
            }
            if (*key == -2) x = std::move(value).value(); else y = std::move(value).value();
        } else {
            auto status = reader.skip();
            if (!status) {
                return foundation::fail(failure("WebAuthn COSE key contains invalid data."));
            }
        }
    }
    if (kty != 2 || alg != -7 || crv != 1 || !x || !y) {
        return foundation::fail(failure("WebAuthn credential is not an ES256 P-256 key."));
    }
    return ParsedCoseKey{foundation::toBase64Url(*x), foundation::toBase64Url(*y), reader.offset()};
}

struct AttestationResult final {
    std::string credentialId;
    std::string x;
    std::string y;
    std::uint32_t signCount{};
};

[[nodiscard]] foundation::Result<AttestationResult> verifyAttestation(
    const RegistrationResponse& response, const PasskeyConfig& config,
    std::string_view expectedChallenge)
{
    auto client = verifyClientData(response.clientDataJson, "webauthn.create",
                                   expectedChallenge, config.origin());
    if (!client) return foundation::fail(client.error());
    auto attestationBytes = decodeCanonical(response.attestationObject, kMaximumAttestation);
    auto rawCredential = decodeCanonical(response.credentialId, kMaximumCredentialIdBytes);
    if (!attestationBytes || !rawCredential) return foundation::fail(failure("WebAuthn registration encoding is invalid."));
    CborReader attestation{attestationBytes.value()};
    auto map = attestation.head();
    if (!map || map->major != 5U || map->value > 16U) return foundation::fail(failure("WebAuthn attestation object is invalid."));
    std::optional<std::string> fmt;
    std::optional<std::vector<std::byte>> authData;
    bool sawAttStmt = false;
    bool emptyAttStmt = false;
    for (std::uint64_t index = 0U; index < map->value; ++index) {
        auto key = attestation.text(32U);
        if (!key) {
            return foundation::fail(failure("WebAuthn attestation object is malformed."));
        }
        if (*key == "fmt") {
            if (fmt) return foundation::fail(failure("Duplicate WebAuthn attestation format."));
            auto value = attestation.text(32U);
            if (!value) {
                return foundation::fail(failure("WebAuthn attestation format is malformed."));
            }
            fmt = std::move(value).value();
        } else if (*key == "authData") {
            if (authData) return foundation::fail(failure("Duplicate WebAuthn authenticator data."));
            auto value = attestation.bytes(kMaximumAttestation);
            if (!value) {
                return foundation::fail(failure("WebAuthn authenticator data is malformed."));
            }
            authData = std::move(value).value();
        } else if (*key == "attStmt") {
            if (sawAttStmt) return foundation::fail(failure("Duplicate WebAuthn attestation statement."));
            sawAttStmt = true;
            auto value = attestation.head();
            if (!value || value->major != 5U) {
                return foundation::fail(failure("WebAuthn attestation statement is malformed."));
            }
            emptyAttStmt = value->value == 0U;
            for (std::uint64_t item = 0U; item < value->value; ++item) {
                auto keyStatus = attestation.skip();
                if (!keyStatus) {
                    return foundation::fail(failure("WebAuthn attestation statement is malformed."));
                }
                auto valueStatus = attestation.skip();
                if (!valueStatus) {
                    return foundation::fail(failure("WebAuthn attestation statement is malformed."));
                }
            }
        } else {
            auto status = attestation.skip();
            if (!status) {
                return foundation::fail(failure("WebAuthn attestation object is malformed."));
            }
        }
    }
    if (!attestation.done() || fmt != std::optional<std::string>{"none"} || !sawAttStmt || !emptyAttStmt || !authData) {
        return foundation::fail(failure("Only privacy-preserving WebAuthn none attestation is accepted."));
    }
    auto prefix = verifyAuthenticatorPrefix(*authData, config.relyingPartyId(), true);
    if (!prefix || prefix->trailing.size() < 18U) return foundation::fail(prefix ? failure("WebAuthn attested credential data is truncated.") : prefix.error());
    auto trailing = prefix->trailing;
    trailing = trailing.subspan(16U);
    const auto credentialLength = (static_cast<std::size_t>(std::to_integer<std::uint8_t>(trailing[0])) << 8U)
        | static_cast<std::size_t>(std::to_integer<std::uint8_t>(trailing[1]));
    trailing = trailing.subspan(2U);
    if (credentialLength == 0U || credentialLength > kMaximumCredentialIdBytes || trailing.size() < credentialLength) {
        return foundation::fail(failure("WebAuthn credential ID is invalid."));
    }
    const auto credentialBytes = trailing.first(credentialLength);
    if (!std::ranges::equal(credentialBytes, rawCredential.value())) {
        return foundation::fail(failure("WebAuthn credential ID binding failed."));
    }
    trailing = trailing.subspan(credentialLength);
    auto key = parseEs256Key(trailing);
    if (!key) return foundation::fail(key.error());
    trailing = trailing.subspan(key->consumed);
    if ((prefix->flags & kExtensionData) != 0U) {
        CborReader extensions{trailing};
        auto skipped = extensions.skip();
        if (!skipped || !extensions.done()) return foundation::fail(failure("WebAuthn extension data is malformed."));
        trailing = {};
    }
    if (!trailing.empty()) return foundation::fail(failure("WebAuthn authenticator data has trailing bytes."));
    return AttestationResult{response.credentialId, key->x, key->y, prefix->signCount};
}

struct PkeyDeleter final { void operator()(EVP_PKEY* value) const noexcept { EVP_PKEY_free(value); } };
struct PkeyContextDeleter final { void operator()(EVP_PKEY_CTX* value) const noexcept { EVP_PKEY_CTX_free(value); } };
struct DigestContextDeleter final { void operator()(EVP_MD_CTX* value) const noexcept { EVP_MD_CTX_free(value); } };
struct ParamBuildDeleter final { void operator()(OSSL_PARAM_BLD* value) const noexcept { OSSL_PARAM_BLD_free(value); } };
struct ParamsDeleter final { void operator()(OSSL_PARAM* value) const noexcept { OSSL_PARAM_free(value); } };
using PkeyPointer = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using PkeyContextPointer = std::unique_ptr<EVP_PKEY_CTX, PkeyContextDeleter>;
using DigestContextPointer = std::unique_ptr<EVP_MD_CTX, DigestContextDeleter>;
using ParamBuildPointer = std::unique_ptr<OSSL_PARAM_BLD, ParamBuildDeleter>;
using ParamsPointer = std::unique_ptr<OSSL_PARAM, ParamsDeleter>;

[[nodiscard]] foundation::Status verifyEs256(
    std::string_view xEncoded, std::string_view yEncoded,
    std::span<const std::byte> message, std::span<const std::byte> signature)
{
    auto x = decodeCanonical(xEncoded, 32U); auto y = decodeCanonical(yEncoded, 32U);
    if (!x || !y || x->size() != 32U || y->size() != 32U || signature.empty() || signature.size() > 128U) {
        return foundation::fail(failure("WebAuthn public key or signature is invalid."));
    }
    std::array<unsigned char, 65> point{}; point[0] = 0x04U;
    std::memcpy(point.data() + 1U, x->data(), 32U);
    std::memcpy(point.data() + 33U, y->data(), 32U);
    ParamBuildPointer builder{OSSL_PARAM_BLD_new()};
    if (!builder
        || OSSL_PARAM_BLD_push_utf8_string(builder.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                           "prime256v1", 0U) != 1
        || OSSL_PARAM_BLD_push_octet_string(builder.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                            point.data(), point.size()) != 1) {
        return foundation::fail(foundation::ErrorCode::Internal);
    }
    ParamsPointer parameters{OSSL_PARAM_BLD_to_param(builder.get())};
    PkeyContextPointer keyContext{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
    EVP_PKEY* rawKey = nullptr;
    if (!parameters || !keyContext || EVP_PKEY_fromdata_init(keyContext.get()) != 1
        || EVP_PKEY_fromdata(keyContext.get(), &rawKey, EVP_PKEY_PUBLIC_KEY, parameters.get()) != 1) {
        return foundation::fail(failure("WebAuthn P-256 public key is invalid."));
    }
    PkeyPointer key{rawKey};
    DigestContextPointer digest{EVP_MD_CTX_new()};
    if (!digest || EVP_DigestVerifyInit(digest.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1
        || EVP_DigestVerify(digest.get(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size(),
                            reinterpret_cast<const unsigned char*>(message.data()), message.size()) != 1) {
        return foundation::fail(failure("WebAuthn assertion signature is invalid."));
    }
    return foundation::ok();
}

[[nodiscard]] foundation::Result<PasskeyCredential> verifyAssertion(
    PasskeyRepository& repository, const AssertionResponse& response,
    const PasskeyConfig& config, std::string_view expectedChallenge,
    foundation::Instant now)
{
    auto client = verifyClientData(response.clientDataJson, "webauthn.get",
                                   expectedChallenge, config.origin());
    auto credentialId = decodeCanonical(response.credentialId, kMaximumCredentialIdBytes);
    auto authenticatorData = decodeCanonical(response.authenticatorData, kMaximumAttestation);
    auto signature = decodeCanonical(response.signature, 256U);
    if (!client || !credentialId || !authenticatorData || !signature) {
        return foundation::fail(failure("WebAuthn assertion encoding is invalid."));
    }
    auto stored = repository.findCredential(response.credentialId);
    if (!stored || !stored->has_value()) return foundation::fail(failure("WebAuthn credential is unknown."));
    auto prefix = verifyAuthenticatorPrefix(*authenticatorData, config.relyingPartyId(), false);
    if (!prefix) return foundation::fail(prefix.error());
    auto trailing = prefix->trailing;
    if ((prefix->flags & kAttestedCredentialData) != 0U) return foundation::fail(failure("Unexpected attested data in WebAuthn assertion."));
    if ((prefix->flags & kExtensionData) != 0U) {
        CborReader extensions{trailing}; auto skipped = extensions.skip();
        if (!skipped || !extensions.done()) return foundation::fail(failure("WebAuthn assertion extension data is malformed."));
    } else if (!trailing.empty()) return foundation::fail(failure("WebAuthn assertion data has trailing bytes."));
    if (response.userHandle) {
        auto handleDigest = security::sha256(stored->value().identity.value());
        if (!handleDigest || !security::constantTimeEquals(*response.userHandle,
                foundation::toBase64Url(handleDigest.value()))) {
            return foundation::fail(failure("WebAuthn user handle binding failed."));
        }
    }
    auto clientHash = security::sha256(std::span<const std::byte>{client->raw});
    if (!clientHash) return foundation::fail(clientHash.error());
    std::vector<std::byte> signedData;
    signedData.reserve(authenticatorData->size() + clientHash->size());
    signedData.insert(signedData.end(), authenticatorData->begin(), authenticatorData->end());
    signedData.insert(signedData.end(), clientHash->begin(), clientHash->end());
    auto verified = verifyEs256(stored->value().publicKeyX, stored->value().publicKeyY,
                                signedData, signature.value());
    if (!verified) return foundation::fail(verified.error());
    const auto previous = stored->value().signCount;
    const auto next = prefix->signCount;
    if ((previous != 0U || next != 0U) && next <= previous) {
        return foundation::fail(failure("WebAuthn signature counter did not advance."));
    }
    // Persist every successful use, including authenticators that do not support a
    // signature counter and therefore report 0 on every assertion. The repository
    // keeps the compare-and-update atomic for counters that are supported.
    auto advanced = repository.advanceCounter(response.credentialId, previous, next, now);
    if (!advanced) return foundation::fail(advanced.error());
    stored->value().signCount = next;
    stored->value().lastUsedAt = now;
    return std::move(stored).value().value();
}

[[nodiscard]] std::optional<std::string_view> parameter(
    const idp::SecretAttributeMap& values, std::string_view name)
{
    const auto found = values.find(name);
    if (found == values.end() || found->second.empty()) return std::nullopt;
    return found->second.expose();
}

} // namespace

foundation::Status InMemoryPasskeyRepository::addCeremony(RegistrationCeremony ceremony)
{
    std::lock_guard guard{m_mutex};
    return m_ceremonies.emplace(ceremony.id, std::move(ceremony)).second
        ? foundation::ok() : foundation::fail(foundation::ErrorCode::AlreadyExists);
}

foundation::Status InMemoryPasskeyRepository::consumeCeremony(
    const idp::ChallengeId& id, const identity::core::IdentityId& identity,
    foundation::Instant now)
{
    std::lock_guard guard{m_mutex};
    const auto found = m_ceremonies.find(id);
    if (found == m_ceremonies.end() || found->second.identity != identity
        || found->second.expiresAt <= now) return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    m_ceremonies.erase(found); return foundation::ok();
}

foundation::Status InMemoryPasskeyRepository::addCredential(PasskeyCredential credential)
{
    std::lock_guard guard{m_mutex};
    return m_credentials.emplace(credential.credentialId, std::move(credential)).second
        ? foundation::ok() : foundation::fail(foundation::ErrorCode::AlreadyExists);
}

foundation::Result<std::optional<PasskeyCredential>> InMemoryPasskeyRepository::findCredential(
    std::string_view credentialId) const
{
    std::lock_guard guard{m_mutex}; const auto found = m_credentials.find(credentialId);
    return found == m_credentials.end() ? std::optional<PasskeyCredential>{}
        : std::optional<PasskeyCredential>{found->second};
}

foundation::Result<std::vector<PasskeyCredential>> InMemoryPasskeyRepository::listCredentials(
    const identity::core::IdentityId& identity) const
{
    std::lock_guard guard{m_mutex}; std::vector<PasskeyCredential> output;
    for (const auto& [_, credential] : m_credentials) if (credential.identity == identity) output.push_back(credential);
    return output;
}

foundation::Status InMemoryPasskeyRepository::advanceCounter(
    std::string_view credentialId, std::uint32_t expected,
    std::uint32_t replacement, foundation::Instant usedAt)
{
    std::lock_guard guard{m_mutex}; const auto found = m_credentials.find(credentialId);
    if (found == m_credentials.end()) return foundation::fail(foundation::ErrorCode::NotFound);
    const bool counterUnsupported = expected == 0U && replacement == 0U;
    if (found->second.signCount != expected
        || (!counterUnsupported && replacement <= expected)) {
        return foundation::fail(foundation::ErrorCode::Conflict);
    }
    found->second.signCount = replacement;
    if (usedAt > found->second.lastUsedAt) {
        found->second.lastUsedAt = usedAt;
    }
    return foundation::ok();
}

foundation::Status InMemoryPasskeyRepository::removeCredentialIfAnotherExists(
    const identity::core::IdentityId& identity, std::string_view credentialId)
{
    std::lock_guard guard{m_mutex};
    const auto found = m_credentials.find(credentialId);
    if (found == m_credentials.end() || found->second.identity != identity) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    const auto count = std::ranges::count_if(m_credentials, [&](const auto& entry) {
        return entry.second.identity == identity;
    });
    if (count <= 1) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "The final passkey credential cannot be removed while passkey sign-in is connected.");
    }
    m_credentials.erase(found);
    return foundation::ok();
}

foundation::Status InMemoryPasskeyRepository::removeCredential(
    const identity::core::IdentityId& identity, std::string_view credentialId)
{
    std::lock_guard guard{m_mutex}; const auto found = m_credentials.find(credentialId);
    if (found == m_credentials.end() || found->second.identity != identity) return foundation::fail(foundation::ErrorCode::NotFound);
    m_credentials.erase(found); return foundation::ok();
}

PasskeyConfig::PasskeyConfig(std::string relyingPartyId, std::string relyingPartyName,
    std::string origin, foundation::SecretString derivationKey,
    foundation::Duration ceremonyLifetime)
    : m_relyingPartyId(std::move(relyingPartyId)), m_relyingPartyName(std::move(relyingPartyName)),
      m_origin(std::move(origin)), m_derivationKey(std::move(derivationKey)),
      m_ceremonyLifetime(ceremonyLifetime) {}

foundation::Result<PasskeyConfig> PasskeyConfig::create(
    std::string relyingPartyId, std::string relyingPartyName, std::string origin,
    foundation::SecretString derivationKey, foundation::Duration ceremonyLifetime)
{
    const bool validOrigin = origin.starts_with("https://") && !origin.ends_with('/')
        && !origin.contains('#') && !origin.contains('?');
    if (!safeText(relyingPartyId, 253U) || relyingPartyId.contains('/') || relyingPartyId.contains(':')
        || !safeText(relyingPartyName, 128U) || !validOrigin || derivationKey.size() < 32U
        || ceremonyLifetime <= foundation::Duration::zero() || ceremonyLifetime > std::chrono::minutes{10}) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument, "The WebAuthn RP configuration is invalid.");
    }
    return PasskeyConfig{std::move(relyingPartyId), std::move(relyingPartyName), std::move(origin),
                         std::move(derivationKey), ceremonyLifetime};
}

std::string_view PasskeyConfig::relyingPartyId() const noexcept { return m_relyingPartyId; }
std::string_view PasskeyConfig::relyingPartyName() const noexcept { return m_relyingPartyName; }
std::string_view PasskeyConfig::origin() const noexcept { return m_origin; }
const foundation::SecretString& PasskeyConfig::derivationKey() const noexcept { return m_derivationKey; }
foundation::Duration PasskeyConfig::ceremonyLifetime() const noexcept { return m_ceremonyLifetime; }

PasskeyService::PasskeyService(PasskeyRepository& repository,
    identity::core::ExternalIdentityDirectory& externalIdentities,
    const foundation::ClockSource& clock, const PasskeyConfig& config)
    : m_repository(&repository), m_externalIdentities(&externalIdentities), m_clock(&clock), m_config(&config) {}

foundation::Result<RegistrationStart> PasskeyService::beginRegistration(
    const identity::core::IdentityId& identity)
{
    auto random = security::randomTokenBase64Url(24U); if (!random) return foundation::fail(random.error());
    idp::ChallengeId id{"pkr_" + std::move(random).value()};
    auto challenge = challengeFor(*m_config, "register", id); if (!challenge) return foundation::fail(challenge.error());
    auto stored = m_repository->addCeremony(RegistrationCeremony{id, identity, m_clock->now() + m_config->ceremonyLifetime()});
    if (!stored) return foundation::fail(stored.error());
    auto userDigest = security::sha256(identity.value()); if (!userDigest) return foundation::fail(userDigest.error());
    json::object options;
    options["challenge"] = challenge.value();
    options["rp"] = json::object{{"id", m_config->relyingPartyId()}, {"name", m_config->relyingPartyName()}};
    options["user"] = json::object{{"id", foundation::toBase64Url(userDigest.value())},
                                    {"name", identity.value()}, {"displayName", identity.value()}};
    options["pubKeyCredParams"] = json::array{json::object{{"type", "public-key"}, {"alg", -7}}};
    options["timeout"] = std::chrono::duration_cast<std::chrono::milliseconds>(m_config->ceremonyLifetime()).count();
    options["attestation"] = "none";
    options["authenticatorSelection"] = json::object{{"residentKey", "required"},
        {"requireResidentKey", true}, {"userVerification", "required"}};
    auto existing = m_repository->listCredentials(identity);
    if (existing) {
        json::array excluded;
        for (const auto& credential : existing.value()) excluded.emplace_back(json::object{{"type", "public-key"}, {"id", credential.credentialId}});
        options["excludeCredentials"] = std::move(excluded);
    }
    return RegistrationStart{id, json::serialize(options)};
}

foundation::Status PasskeyService::completeRegistration(
    const identity::core::IdentityId& identity, const idp::ChallengeId& ceremonyId,
    const RegistrationResponse& response)
{
    auto challenge = challengeFor(*m_config, "register", ceremonyId); if (!challenge) return foundation::fail(challenge.error());
    auto attestation = verifyAttestation(response, *m_config, challenge.value());
    if (!attestation) return foundation::fail(attestation.error());
    auto consumed = m_repository->consumeCeremony(ceremonyId, identity, m_clock->now());
    if (!consumed) return consumed;
    const identity::core::ExternalIdentityRef external{idp::ProviderId{"passkey"}, idp::ExternalSubject{std::string{identity.value()}}};
    auto owner = m_externalIdentities->ownerOf(external);
    if (!owner) return foundation::fail(owner.error());
    if (owner->has_value() && owner->value() != identity) return foundation::fail(foundation::ErrorCode::Conflict);
    PasskeyCredential credential{attestation->credentialId, identity, attestation->x, attestation->y,
        attestation->signCount, m_clock->now(), m_clock->now()};
    auto added = m_repository->addCredential(credential); if (!added) return added;
    if (!owner->has_value()) {
        auto link = identity::core::IdentityLink::request(identity, external, m_clock->now(), std::chrono::minutes{5});
        if (!link || !link->requireVerification(m_clock->now()) || !link->markVerified(m_clock->now()) || !link->complete(m_clock->now())) {
            static_cast<void>(m_repository->removeCredential(identity, response.credentialId));
            return foundation::fail(foundation::ErrorCode::Internal);
        }
        auto attached = m_externalIdentities->attach(link.value());
        if (!attached) { static_cast<void>(m_repository->removeCredential(identity, response.credentialId)); return attached; }
    }
    return foundation::ok();
}

foundation::Result<std::vector<PasskeyCredential>> PasskeyService::list(
    const identity::core::IdentityId& identity) const { return m_repository->listCredentials(identity); }
foundation::Status PasskeyService::remove(const identity::core::IdentityId& identity,
    std::string_view credentialId)
{
    auto preserved = m_repository->removeCredentialIfAnotherExists(identity, credentialId);
    if (preserved) return preserved;
    if (preserved.error().code() != foundation::ErrorCode::FailedPrecondition) {
        return preserved;
    }

    const identity::core::ExternalIdentityRef external{
        idp::ProviderId{"passkey"}, idp::ExternalSubject{std::string{identity.value()}}};
    auto owner = m_externalIdentities->ownerOf(external);
    if (!owner) return foundation::fail(owner.error());
    if (owner->has_value()) {
        if (owner->value() != identity) {
            return foundation::fail(foundation::ErrorCode::PermissionDenied);
        }
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "Disconnect passkey sign-in before removing the final passkey credential.");
    }
    return m_repository->removeCredential(identity, credentialId);
}

PasskeyAuthenticationProvider::PasskeyAuthenticationProvider(PasskeyRepository& repository,
    const foundation::ClockSource& clock, const PasskeyConfig& config)
    : m_repository(&repository), m_clock(&clock), m_config(&config) {}

idp::ProviderId PasskeyAuthenticationProvider::id() const { return idp::ProviderId{"passkey"}; }
idp::InteractionModel PasskeyAuthenticationProvider::interactionModel() const noexcept { return idp::InteractionModel::ChallengeResponse; }
idp::AssuranceLevel PasskeyAuthenticationProvider::maximumClaimableAssurance() const noexcept { return idp::AssuranceLevel::Ial2; }

foundation::Result<idp::AuthenticationChallenge> PasskeyAuthenticationProvider::beginAuthentication(
    const idp::AuthenticationRequest& request)
{
    if (request.provider() != id()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    auto random = security::randomTokenBase64Url(24U); if (!random) return foundation::fail(random.error());
    idp::ChallengeId idValue{"pka_" + std::move(random).value()};
    auto challenge = challengeFor(*m_config, "authenticate", idValue); if (!challenge) return foundation::fail(challenge.error());
    json::object options{{"challenge", challenge.value()}, {"rpId", m_config->relyingPartyId()},
        {"timeout", std::chrono::duration_cast<std::chrono::milliseconds>(m_config->ceremonyLifetime()).count()},
        {"userVerification", "required"}};
    idp::AuthenticationChallenge output{idValue, m_clock->now() + m_config->ceremonyLifetime()};
    output.setParameter("public_key_options", json::serialize(options));
    return output;
}

foundation::Result<idp::AuthenticationOutcome> PasskeyAuthenticationProvider::completeAuthentication(
    const idp::AuthenticationResponse& response)
{
    const auto credentialId = parameter(response.parameters(), "credential_id");
    const auto clientData = parameter(response.parameters(), "client_data_json");
    const auto authenticatorData = parameter(response.parameters(), "authenticator_data");
    const auto signature = parameter(response.parameters(), "signature");
    const auto userHandle = parameter(response.parameters(), "user_handle");
    if (!credentialId || !clientData || !authenticatorData || !signature) return foundation::fail(failure("WebAuthn assertion is incomplete."));
    auto challenge = challengeFor(*m_config, "authenticate", response.challengeId());
    if (!challenge) return foundation::fail(challenge.error());
    AssertionResponse assertion{std::string{*credentialId}, std::string{*clientData},
        std::string{*authenticatorData}, std::string{*signature},
        userHandle ? std::optional<std::string>{std::string{*userHandle}} : std::nullopt};
    auto credential = verifyAssertion(*m_repository, assertion, *m_config, challenge.value(), m_clock->now());
    if (!credential) return foundation::fail(credential.error());
    idp::ProviderEvidence evidence;
    evidence.add("protocol", "webauthn_level3");
    evidence.add("credential_id", credential->credentialId);
    evidence.add("algorithm", "ES256");
    evidence.add("user_verification", "required");
    return idp::AuthenticationOutcome::create(id(), idp::ExternalSubject{std::string{credential->identity.value()}},
        idp::VerifiedClaims{}, idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, true},
        std::move(evidence), m_clock->now());
}

} // namespace openproof::provider::passkey
