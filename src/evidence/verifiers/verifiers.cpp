module;

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <limits>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/json.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

module openproof.evidence.verifiers;

import openproof.security;

namespace openproof::evidence::verification {
namespace {
namespace json = boost::json;

constexpr std::size_t kChallengeBytes = 32U;
constexpr std::size_t kMaximumAssertionBytes = 16U * 1024U;
constexpr std::size_t kMaximumCertificateBytes = 64U * 1024U;
constexpr std::size_t kMaximumEvidenceItems = 32U;
constexpr std::int64_t kClockSkewSeconds = 60;

struct BioDeleter final {
    void operator()(BIO* value) const noexcept { BIO_free(value); }
};
struct PkeyDeleter final {
    void operator()(EVP_PKEY* value) const noexcept { EVP_PKEY_free(value); }
};
struct MdContextDeleter final {
    void operator()(EVP_MD_CTX* value) const noexcept { EVP_MD_CTX_free(value); }
};
struct X509Deleter final {
    void operator()(X509* value) const noexcept { X509_free(value); }
};
struct StoreDeleter final {
    void operator()(X509_STORE* value) const noexcept { X509_STORE_free(value); }
};
struct StoreContextDeleter final {
    void operator()(X509_STORE_CTX* value) const noexcept { X509_STORE_CTX_free(value); }
};
struct CrlDeleter final {
    void operator()(X509_CRL* value) const noexcept { X509_CRL_free(value); }
};
struct GeneralNamesDeleter final {
    void operator()(GENERAL_NAMES* value) const noexcept { GENERAL_NAMES_free(value); }
};
struct X509StackDeleter final {
    void operator()(STACK_OF(X509)* value) const noexcept { sk_X509_free(value); }
};

using BioPointer = std::unique_ptr<BIO, BioDeleter>;
using PkeyPointer = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using MdContextPointer = std::unique_ptr<EVP_MD_CTX, MdContextDeleter>;
using X509Pointer = std::unique_ptr<X509, X509Deleter>;
using StorePointer = std::unique_ptr<X509_STORE, StoreDeleter>;
using StoreContextPointer = std::unique_ptr<X509_STORE_CTX, StoreContextDeleter>;
using CrlPointer = std::unique_ptr<X509_CRL, CrlDeleter>;
using GeneralNamesPointer = std::unique_ptr<GENERAL_NAMES, GeneralNamesDeleter>;
using X509StackPointer = std::unique_ptr<STACK_OF(X509), X509StackDeleter>;

[[nodiscard]] foundation::Error authenticationError(std::string message)
{
    return foundation::Error{foundation::ErrorCode::AuthenticationFailed, std::move(message)};
}

[[nodiscard]] std::string digestHex(std::span<const std::byte> bytes)
{
    constexpr std::array<char, 16> alphabet{
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    std::string output;
    output.reserve(bytes.size() * 2U);
    for (const auto value : bytes) {
        const auto octet = std::to_integer<unsigned int>(value);
        output.push_back(alphabet[(octet >> 4U) & 0x0FU]);
        output.push_back(alphabet[octet & 0x0FU]);
    }
    return output;
}

[[nodiscard]] foundation::Result<ChallengeDigest> challengeDigest(
    const foundation::SecretString& token)
{
    if (token.expose().empty() || token.expose().size() > 256U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The evidence challenge is invalid.");
    }
    auto digest = security::sha256(token.expose());
    if (!digest) return foundation::fail(digest.error());
    return ChallengeDigest{digestHex(digest.value())};
}

[[nodiscard]] foundation::Result<json::object> parseObject(std::string_view text)
{
    boost::system::error_code error;
    auto parsed = json::parse(text, error);
    if (error || !parsed.is_object()) {
        return foundation::fail(authenticationError("The evidence assertion JSON is malformed."));
    }
    return std::move(parsed).as_object();
}

[[nodiscard]] std::optional<std::string> stringClaim(
    const json::object& object, std::string_view name)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || !value->is_string()) return std::nullopt;
    const auto text = value->as_string();
    return std::string{text.data(), text.size()};
}

[[nodiscard]] std::optional<std::int64_t> integerClaim(
    const json::object& object, std::string_view name)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr) return std::nullopt;
    if (value->is_int64()) return value->as_int64();
    if (value->is_uint64() && value->as_uint64() <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return static_cast<std::int64_t>(value->as_uint64());
    }
    return std::nullopt;
}

[[nodiscard]] foundation::Instant fromUnixSeconds(std::int64_t seconds)
{
    return foundation::Instant{std::chrono::duration_cast<foundation::Duration>(
        std::chrono::seconds{seconds})};
}

[[nodiscard]] std::int64_t unixSeconds(foundation::Instant instant)
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        instant.time_since_epoch()).count();
}

[[nodiscard]] bool audienceContains(const json::object& object, std::string_view expected)
{
    const auto* audience = object.if_contains("aud");
    if (audience == nullptr) return false;
    if (audience->is_string()) return audience->as_string() == expected;
    if (!audience->is_array()) return false;
    return std::ranges::any_of(audience->as_array(), [expected](const json::value& value) {
        return value.is_string() && value.as_string() == expected;
    });
}

[[nodiscard]] foundation::Result<EvidenceId> evidenceId()
{
    auto token = security::randomTokenBase64Url(24U);
    if (!token) return foundation::fail(token.error());
    return EvidenceId{std::move(token.value())};
}

[[nodiscard]] foundation::Result<Evidence> makeEvidence(
    const identity::core::IdentityId& identity,
    const identity::provider::ProviderId& provider,
    std::string kind, std::string claim, std::string value,
    unsigned int confidence, foundation::Instant now,
    std::optional<foundation::Instant> expiresAt)
{
    auto id = evidenceId();
    if (!id) return foundation::fail(id.error());
    return Evidence::create(std::move(id.value()), identity, provider,
                            std::move(kind), std::move(claim), std::move(value),
                            confidence, now, expiresAt);
}

[[nodiscard]] foundation::Result<std::vector<X509Pointer>> parseCertificateChain(
    std::string_view pem)
{
    if (pem.empty() || pem.size() > kMaximumCertificateBytes
        || pem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return foundation::fail(authenticationError("The certificate evidence is invalid."));
    }
    BioPointer input{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    if (!input) return foundation::fail(foundation::ErrorCode::Internal);

    std::vector<X509Pointer> certificates;
    while (true) {
        X509* raw = PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr);
        if (raw == nullptr) break;
        certificates.emplace_back(raw);
        if (certificates.size() > 16U) {
            return foundation::fail(authenticationError("The certificate chain is too long."));
        }
    }
    ERR_clear_error();
    if (certificates.empty()) {
        return foundation::fail(authenticationError("The certificate evidence is malformed."));
    }
    return certificates;
}

[[nodiscard]] foundation::Result<foundation::Instant> certificateNotAfter(X509* certificate)
{
    std::tm value{};
    if (certificate == nullptr
        || ASN1_TIME_to_tm(X509_get0_notAfter(certificate), &value) != 1) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The certificate expiry could not be decoded.");
    }
    using namespace std::chrono;
    const year_month_day day{year{value.tm_year + 1900},
                             month{static_cast<unsigned>(value.tm_mon + 1)},
                             std::chrono::day{static_cast<unsigned>(value.tm_mday)}};
    if (!day.ok()) return foundation::fail(foundation::ErrorCode::Internal);
    const auto seconds = sys_days{day} + hours{value.tm_hour}
        + minutes{value.tm_min} + std::chrono::seconds{value.tm_sec};
    return foundation::Instant{duration_cast<foundation::Duration>(seconds.time_since_epoch())};
}

[[nodiscard]] foundation::Result<std::string> requiredSanUri(
    X509* certificate, const identity::core::IdentityId& identity)
{
    const std::string expected = "urn:openproof:identity:" + identity.str();
    GeneralNamesPointer names{static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr))};
    if (!names) {
        return foundation::fail(authenticationError("The certificate has no subject alternative name."));
    }
    bool found = false;
    for (int index = 0; index < sk_GENERAL_NAME_num(names.get()); ++index) {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), index);
        if (name == nullptr || name->type != GEN_URI) continue;
        const ASN1_IA5STRING* uri = name->d.uniformResourceIdentifier;
        const auto* bytes = ASN1_STRING_get0_data(uri);
        const int length = ASN1_STRING_length(uri);
        if (bytes == nullptr || length <= 0) continue;
        std::string candidate{reinterpret_cast<const char*>(bytes), static_cast<std::size_t>(length)};
        if (candidate.find('\0') != std::string::npos) {
            return foundation::fail(authenticationError("The certificate SAN is malformed."));
        }
        if (candidate == expected) found = true;
    }
    if (!found) {
        return foundation::fail(authenticationError(
            "The certificate SAN is not bound to the requested identity."));
    }
    return expected;
}

[[nodiscard]] foundation::Result<std::string> certificateFingerprint(X509* certificate)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0U;
    if (X509_digest(certificate, EVP_sha256(), digest.data(), &length) != 1 || length != 32U) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The certificate fingerprint could not be computed.");
    }
    return digestHex(std::span{reinterpret_cast<const std::byte*>(digest.data()), length});
}


[[nodiscard]] foundation::Status loadCrl(X509_STORE* store, std::string_view crlFile)
{
    if (crlFile.empty()) return foundation::ok();
    if (crlFile.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    BioPointer input{BIO_new_file(std::string{crlFile}.c_str(), "rb")};
    if (!input) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The configured evidence CRL is unavailable.");
    }
    bool loaded = false;
    while (true) {
        CrlPointer crl{PEM_read_bio_X509_CRL(input.get(), nullptr, nullptr, nullptr)};
        if (!crl) break;
        loaded = true;
        if (X509_STORE_add_crl(store, crl.get()) != 1) {
            const auto error = ERR_peek_last_error();
            if (ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                ERR_clear_error();
                return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                        "The configured evidence CRL is invalid.");
            }
            ERR_clear_error();
        }
    }
    ERR_clear_error();
    if (!loaded || X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) != 1) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The configured evidence CRL is invalid.");
    }
    return foundation::ok();
}

[[nodiscard]] foundation::Status verifyCertificateChain(
    const std::vector<X509Pointer>& certificates, std::string_view caFile,
    std::string_view crlFile, foundation::Instant now)
{
    StorePointer store{X509_STORE_new()};
    if (!store || X509_STORE_load_locations(store.get(), std::string{caFile}.c_str(), nullptr) != 1) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The configured evidence CA trust store is unavailable.");
    }
    auto crlStatus = loadCrl(store.get(), crlFile);
    if (!crlStatus) return crlStatus;

    X509StackPointer untrusted{sk_X509_new_null()};
    if (!untrusted) return foundation::fail(foundation::ErrorCode::Internal);
    for (std::size_t index = 1U; index < certificates.size(); ++index) {
        if (sk_X509_push(untrusted.get(), certificates[index].get()) == 0) {
            return foundation::fail(foundation::ErrorCode::Internal);
        }
    }
    StoreContextPointer context{X509_STORE_CTX_new()};
    if (!context
        || X509_STORE_CTX_init(context.get(), store.get(), certificates.front().get(),
                               untrusted.get()) != 1) {
        return foundation::fail(foundation::ErrorCode::Internal);
    }
    X509_VERIFY_PARAM* parameters = X509_STORE_CTX_get0_param(context.get());
    if (parameters == nullptr) return foundation::fail(foundation::ErrorCode::Internal);
    X509_VERIFY_PARAM_set_time(parameters, static_cast<std::time_t>(unixSeconds(now)));
    X509_VERIFY_PARAM_set_flags(parameters, X509_V_FLAG_X509_STRICT);
    if (X509_verify_cert(context.get()) != 1) {
        return foundation::fail(authenticationError("The certificate chain is not trusted."));
    }
    return foundation::ok();
}

[[nodiscard]] foundation::Status verifyDetachedProof(
    X509* certificate, std::string_view message, std::span<const std::byte> signature)
{
    PkeyPointer key{X509_get_pubkey(certificate)};
    if (!key) return foundation::fail(authenticationError("The certificate has no usable public key."));
    const int type = EVP_PKEY_base_id(key.get());
    if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_bits(key.get()) < 2048) {
            return foundation::fail(authenticationError("The certificate RSA key is too small."));
        }
    } else if (type == EVP_PKEY_EC) {
        if (EVP_PKEY_bits(key.get()) < 256) {
            return foundation::fail(authenticationError("The certificate EC key is too small."));
        }
    } else {
        return foundation::fail(authenticationError("The certificate key algorithm is unsupported."));
    }

    MdContextPointer context{EVP_MD_CTX_new()};
    if (!context
        || EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1
        || EVP_DigestVerifyUpdate(context.get(), message.data(), message.size()) != 1
        || EVP_DigestVerifyFinal(context.get(),
               reinterpret_cast<const unsigned char*>(signature.data()), signature.size()) != 1) {
        return foundation::fail(authenticationError("The certificate proof-of-possession is invalid."));
    }
    return foundation::ok();
}

} // namespace

Challenge::Challenge(ChallengeDigest digest, identity::core::IdentityId identity,
                     identity::provider::ProviderId provider,
                     foundation::Instant issuedAt, foundation::Instant expiresAt)
    : m_digest(std::move(digest)), m_identity(std::move(identity)),
      m_provider(std::move(provider)), m_issuedAt(issuedAt), m_expiresAt(expiresAt)
{
}

foundation::Result<Challenge> Challenge::create(
    ChallengeDigest digest, identity::core::IdentityId identity,
    identity::provider::ProviderId provider, foundation::Instant issuedAt,
    foundation::Instant expiresAt)
{
    if (digest.empty() || identity.empty() || provider.empty() || expiresAt <= issuedAt) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The evidence challenge is invalid.");
    }
    return Challenge{std::move(digest), std::move(identity), std::move(provider),
                     issuedAt, expiresAt};
}

const ChallengeDigest& Challenge::digest() const noexcept { return m_digest; }
const identity::core::IdentityId& Challenge::identity() const noexcept { return m_identity; }
const identity::provider::ProviderId& Challenge::provider() const noexcept { return m_provider; }
foundation::Instant Challenge::issuedAt() const noexcept { return m_issuedAt; }
foundation::Instant Challenge::expiresAt() const noexcept { return m_expiresAt; }

ChallengeService::ChallengeService(ChallengeStore& store,
                                   const foundation::ClockSource& clock,
                                   foundation::Duration lifetime)
    : m_store(&store), m_clock(&clock), m_lifetime(lifetime)
{
}

foundation::Result<IssuedChallenge> ChallengeService::issue(
    const identity::core::IdentityId& identity,
    const identity::provider::ProviderId& provider)
{
    if (identity.empty() || provider.empty() || m_lifetime <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    auto raw = security::randomTokenBase64Url(kChallengeBytes);
    if (!raw) return foundation::fail(raw.error());
    foundation::SecretString token{std::move(raw.value())};
    auto digest = challengeDigest(token);
    if (!digest) return foundation::fail(digest.error());
    const auto now = m_clock->now();
    const auto expiry = now + m_lifetime;
    auto challenge = Challenge::create(std::move(digest.value()), identity, provider, now, expiry);
    if (!challenge) return foundation::fail(challenge.error());
    auto stored = m_store->add(std::move(challenge.value()));
    if (!stored) return foundation::fail(stored.error());
    return IssuedChallenge{.token = std::move(token), .expiresAt = expiry};
}

foundation::Status ChallengeService::consume(
    const identity::core::IdentityId& identity,
    const identity::provider::ProviderId& provider,
    const foundation::SecretString& token)
{
    auto digest = challengeDigest(token);
    if (!digest) return foundation::fail(digest.error());
    return m_store->consume(digest.value(), identity, provider, m_clock->now());
}

SignedJwtVerifier::SignedJwtVerifier(identity::provider::ProviderId provider,
                                     std::string issuer, std::string audience,
                                     std::string publicKeyPem,
                                     foundation::Duration maximumAge)
    : m_provider(std::move(provider)), m_issuer(std::move(issuer)),
      m_audience(std::move(audience)), m_publicKeyPem(std::move(publicKeyPem)),
      m_maximumAge(maximumAge)
{
}

foundation::Result<std::unique_ptr<SignedJwtVerifier>> SignedJwtVerifier::create(
    identity::provider::ProviderId provider, std::string issuer,
    std::string audience, std::string publicKeyPem,
    foundation::Duration maximumAge)
{
    if (provider.empty() || issuer.empty() || issuer.size() > 512U
        || audience.empty() || audience.size() > 512U
        || maximumAge <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The signed evidence verifier configuration is invalid.");
    }
    auto keyStatus = security::validateRs256PublicKey(publicKeyPem);
    if (!keyStatus) return foundation::fail(keyStatus.error());
    return std::unique_ptr<SignedJwtVerifier>{new SignedJwtVerifier{
        std::move(provider), std::move(issuer), std::move(audience),
        std::move(publicKeyPem), maximumAge}};
}

identity::provider::ProviderId SignedJwtVerifier::provider() const { return m_provider; }

foundation::Result<std::vector<Evidence>> SignedJwtVerifier::verify(
    const identity::core::IdentityId& identity,
    const identity::provider::AttributeMap& publicInputs,
    const identity::provider::SecretAttributeMap& secretInputs,
    foundation::Instant now)
{
    const auto challengeFound = publicInputs.find("challenge");
    const auto assertionFound = secretInputs.find("assertion");
    if (identity.empty() || challengeFound == publicInputs.end()
        || challengeFound->second.empty() || challengeFound->second.size() > 256U
        || assertionFound == secretInputs.end() || assertionFound->second.empty()
        || assertionFound->second.expose().size() > kMaximumAssertionBytes) {
        return foundation::fail(authenticationError("The signed evidence proof is incomplete."));
    }

    auto verified = security::verifyRs256Jwt(m_publicKeyPem, assertionFound->second.expose());
    if (!verified) return foundation::fail(verified.error());
    auto header = parseObject(verified->headerJson());
    auto payload = parseObject(verified->payloadJson());
    if (!header || !payload) return foundation::fail(authenticationError("The evidence JWT is malformed."));
    if (stringClaim(header.value(), "alg") != std::optional<std::string>{"RS256"}) {
        return foundation::fail(authenticationError("The evidence JWT algorithm is not allowed."));
    }

    const auto issuer = stringClaim(payload.value(), "iss");
    const auto subject = stringClaim(payload.value(), "sub");
    const auto nonce = stringClaim(payload.value(), "nonce");
    const auto issued = integerClaim(payload.value(), "iat");
    const auto expires = integerClaim(payload.value(), "exp");
    if (!issuer || *issuer != m_issuer || !subject || *subject != identity.value()
        || !nonce || *nonce != challengeFound->second || !audienceContains(payload.value(), m_audience)
        || !issued || !expires || *expires <= *issued) {
        return foundation::fail(authenticationError("The evidence JWT claims are invalid."));
    }
    const auto nowSeconds = unixSeconds(now);
    const auto maximumAgeSeconds = std::chrono::duration_cast<std::chrono::seconds>(m_maximumAge).count();
    if (*issued > nowSeconds + kClockSkewSeconds
        || *issued < nowSeconds - maximumAgeSeconds - kClockSkewSeconds
        || *expires <= nowSeconds - kClockSkewSeconds) {
        return foundation::fail(authenticationError("The evidence JWT is outside its validity window."));
    }
    if (const auto notBefore = integerClaim(payload.value(), "nbf");
        notBefore && *notBefore > nowSeconds + kClockSkewSeconds) {
        return foundation::fail(authenticationError("The evidence JWT is not active yet."));
    }
    const auto expiry = fromUnixSeconds(*expires);

    std::vector<Evidence> output;
    auto summary = makeEvidence(identity, m_provider, "jwt.attestation", "issuer",
                                m_issuer, 95U, now, expiry);
    if (!summary) return foundation::fail(summary.error());
    output.push_back(std::move(summary.value()));

    const auto* evidenceValue = payload->if_contains("evidence");
    if (evidenceValue == nullptr || !evidenceValue->is_array()
        || evidenceValue->as_array().empty()
        || evidenceValue->as_array().size() > kMaximumEvidenceItems) {
        return foundation::fail(authenticationError("The evidence JWT contains no valid evidence set."));
    }
    for (const auto& value : evidenceValue->as_array()) {
        if (!value.is_object()) {
            return foundation::fail(authenticationError("The evidence JWT item is malformed."));
        }
        const auto& object = value.as_object();
        auto kind = stringClaim(object, "kind");
        auto claim = stringClaim(object, "claim");
        auto itemValue = stringClaim(object, "value");
        auto confidence = integerClaim(object, "confidence");
        if (!kind || !claim || !itemValue || !confidence || *confidence < 0 || *confidence > 100) {
            return foundation::fail(authenticationError("The evidence JWT item is invalid."));
        }
        std::optional<foundation::Instant> itemExpiry{expiry};
        if (auto itemExp = integerClaim(object, "exp"); itemExp) {
            if (*itemExp <= nowSeconds || *itemExp > *expires) {
                return foundation::fail(authenticationError("The evidence JWT item expiry is invalid."));
            }
            itemExpiry = fromUnixSeconds(*itemExp);
        }
        auto item = makeEvidence(identity, m_provider, std::move(*kind), std::move(*claim),
                                 std::move(*itemValue), static_cast<unsigned int>(*confidence),
                                 now, itemExpiry);
        if (!item) return foundation::fail(item.error());
        output.push_back(std::move(item.value()));
    }
    return output;
}

X509Verifier::X509Verifier(identity::provider::ProviderId provider,
                           std::string caFile, std::string crlFile)
    : m_provider(std::move(provider)), m_caFile(std::move(caFile)),
      m_crlFile(std::move(crlFile))
{
}

foundation::Result<std::unique_ptr<X509Verifier>> X509Verifier::create(
    identity::provider::ProviderId provider, std::string caFile,
    std::string crlFile)
{
    if (provider.empty() || caFile.empty() || caFile.size() > 4096U || crlFile.size() > 4096U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The X.509 evidence verifier configuration is invalid.");
    }
    StorePointer store{X509_STORE_new()};
    if (!store || X509_STORE_load_locations(store.get(), caFile.c_str(), nullptr) != 1) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The X.509 evidence CA file is invalid.");
    }
    auto crlStatus = loadCrl(store.get(), crlFile);
    if (!crlStatus) return foundation::fail(crlStatus.error());
    return std::unique_ptr<X509Verifier>{new X509Verifier{
        std::move(provider), std::move(caFile), std::move(crlFile)}};
}

identity::provider::ProviderId X509Verifier::provider() const { return m_provider; }

foundation::Result<std::vector<Evidence>> X509Verifier::verify(
    const identity::core::IdentityId& identity,
    const identity::provider::AttributeMap& publicInputs,
    const identity::provider::SecretAttributeMap& secretInputs,
    foundation::Instant now)
{
    const auto challengeFound = publicInputs.find("challenge");
    const auto certificateFound = publicInputs.find("certificate_pem");
    const auto signatureFound = secretInputs.find("signature");
    if (identity.empty() || challengeFound == publicInputs.end() || challengeFound->second.empty()
        || challengeFound->second.size() > 256U || certificateFound == publicInputs.end()
        || certificateFound->second.empty() || certificateFound->second.size() > kMaximumCertificateBytes
        || signatureFound == secretInputs.end() || signatureFound->second.empty()) {
        return foundation::fail(authenticationError("The X.509 evidence proof is incomplete."));
    }
    auto signature = foundation::fromBase64Url(signatureFound->second.expose());
    if (!signature || signature->empty() || signature->size() > 8192U) {
        return foundation::fail(authenticationError("The X.509 evidence signature is malformed."));
    }
    auto certificates = parseCertificateChain(certificateFound->second);
    if (!certificates) return foundation::fail(certificates.error());
    auto chainStatus = verifyCertificateChain(certificates.value(), m_caFile, m_crlFile, now);
    if (!chainStatus) return foundation::fail(chainStatus.error());
    auto san = requiredSanUri(certificates->front().get(), identity);
    if (!san) return foundation::fail(san.error());

    const std::string message = "OpenProof Evidence Proof\n" + challengeFound->second
        + "\n" + identity.str();
    auto proofStatus = verifyDetachedProof(certificates->front().get(), message, signature.value());
    if (!proofStatus) return foundation::fail(proofStatus.error());
    auto expiry = certificateNotAfter(certificates->front().get());
    if (!expiry || expiry.value() <= now) {
        return foundation::fail(authenticationError("The evidence certificate is expired."));
    }
    auto fingerprint = certificateFingerprint(certificates->front().get());
    if (!fingerprint) return foundation::fail(fingerprint.error());

    std::vector<Evidence> output;
    auto identityEvidence = makeEvidence(identity, m_provider, "x509.identity", "san_uri",
                                         std::move(san.value()), 98U, now, expiry.value());
    if (!identityEvidence) return foundation::fail(identityEvidence.error());
    output.push_back(std::move(identityEvidence.value()));
    auto certificateEvidence = makeEvidence(identity, m_provider, "x509.certificate", "sha256",
                                            std::move(fingerprint.value()), 95U, now, expiry.value());
    if (!certificateEvidence) return foundation::fail(certificateEvidence.error());
    output.push_back(std::move(certificateEvidence.value()));
    return output;
}

} // namespace openproof::evidence::verification
