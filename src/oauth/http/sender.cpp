module;

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <limits>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

#include <boost/asio/awaitable.hpp>
#include <boost/json.hpp>

#include "protected_header_validation.hpp"

module openproof.oauth.http.sender;

import openproof.security;

namespace openproof::oauth::http {
namespace {
namespace json = boost::json;

[[nodiscard]] foundation::Result<json::object> parseJsonObject(std::string_view text)
{
    boost::system::error_code parseError;
    auto value = json::parse(text, parseError);
    if (parseError || !value.is_object()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The proof JWT is malformed.");
    }
    return std::move(value).as_object();
}

[[nodiscard]] std::optional<std::string> stringClaim(
    const json::object& object, std::string_view name)
{
    const auto found = object.find(name);
    if (found == object.end() || !found->value().is_string()) return std::nullopt;
    const auto value = found->value().as_string();
    return std::string{value.data(), value.size()};
}

[[nodiscard]] foundation::Result<std::int64_t> integerClaim(
    const json::object& object, std::string_view name)
{
    const auto found = object.find(name);
    if (found == object.end() || !found->value().is_int64()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The proof JWT temporal claim is invalid.");
    }
    return found->value().as_int64();
}

[[nodiscard]] foundation::Result<json::object> unverifiedProtectedHeader(
    std::string_view compactJwt)
{
    const auto dot = compactJwt.find('.');
    if (dot == std::string_view::npos || dot == 0U || dot > 4096U) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP proof is malformed.");
    }
    auto decoded = foundation::fromBase64Url(compactJwt.substr(0U, dot));
    if (!decoded || decoded->empty() || decoded->size() > 4096U) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP protected header is invalid.");
    }
    const std::string text{
        reinterpret_cast<const char*>(decoded->data()), decoded->size()};
    return parseJsonObject(text);
}

[[nodiscard]] foundation::Result<std::pair<std::string, std::string>> rsaJwk(
    const json::object& header)
{
    const auto algorithm = stringClaim(header, "alg");
    const auto type = stringClaim(header, "typ");
    const auto jwkFound = header.find("jwk");
    if (algorithm != std::optional<std::string>{"RS256"}
        || type != std::optional<std::string>{"dpop+jwt"}
        || !detail::joseProtectedHeaderUsesSupportedExtensions(header)
        || jwkFound == header.end() || !jwkFound->value().is_object()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP protected header is invalid.");
    }
    const auto& jwk = jwkFound->value().as_object();
    if (stringClaim(jwk, "kty") != std::optional<std::string>{"RSA"}) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP proof key is unsupported.");
    }
    for (std::string_view privateName : {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}) {
        if (jwk.contains(privateName)) {
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                    "A DPoP proof must contain only public key material.");
        }
    }
    auto modulus = stringClaim(jwk, "n");
    auto exponent = stringClaim(jwk, "e");
    if (!modulus || !exponent) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP proof key is incomplete.");
    }
    return std::pair{std::move(*modulus), std::move(*exponent)};
}

[[nodiscard]] foundation::Instant instantFromUnixSeconds(std::int64_t seconds)
{
    return foundation::Instant{
        std::chrono::duration_cast<foundation::Duration>(std::chrono::seconds{seconds})};
}

[[nodiscard]] foundation::Result<std::int64_t> decimalInteger(std::string_view text)
{
    std::int64_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authenticated mTLS forwarding timestamp is invalid.");
    }
    return value;
}

[[nodiscard]] bool safeThumbprint(std::string_view value) noexcept
{
    return value.size() == 43U && std::ranges::all_of(value, [](char symbol) {
        return (symbol >= 'A' && symbol <= 'Z') || (symbol >= 'a' && symbol <= 'z')
            || (symbol >= '0' && symbol <= '9') || symbol == '-' || symbol == '_';
    });
}

}

SenderProofVerifier::SenderProofVerifier(
    DpopService& dpop, MtlsForwardingReplayStore& mtlsReplays,
    const foundation::ClockSource& clock, std::string publicOrigin,
    std::optional<foundation::SecretString> mtlsForwardingKey)
    : m_dpop(&dpop), m_mtlsReplays(&mtlsReplays), m_clock(&clock),
      m_publicOrigin(std::move(publicOrigin)),
      m_mtlsForwardingKey(std::move(mtlsForwardingKey))
{
    while (m_publicOrigin.size() > 1U && m_publicOrigin.ends_with('/')) {
        m_publicOrigin.pop_back();
    }
}

std::string SenderProofVerifier::expectedHtu(const gateway::HttpRequest& request) const
{
    return m_publicOrigin + std::string{request.path()};
}

foundation::Result<SenderProofVerifier::ReplayProof> SenderProofVerifier::prepareDpop(
    gateway::HttpRequest& request, const foundation::SecretString* accessToken)
{
    const auto proof = request.header("dpop");
    if (!proof || proof->empty() || proof->size() > 16U * 1024U) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "A DPoP proof is required.");
    }
    auto header = unverifiedProtectedHeader(*proof);
    if (!header) return foundation::fail(header.error());
    auto key = rsaJwk(header.value());
    if (!key) return foundation::fail(key.error());
    auto verified = security::verifyRs256Jwk(key->first, key->second, *proof);
    if (!verified) return foundation::fail(verified.error());
    auto verifiedHeader = parseJsonObject(verified->headerJson());
    auto payload = parseJsonObject(verified->payloadJson());
    if (!verifiedHeader || !payload) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP proof is malformed.");
    }
    auto verifiedKey = rsaJwk(verifiedHeader.value());
    if (!verifiedKey || verifiedKey.value() != key.value()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP proof key is invalid.");
    }
    const auto jwtId = stringClaim(payload.value(), "jti");
    const auto method = stringClaim(payload.value(), "htm");
    const auto target = stringClaim(payload.value(), "htu");
    auto issuedSeconds = integerClaim(payload.value(), "iat");
    if (!jwtId || !method || !target || !issuedSeconds
        || *method != gateway::httpMethodName(request.method())
        || *target != expectedHtu(request)) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP proof is not bound to this request.");
    }
    if (accessToken != nullptr) {
        const auto accessHash = security::sha256(accessToken->expose());
        if (!accessHash) return foundation::fail(accessHash.error());
        const auto expectedAth = foundation::toBase64Url(accessHash.value());
        if (stringClaim(payload.value(), "ath") != std::optional<std::string>{expectedAth}) {
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                    "The DPoP proof is not bound to the access token.");
        }
    }
    auto thumbprint = security::rsaJwkThumbprint(key->first, key->second);
    if (!thumbprint) return foundation::fail(thumbprint.error());
    if (issuedSeconds.value()<0 || issuedSeconds.value()>
        std::numeric_limits<foundation::Duration::rep>::max()/1000-720)
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    auto window=m_dpop->replayWindow(thumbprint.value(),*jwtId,
        instantFromUnixSeconds(issuedSeconds.value()));
    if (!window) return foundation::fail(window.error());
    auto binding=token::SenderConstraint::create(
        token::SenderConstraintKind::Dpop,std::move(thumbprint).value());
    if (!binding) return foundation::fail(binding.error());
    request.eraseHeader("dpop");
    return ReplayProof{std::move(binding).value(),*jwtId,window->first,window->second,instantFromUnixSeconds(issuedSeconds.value())};
}

foundation::Result<SenderProofVerifier::ReplayProof> SenderProofVerifier::prepareMtlsForwarding(
    gateway::HttpRequest& request)
{
    const auto thumbprint = request.header("x-forwarded-client-cert-sha256");
    const auto timestamp = request.header("x-forwarded-client-cert-timestamp");
    const auto nonce = request.header("x-forwarded-client-cert-nonce");
    const auto signature = request.header("x-forwarded-client-cert-signature");
    const auto erase = [&request] {
        request.eraseHeader("x-forwarded-client-cert-sha256");
        request.eraseHeader("x-forwarded-client-cert-timestamp");
        request.eraseHeader("x-forwarded-client-cert-nonce");
        request.eraseHeader("x-forwarded-client-cert-signature");
    };
    if (!thumbprint || !timestamp || !nonce || !signature || !m_mtlsForwardingKey
        || !safeThumbprint(*thumbprint) || nonce->empty() || nonce->size() > 256U
        || signature->empty() || signature->size() > 128U) {
        erase();
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "Authenticated mTLS certificate forwarding is required.");
    }
    auto milliseconds = decimalInteger(*timestamp);
    auto suppliedSignature = foundation::fromBase64Url(*signature);
    if (!milliseconds || !suppliedSignature || suppliedSignature->size() != 32U) {
        erase();
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authenticated mTLS forwarding assertion is invalid.");
    }
    const foundation::Instant assertedAt{foundation::Duration{milliseconds.value()}};
    const auto now = m_clock->now();
    constexpr auto maximumAge = std::chrono::seconds{60};
    constexpr auto maximum=std::numeric_limits<foundation::Duration::rep>::max()-120000;
    if (milliseconds.value()<0 || milliseconds.value()>maximum
        || now.time_since_epoch().count()<0 || now.time_since_epoch().count()>maximum
        || assertedAt > now + maximumAge || assertedAt + maximumAge <= now
        || std::ranges::any_of(*nonce,[](char ch){
            const auto byte=static_cast<unsigned char>(ch);
            return byte<0x20U || byte==0x7fU;
        })) {
        erase();
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authenticated mTLS forwarding assertion expired.");
    }
    std::string payload;
    payload.reserve(request.target().size() + thumbprint->size() + nonce->size() + timestamp->size() + 32U);
    payload.append(gateway::httpMethodName(request.method())).push_back('\n');
    payload.append(request.target()).push_back('\n');
    payload.append(*thumbprint).push_back('\n');
    payload.append(*timestamp).push_back('\n');
    payload.append(*nonce);
    auto expected = security::hmacSha256(*m_mtlsForwardingKey, payload);
    if (!expected || !security::constantTimeEquals(expected.value(), suppliedSignature.value())) {
        erase();
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authenticated mTLS forwarding assertion signature is invalid.");
    }
    auto binding=token::SenderConstraint::create(token::SenderConstraintKind::Mtls,
        std::string{*thumbprint});
    const std::string identifier{*nonce};
    erase();
    if (!binding) return foundation::fail(binding.error());
    return ReplayProof{std::move(binding).value(),identifier,assertedAt+maximumAge,now,assertedAt};
}

foundation::Result<token::SenderConstraint> SenderProofVerifier::verifyDpop(
    gateway::HttpRequest& request,const foundation::SecretString* accessToken)
{
    auto prepared=prepareDpop(request,accessToken);
    if (!prepared) return foundation::fail(prepared.error());
    // Legacy callers use exactly the same time window and replay key.
    auto replay=m_dpop->consume(prepared->binding.value(),prepared->identifier,
        prepared->issuedAt);
    if (!replay) return foundation::fail(replay.error());
    return std::move(prepared->binding);
}

foundation::Result<token::SenderConstraint> SenderProofVerifier::verifyMtlsForwarding(
    gateway::HttpRequest& request)
{
    auto prepared=prepareMtlsForwarding(request);
    if (!prepared) return foundation::fail(prepared.error());
    auto replay=m_mtlsReplays->consumeMtlsForwardingReplay(prepared->binding.value(),
        prepared->identifier,prepared->expiresAt,prepared->now);
    if (!replay) return foundation::fail(replay.error());
    return std::move(prepared->binding);
}

boost::asio::awaitable<foundation::Status> SenderProofVerifier::verifyAsync(
    gateway::HttpRequest& request,const session::DelegatedSenderConstraint& constraint,
    const foundation::SecretString& accessToken,bool dpopAuthorizationScheme,ConsumeReplay consume)
{
    // This function is intentionally not a coroutine: raw credential and
    // request references cannot survive into the replay coroutine frame.
    const bool dpop=constraint.kind()==session::DelegatedSenderConstraintKind::Dpop;
    if (!consume || (constraint.kind()!=session::DelegatedSenderConstraintKind::Dpop
            && constraint.kind()!=session::DelegatedSenderConstraintKind::Mtls)
        || dpop!=dpopAuthorizationScheme)
        return consumePreparedAsync(foundation::fail(foundation::ErrorCode::AuthenticationFailed),{});
    auto prepared=dpop?prepareDpop(request,&accessToken):prepareMtlsForwarding(request);
    if (prepared && prepared->binding.value()!=constraint.value())
        prepared=foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    return consumePreparedAsync(std::move(prepared),std::move(consume));
}

boost::asio::awaitable<foundation::Status> SenderProofVerifier::consumePreparedAsync(
    foundation::Result<ReplayProof> proof,ConsumeReplay consume)
{
    if (!proof) co_return foundation::fail(proof.error());
    if (!consume) co_return foundation::fail(foundation::ErrorCode::Unavailable);
    const auto kind=proof->binding.kind()==token::SenderConstraintKind::Dpop
        ?session::DelegatedSenderConstraintKind::Dpop:session::DelegatedSenderConstraintKind::Mtls;
    co_return co_await consume(kind,std::string{proof->binding.value()},
        std::move(proof->identifier),proof->expiresAt,proof->now);
}

boost::asio::awaitable<foundation::Result<std::optional<token::SenderConstraint>>>
SenderProofVerifier::tokenEndpointConstraintAsync(gateway::HttpRequest& request,ConsumeReplay consume)
{
    // Non-coroutine: prepare and erase raw sender proof before suspension.
    const bool dpop=request.header("dpop").has_value();
    const bool mtls=request.header("x-forwarded-client-cert-sha256").has_value()
        || request.header("x-forwarded-client-cert-timestamp").has_value()
        || request.header("x-forwarded-client-cert-nonce").has_value()
        || request.header("x-forwarded-client-cert-signature").has_value();
    const auto erase=[&request] {
        for (const auto* key:{"dpop","x-forwarded-client-cert-sha256",
                "x-forwarded-client-cert-timestamp","x-forwarded-client-cert-nonce",
                "x-forwarded-client-cert-signature"}) request.eraseHeader(key);
    };
    if (dpop && mtls) {
        erase();
        return consumeTokenProofAsync(foundation::fail(foundation::ErrorCode::InvalidArgument),{});
    }
    if (!dpop && !mtls) return consumeTokenProofAsync(std::optional<ReplayProof>{},std::move(consume));
    auto prepared=dpop?prepareDpop(request,nullptr):prepareMtlsForwarding(request);
    erase();
    if (!prepared) return consumeTokenProofAsync(foundation::fail(prepared.error()),{});
    return consumeTokenProofAsync(std::optional<ReplayProof>{std::move(prepared).value()},std::move(consume));
}

boost::asio::awaitable<foundation::Result<std::optional<token::SenderConstraint>>>
SenderProofVerifier::consumeTokenProofAsync(foundation::Result<std::optional<ReplayProof>> proof,
    ConsumeReplay consume)
{
    if (!proof) co_return foundation::fail(proof.error());
    if (!proof->has_value()) co_return std::optional<token::SenderConstraint>{};
    if (!consume) co_return foundation::fail(foundation::ErrorCode::Unavailable);
    auto& prepared=proof->value();
    const auto kind=prepared.binding.kind()==token::SenderConstraintKind::Dpop
        ?session::DelegatedSenderConstraintKind::Dpop:session::DelegatedSenderConstraintKind::Mtls;
    auto consumed=co_await consume(kind,std::string{prepared.binding.value()},
        std::move(prepared.identifier),prepared.expiresAt,prepared.now);
    if (!consumed) co_return foundation::fail(consumed.error());
    co_return std::optional<token::SenderConstraint>{std::move(prepared.binding)};
}

foundation::Result<std::optional<token::SenderConstraint>>
SenderProofVerifier::tokenEndpointConstraint(gateway::HttpRequest& request)
{
    const bool hasDpop = request.header("dpop").has_value();
    const bool hasMtls = request.header("x-forwarded-client-cert-sha256").has_value()
        || request.header("x-forwarded-client-cert-timestamp").has_value()
        || request.header("x-forwarded-client-cert-nonce").has_value()
        || request.header("x-forwarded-client-cert-signature").has_value();
    if (hasDpop && hasMtls) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A token request cannot combine DPoP and mTLS sender binding.");
    }
    if (hasDpop) {
        auto verified = verifyDpop(request);
        if (!verified) return foundation::fail(verified.error());
        return std::optional<token::SenderConstraint>{std::move(verified).value()};
    }
    if (hasMtls) {
        auto verified = verifyMtlsForwarding(request);
        if (!verified) return foundation::fail(verified.error());
        return std::optional<token::SenderConstraint>{std::move(verified).value()};
    }
    return std::optional<token::SenderConstraint>{};
}

foundation::Status SenderProofVerifier::verifyTokenConstraint(
    gateway::HttpRequest& request, const token::SenderConstraint& constraint,
    const foundation::SecretString& accessToken, bool dpopAuthorizationScheme)
{
    if (constraint.kind() == token::SenderConstraintKind::Dpop) {
        if (!dpopAuthorizationScheme) {
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                    "A DPoP-bound access token requires the DPoP authorization scheme.");
        }
        auto verified = verifyDpop(request, &accessToken);
        if (!verified || verified->kind() != token::SenderConstraintKind::Dpop
            || verified->value() != constraint.value()) {
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                    "The DPoP proof key does not match the access token binding.");
        }
        return foundation::ok();
    }
    if (dpopAuthorizationScheme) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "An mTLS-bound access token uses the Bearer authorization scheme.");
    }
    auto verified = verifyMtlsForwarding(request);
    if (!verified || verified->kind() != token::SenderConstraintKind::Mtls
        || verified->value() != constraint.value()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The mTLS certificate does not match the access token binding.");
    }
    return foundation::ok();
}

foundation::Status SenderProofVerifier::verify(
    gateway::HttpRequest& request,
    const session::DelegatedSenderConstraint& constraint,
    const foundation::SecretString& accessToken,
    bool dpopAuthorizationScheme)
{
    if (constraint.kind() == session::DelegatedSenderConstraintKind::Dpop) {
        if (!dpopAuthorizationScheme) {
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                    "A DPoP-bound access token requires the DPoP authorization scheme.");
        }
        auto verified = verifyDpop(request, &accessToken);
        if (!verified || verified->kind() != token::SenderConstraintKind::Dpop
            || verified->value() != constraint.value()) {
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                    "The DPoP proof key does not match the access token binding.");
        }
        return foundation::ok();
    }
    if (dpopAuthorizationScheme) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "An mTLS-bound access token uses the Bearer authorization scheme.");
    }
    auto verified = verifyMtlsForwarding(request);
    if (!verified || verified->kind() != token::SenderConstraintKind::Mtls
        || verified->value() != constraint.value()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The mTLS certificate does not match the access token binding.");
    }
    return foundation::ok();
}

}
