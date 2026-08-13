module;

#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include <boost/json.hpp>

module openproof.evidence.http;

namespace openproof::evidence::http {
namespace {
namespace json = boost::json;

constexpr std::size_t kMaximumBody = 96U * 1024U;

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, json::value value)
{
    gateway::HttpResponse response{status,
        gateway::Headers{{"content-type", "application/json"}}, json::serialize(value)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    return response;
}

[[nodiscard]] foundation::Result<json::object> objectBody(const gateway::HttpRequest& request)
{
    if (request.body().empty() || request.body().size() > kMaximumBody) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request body is invalid.");
    }
    boost::system::error_code error;
    auto value = json::parse(request.body(), error);
    if (error || !value.is_object()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The request body must be a JSON object.");
    }
    return std::move(value).as_object();
}

[[nodiscard]] foundation::Result<std::string> requiredString(
    const json::object& object, std::string_view name, std::size_t maximum)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || !value->is_string() || value->as_string().empty()
        || value->as_string().size() > maximum) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A required evidence field is invalid.");
    }
    return std::string{value->as_string()};
}

[[nodiscard]] json::object evidenceJson(const Evidence& item)
{
    json::object output{
        {"id", item.id().str()},
        {"provider", item.provider().str()},
        {"kind", std::string{item.kind()}},
        {"claim", std::string{item.claim()}},
        {"value", std::string{item.value()}},
        {"confidence", item.confidence()},
        {"status", item.status() == EvidenceStatus::Verified ? "verified" : "revoked"},
        {"verified_at", foundation::toIso8601(item.verifiedAt())},
    };
    if (item.expiresAt()) output["expires_at"] = foundation::toIso8601(*item.expiresAt());
    return output;
}

} // namespace

Api::Api(EvidenceService& evidence, EvidenceRepository& repository,
         verification::ChallengeService& challenges, trust::TrustEngine& trustEngine,
         session::SessionService& sessions, std::set<std::string, std::less<>> providers,
         gateway::TokenBucketRateLimiter& limiter, gateway::HttpHandler& fallback)
    : m_evidence(&evidence), m_repository(&repository), m_challenges(&challenges),
      m_trust(&trustEngine), m_sessions(&sessions), m_providers(std::move(providers)),
      m_limiter(&limiter), m_fallback(&fallback)
{
}

foundation::Result<identity::core::IdentityId> Api::authorize(gateway::HttpRequest& request) const
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential) return foundation::fail(credential.error());
    if (!credential->has_value()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationRequired,
                                "Authentication is required.");
    }
    auto authenticated = m_sessions->authenticate(credential->value());
    if (!authenticated) return foundation::fail(authenticated.error());
    return authenticated->session().identity();
}

gateway::HttpResponse Api::error(
    const foundation::Error& failure, const gateway::HttpRequest& request) const
{
    gateway::HttpResponse response{
        foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    if (failure.code() == foundation::ErrorCode::AuthenticationRequired) {
        response.setHeader("www-authenticate", "Bearer");
    }
    return response;
}

gateway::HttpResponse Api::handle(gateway::HttpRequest request)
{
    if (request.path() != "/evidence" && request.path() != "/trust"
        && !request.path().starts_with("/evidence/")) {
        return m_fallback->handle(std::move(request));
    }
    const std::string key = "evidence:" + std::string{request.remoteAddress()} + ":"
        + std::string{request.path()};
    if (!m_limiter->allow(key)) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    using gateway::HttpMethod;
    if (request.method() == HttpMethod::Post && request.path() == "/evidence/challenge") {
        return issueChallenge(std::move(request));
    }
    if (request.method() == HttpMethod::Post && request.path() == "/evidence/verify") {
        return verify(std::move(request));
    }
    if (request.method() == HttpMethod::Get && request.path() == "/evidence") {
        return list(std::move(request));
    }
    if (request.method() == HttpMethod::Get && request.path() == "/trust") {
        return assess(std::move(request));
    }
    return jsonResponse(404, json::object{{"error", "not_found"}});
}

gateway::HttpResponse Api::issueChallenge(gateway::HttpRequest request)
{
    auto identity = authorize(request);
    if (!identity) return error(identity.error(), request);
    auto body = objectBody(request);
    if (!body) return error(body.error(), request);
    auto provider = requiredString(body.value(), "provider", 200U);
    if (!provider) return error(provider.error(), request);
    if (!m_providers.contains(*provider)) {
        return error(foundation::Error{foundation::ErrorCode::NotFound,
                                      "The evidence verifier is unavailable."}, request);
    }
    const identity::provider::ProviderId providerId{*provider};
    auto challenge = m_challenges->issue(identity.value(), providerId);
    if (!challenge) return error(challenge.error(), request);
    const auto token = challenge->token.expose();
    json::object output{
        {"provider", *provider},
        {"challenge", token},
        {"subject", identity->str()},
        {"expires_at", foundation::toIso8601(challenge->expiresAt)},
    };
    if (*provider == "x509-evidence") {
        output["proof_message"] = "OpenProof Evidence Proof\n" + token + "\n" + identity->str();
    }
    return jsonResponse(201, std::move(output));
}

gateway::HttpResponse Api::verify(gateway::HttpRequest request)
{
    auto identity = authorize(request);
    if (!identity) return error(identity.error(), request);
    auto body = objectBody(request);
    if (!body) return error(body.error(), request);
    auto provider = requiredString(body.value(), "provider", 200U);
    auto challenge = requiredString(body.value(), "challenge", 256U);
    if (!provider || !challenge) return error(!provider ? provider.error() : challenge.error(), request);
    if (!m_providers.contains(*provider)) {
        return error(foundation::Error{foundation::ErrorCode::NotFound,
                                      "The evidence verifier is unavailable."}, request);
    }
    const identity::provider::ProviderId providerId{*provider};
    foundation::SecretString challengeSecret{*challenge};
    auto consumed = m_challenges->consume(identity.value(), providerId, challengeSecret);
    if (!consumed) return error(consumed.error(), request);

    identity::provider::AttributeMap publicInputs{{"challenge", *challenge}};
    identity::provider::SecretAttributeMap secretInputs;
    if (*provider == "signed-jwt-evidence") {
        auto assertion = requiredString(body.value(), "assertion", 16U * 1024U);
        if (!assertion) return error(assertion.error(), request);
        secretInputs.emplace("assertion", identity::provider::CredentialValue{std::move(*assertion)});
    } else if (*provider == "x509-evidence") {
        auto certificate = requiredString(body.value(), "certificate_pem", 64U * 1024U);
        auto signature = requiredString(body.value(), "signature", 12U * 1024U);
        if (!certificate || !signature) {
            return error(!certificate ? certificate.error() : signature.error(), request);
        }
        publicInputs.emplace("certificate_pem", std::move(*certificate));
        secretInputs.emplace("signature", identity::provider::CredentialValue{std::move(*signature)});
    } else {
        return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    }

    auto verified = m_evidence->verify(identity.value(), providerId, publicInputs, secretInputs);
    if (!verified) return error(verified.error(), request);
    json::array items;
    items.reserve(verified->size());
    for (const auto& item : verified.value()) items.emplace_back(evidenceJson(item));
    return jsonResponse(201, json::object{{"evidence", std::move(items)}});
}

gateway::HttpResponse Api::list(gateway::HttpRequest request)
{
    auto identity = authorize(request);
    if (!identity) return error(identity.error(), request);
    auto records = m_repository->forIdentity(identity.value());
    if (!records) return error(records.error(), request);
    json::array items;
    items.reserve(records->size());
    for (const auto& item : records.value()) items.emplace_back(evidenceJson(item));
    return jsonResponse(200, json::object{{"evidence", std::move(items)}});
}

gateway::HttpResponse Api::assess(gateway::HttpRequest request)
{
    auto identity = authorize(request);
    if (!identity) return error(identity.error(), request);
    auto assessment = m_trust->assess(identity.value());
    if (!assessment) return error(assessment.error(), request);
    json::array ids;
    for (const auto& id : assessment->evidenceIds()) ids.emplace_back(id);
    return jsonResponse(200, json::object{
        {"identity", identity->str()},
        {"trust_score", assessment->trustScore()},
        {"risk_score", assessment->riskScore()},
        {"confidence", assessment->confidence()},
        {"evidence_ids", std::move(ids)},
    });
}

} // namespace openproof::evidence::http
