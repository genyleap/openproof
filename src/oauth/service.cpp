module;

#include <algorithm>
#include <chrono>
#include <optional>
#include <vector>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>

module openproof.oauth;

namespace openproof::oauth {
namespace {

[[nodiscard]] bool verifierCharacter(char symbol) noexcept
{
    return (symbol >= 'A' && symbol <= 'Z') || (symbol >= 'a' && symbol <= 'z')
        || (symbol >= '0' && symbol <= '9') || symbol == '-' || symbol == '.'
        || symbol == '_' || symbol == '~';
}

}

AuthorizationCodeKey::AuthorizationCodeKey(AuthorizationCodeKey&& other) noexcept
    : m_key(std::move(other.m_key))
{
}
AuthorizationCodeKey& AuthorizationCodeKey::operator=(AuthorizationCodeKey&& other) noexcept
{
    if (this != &other) m_key = std::move(other.m_key);
    return *this;
}
AuthorizationCodeKey::~AuthorizationCodeKey() {}

RedeemedAuthorization::RedeemedAuthorization(const RedeemedAuthorization& other)
    : m_code(other.m_code) {}
RedeemedAuthorization::RedeemedAuthorization(RedeemedAuthorization&& other)
    : m_code(std::move(other.m_code)) {}
RedeemedAuthorization& RedeemedAuthorization::operator=(const RedeemedAuthorization& other)
{
    if (this != &other) m_code = other.m_code;
    return *this;
}
RedeemedAuthorization& RedeemedAuthorization::operator=(RedeemedAuthorization&& other)
{
    if (this != &other) m_code = std::move(other.m_code);
    return *this;
}
RedeemedAuthorization::~RedeemedAuthorization() {}

AuthorizationCodeKey::AuthorizationCodeKey(foundation::SecretString key)
    : m_key(std::move(key))
{
}

foundation::Result<AuthorizationCodeKey> AuthorizationCodeKey::create(
    foundation::SecretString key)
{
    if (key.expose().size() < 32U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An authorization-code key requires at least 32 bytes.");
    }
    return AuthorizationCodeKey{std::move(key)};
}

RedeemedAuthorization::RedeemedAuthorization(AuthorizationCode code)
    : m_code(std::move(code))
{
}
const client::ClientId& RedeemedAuthorization::clientId() const noexcept { return m_code.clientId(); }
const identity::core::IdentityId& RedeemedAuthorization::identity() const noexcept { return m_code.identity(); }
const std::vector<client::Scope>& RedeemedAuthorization::scopes() const noexcept { return m_code.scopes(); }
const std::optional<std::string>& RedeemedAuthorization::nonce() const noexcept { return m_code.nonce(); }
const std::optional<std::string>& RedeemedAuthorization::resource() const noexcept { return m_code.resource(); }
const identity::provider::ProviderId& RedeemedAuthorization::provider() const noexcept { return m_code.provider(); }
identity::provider::AssuranceLevel RedeemedAuthorization::assurance() const noexcept { return m_code.assurance(); }
const identity::provider::AuthenticationStrength& RedeemedAuthorization::strength() const noexcept { return m_code.strength(); }
foundation::Instant RedeemedAuthorization::authenticatedAt() const noexcept { return m_code.authenticatedAt(); }

AuthorizationService::AuthorizationService(
    client::ClientManager& clients, AuthorizationCodeStore& codes,
    const foundation::ClockSource& clock, AuthorizationCodeKey key,
    foundation::Duration codeLifetime)
    : m_clients(&clients), m_codes(&codes), m_clock(&clock), m_key(std::move(key)),
      m_codeLifetime(codeLifetime)
{
    foundation::requireInvariant(m_codeLifetime > foundation::Duration::zero(), "authorization code lifetime must be positive");
}

foundation::Result<CodeDigest> AuthorizationService::digest(
    const foundation::SecretString& code) const
{
    if (code.empty()) return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    auto digest = security::hmacSha256(m_key.m_key, code.expose());
    if (!digest) return foundation::fail(digest.error());
    return CodeDigest{digest.value()};
}

foundation::Result<PkceChallenge> AuthorizationService::challengeForVerifier(
    std::string_view verifier)
{
    if (verifier.size() < 43U || verifier.size() > 128U
        || !std::ranges::all_of(verifier, verifierCharacter)) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authorization grant is invalid.");
    }
    auto digest = security::sha256(verifier);
    if (!digest) return foundation::fail(digest.error());
    return PkceChallenge::create(foundation::toBase64Url(digest.value()));
}

foundation::Result<AuthorizationGrant> AuthorizationService::authorize(
    const session::AuthenticatedSession& authenticated,
    AuthorizationRequest request)
{
    auto client = m_clients->requireActive(request.clientId());
    if (!client) return foundation::fail(client.error());
    if (!client->permitsRedirect(request.redirectUri())
        || !client->permitsScopes(request.scopes())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The authorization request is invalid.");
    }
    const foundation::Instant now = m_clock->now();
    if (request.maximumAuthenticationAge().has_value()
        && authenticated.session().authenticatedAt()
            + *request.maximumAuthenticationAge() <= now) {
        return foundation::fail(foundation::ErrorCode::AuthenticationRequired,
                                "Fresh authentication is required.");
    }
    auto generated = security::randomTokenBase64Url(32U);
    if (!generated) return foundation::fail(generated.error());
    foundation::SecretString rawCode{"opa_" + std::move(generated).value()};
    auto fingerprint = digest(rawCode);
    if (!fingerprint) return foundation::fail(fingerprint.error());
    auto code = AuthorizationCode::create(
        fingerprint.value(), request.clientId(), authenticated.session().identity(),
        std::string{request.redirectUri()}, request.scopes(), request.codeChallenge(),
        request.nonce(), authenticated.session().provider(), authenticated.session().assurance(),
        authenticated.session().strength(), authenticated.session().authenticatedAt(), now,
        m_codeLifetime, request.resource());
    if (!code) return foundation::fail(code.error());
    auto stored = m_codes->add(std::move(code).value());
    if (!stored) return foundation::fail(stored.error());
    return AuthorizationGrant{std::move(rawCode), std::string{request.redirectUri()},
                              request.state()};
}

foundation::Result<RedeemedAuthorization> AuthorizationService::redeem(
    const foundation::SecretString& code, const client::ClientId& clientId,
    std::string_view redirectUri, std::string_view codeVerifier)
{
    auto activeClient = m_clients->requireActive(clientId);
    if (!activeClient) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authorization grant is invalid.");
    }
    auto expectedChallenge = challengeForVerifier(codeVerifier);
    if (!expectedChallenge) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authorization grant is invalid.");
    }
    auto fingerprint = digest(code);
    if (!fingerprint) return foundation::fail(fingerprint.error());
    auto stored = m_codes->consumeBound(
        fingerprint.value(), m_clock->now(), clientId.value(), redirectUri,
        expectedChallenge->value());
    if (!stored) return foundation::fail(stored.error());
    return RedeemedAuthorization{std::move(stored).value()};
}

}
