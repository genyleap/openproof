module;

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

module openproof.token;

import openproof.security;

namespace openproof::token {

namespace {
constexpr std::size_t kMinimumKeyBytes = 32U;
constexpr std::size_t kTokenEntropyBytes = 32U;
constexpr std::size_t kFamilyEntropyBytes = 24U;

[[nodiscard]] foundation::Error invalidToken(std::string detail)
{
    return foundation::Error{foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

[[nodiscard]] bool sameConstraint(
    const std::optional<SenderConstraint>& expected,
    const std::optional<SenderConstraint>& presented) noexcept
{
    return (!expected && !presented)
        || (expected && presented && expected->kind() == presented->kind()
            && expected->value() == presented->value());
}
}

TokenKey::TokenKey(TokenKey&& other) noexcept
    : m_secret(std::move(other.m_secret))
{
}
TokenKey& TokenKey::operator=(TokenKey&& other) noexcept
{
    if (this != &other) m_secret = std::move(other.m_secret);
    return *this;
}
TokenKey::~TokenKey() {}

TokenGrant::TokenGrant(TokenGrant&& other) noexcept
    : m_access(std::move(other.m_access))
    , m_refresh(std::move(other.m_refresh))
    , m_expiresIn(other.m_expiresIn)
    , m_context(std::move(other.m_context))
{
}
TokenGrant& TokenGrant::operator=(TokenGrant&& other) noexcept
{
    if (this != &other) {
        m_access = std::move(other.m_access);
        m_refresh = std::move(other.m_refresh);
        m_expiresIn = other.m_expiresIn;
        m_context = std::move(other.m_context);
    }
    return *this;
}
TokenGrant::~TokenGrant() {}

TokenKey::TokenKey(foundation::SecretString secret) : m_secret(std::move(secret)) {}
foundation::Result<TokenKey> TokenKey::create(foundation::SecretString secret)
{
    if (secret.expose().size() < kMinimumKeyBytes) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A token key must contain at least 32 bytes.");
    }
    return TokenKey{std::move(secret)};
}

TokenPolicy::TokenPolicy(const TokenPolicy& other)
    : m_accessLifetime(other.m_accessLifetime)
    , m_refreshLifetime(other.m_refreshLifetime)
{
}
TokenPolicy::TokenPolicy(TokenPolicy&& other)
    : m_accessLifetime(other.m_accessLifetime)
    , m_refreshLifetime(other.m_refreshLifetime)
{
}
TokenPolicy& TokenPolicy::operator=(const TokenPolicy& other)
{
    if (this != &other) {
        m_accessLifetime = other.m_accessLifetime;
        m_refreshLifetime = other.m_refreshLifetime;
    }
    return *this;
}
TokenPolicy& TokenPolicy::operator=(TokenPolicy&& other)
{
    if (this != &other) {
        m_accessLifetime = other.m_accessLifetime;
        m_refreshLifetime = other.m_refreshLifetime;
    }
    return *this;
}
TokenPolicy::~TokenPolicy() {}

TokenPolicy::TokenPolicy(foundation::Duration accessLifetime,
                         foundation::Duration refreshLifetime)
    : m_accessLifetime(accessLifetime), m_refreshLifetime(refreshLifetime) {}
foundation::Result<TokenPolicy> TokenPolicy::create(
    foundation::Duration accessLifetime, foundation::Duration refreshLifetime)
{
    if (accessLifetime <= foundation::Duration::zero()
        || refreshLifetime <= accessLifetime
        || accessLifetime > std::chrono::hours{1}
        || refreshLifetime > std::chrono::hours{24 * 90}) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "OAuth token lifetimes are invalid.");
    }
    return TokenPolicy{accessLifetime, refreshLifetime};
}
foundation::Duration TokenPolicy::accessLifetime() const noexcept { return m_accessLifetime; }
foundation::Duration TokenPolicy::refreshLifetime() const noexcept { return m_refreshLifetime; }

TokenGrant::TokenGrant(foundation::SecretString access, foundation::SecretString refresh,
                       foundation::Duration expiresIn, TokenContext context)
    : m_access(std::move(access)), m_refresh(std::move(refresh)), m_expiresIn(expiresIn),
      m_context(std::move(context)) {}
const foundation::SecretString& TokenGrant::accessToken() const noexcept { return m_access; }
const foundation::SecretString& TokenGrant::refreshToken() const noexcept { return m_refresh; }
foundation::Duration TokenGrant::expiresIn() const noexcept { return m_expiresIn; }
const TokenContext& TokenGrant::context() const noexcept { return m_context; }

MachineTokenGrant::MachineTokenGrant(
    foundation::SecretString access, foundation::Duration expiresIn, TokenContext context)
    : m_access(std::move(access)), m_expiresIn(expiresIn), m_context(std::move(context))
{
}
MachineTokenGrant::MachineTokenGrant(MachineTokenGrant&&) noexcept = default;
MachineTokenGrant& MachineTokenGrant::operator=(MachineTokenGrant&&) noexcept = default;
MachineTokenGrant::~MachineTokenGrant() = default;
const foundation::SecretString& MachineTokenGrant::accessToken() const noexcept { return m_access; }
foundation::Duration MachineTokenGrant::expiresIn() const noexcept { return m_expiresIn; }
const TokenContext& MachineTokenGrant::context() const noexcept { return m_context; }

TokenService::TokenService(TokenRepository& repository, client::ClientManager& clients,
                           const foundation::ClockSource& clock, TokenKey key,
                           TokenPolicy policy)
    : m_repository(repository), m_clients(clients), m_clock(clock),
      m_key(std::move(key)), m_policy(policy) {}

foundation::Result<TokenDigest> TokenService::digest(const foundation::SecretString& token) const
{
    if (token.empty() || token.expose().size() > 256U) {
        return foundation::fail(invalidToken("An invalid OAuth token was presented."));
    }
    auto fingerprint = security::hmacSha256(m_key.m_secret, token.expose());
    if (!fingerprint.has_value()) return foundation::fail(fingerprint.error());
    return TokenDigest{fingerprint.value()};
}

foundation::Result<TokenGrant> TokenService::issue(
    const oauth::RedeemedAuthorization& authorization,
    std::optional<SenderConstraint> senderConstraint)
{
    std::vector<std::string> scopes;
    scopes.reserve(authorization.scopes().size());
    for (const auto& scope : authorization.scopes()) {
        scopes.emplace_back(scope.value());
    }
    std::vector<std::string> audiences;
    if (authorization.resource().has_value()) {
        audiences.push_back(*authorization.resource());
    }
    TokenContext context{authorization.clientId(), authorization.identity(),
                         authorization.provider(), authorization.assurance(),
                         authorization.strength(), std::move(scopes),
                         authorization.authenticatedAt(), std::move(audiences),
                         std::move(senderConstraint)};
    return makeInitial(std::move(context));
}

foundation::Result<TokenGrant> TokenService::makeInitial(TokenContext context)
{
    const auto client = m_clients.requireActive(context.client());
    if (!client.has_value()) return foundation::fail(client.error());
    auto familyRaw = security::randomTokenBase64Url(kFamilyEntropyBytes);
    auto accessRaw = security::randomTokenBase64Url(kTokenEntropyBytes);
    auto refreshRaw = security::randomTokenBase64Url(kTokenEntropyBytes);
    if (!familyRaw.has_value()) return foundation::fail(familyRaw.error());
    if (!accessRaw.has_value()) return foundation::fail(accessRaw.error());
    if (!refreshRaw.has_value()) return foundation::fail(refreshRaw.error());
    foundation::SecretString access{std::string{"opa_"} + accessRaw.value()};
    foundation::SecretString refresh{std::string{"opr_"} + refreshRaw.value()};
    auto accessDigest = digest(access);
    auto refreshDigest = digest(refresh);
    if (!accessDigest.has_value()) return foundation::fail(accessDigest.error());
    if (!refreshDigest.has_value()) return foundation::fail(refreshDigest.error());
    const auto now = m_clock.now();
    TokenFamilyId family{std::move(familyRaw).value()};
    AccessTokenRecord accessRecord{accessDigest.value(), family, context, now,
                                   now + m_policy.accessLifetime()};
    RefreshTokenRecord refreshRecord{refreshDigest.value(), family, 0U, context, now,
                                     now + m_policy.refreshLifetime()};
    const auto stored = m_repository.storeInitial(std::move(accessRecord),
                                                   std::move(refreshRecord));
    if (!stored.has_value()) return foundation::fail(stored.error());
    return TokenGrant{std::move(access), std::move(refresh),
                      m_policy.accessLifetime(), std::move(context)};
}

foundation::Result<TokenGrant> TokenService::issueDeviceAuthorization(
    const oauth::DeviceAuthorization& authorization,
    std::optional<SenderConstraint> senderConstraint)
{
    if (authorization.status() != oauth::DeviceAuthorizationStatus::Consumed
        || !authorization.identity() || !authorization.provider()
        || !authorization.assurance() || !authorization.strength()
        || !authorization.authenticatedAt()) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "The device authorization has not been consumed safely.");
    }
    std::vector<std::string> scopes;
    scopes.reserve(authorization.scopes().size());
    for (const auto& scope : authorization.scopes()) {
        scopes.emplace_back(scope.value());
    }
    std::vector<std::string> audiences;
    if (authorization.resource()) audiences.push_back(*authorization.resource());
    TokenContext context{
        authorization.clientId(), *authorization.identity(), *authorization.provider(),
        *authorization.assurance(), *authorization.strength(), std::move(scopes),
        *authorization.authenticatedAt(), std::move(audiences),
        std::move(senderConstraint)};
    return makeInitial(std::move(context));
}

foundation::Result<MachineTokenGrant> TokenService::issueClientCredentials(
    const resource::ServiceIdentity& service, std::string audience,
    std::vector<std::string> scopes, std::optional<SenderConstraint> senderConstraint)
{
    if (!service.active() || !service.permitsAudience(audience)
        || !service.permitsScopes(scopes) || scopes.empty()) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            "The service identity does not permit the requested machine grant.");
    }
    auto activeClient = m_clients.requireActive(service.client());
    if (!activeClient || activeClient->kind() != client::ClientKind::Service) {
        return foundation::fail(
            foundation::ErrorCode::AuthenticationFailed,
            "Client authentication failed.");
    }
    auto familyRaw = security::randomTokenBase64Url(kFamilyEntropyBytes);
    auto accessRaw = security::randomTokenBase64Url(kTokenEntropyBytes);
    if (!familyRaw) return foundation::fail(familyRaw.error());
    if (!accessRaw) return foundation::fail(accessRaw.error());
    foundation::SecretString access{std::string{"opa_"} + accessRaw.value()};
    auto accessDigest = digest(access);
    if (!accessDigest) return foundation::fail(accessDigest.error());
    const auto now = m_clock.now();
    TokenContext context{
        service.client(), service.identity(),
        identity::provider::ProviderId{"client_credentials"},
        identity::provider::AssuranceLevel::Ial1,
        identity::provider::AuthenticationStrength{
            identity::provider::AuthenticationFactor::Knowledge, false},
        std::move(scopes), now, std::vector<std::string>{std::move(audience)},
        std::move(senderConstraint)};
    AccessTokenRecord record{
        accessDigest.value(), TokenFamilyId{std::move(familyRaw).value()},
        context, now, now + m_policy.accessLifetime()};
    auto stored = m_repository.storeAccessOnly(std::move(record));
    if (!stored) return foundation::fail(stored.error());
    return MachineTokenGrant{std::move(access), m_policy.accessLifetime(), std::move(context)};
}

foundation::Result<MachineTokenGrant> TokenService::issueTokenExchange(
    const client::ClientId& clientId, const foundation::SecretString& subjectToken,
    std::string audience, std::vector<std::string> scopes,
    std::optional<SenderConstraint> senderConstraint)
{
    auto source = introspect(subjectToken);
    if (!source) return foundation::fail(source.error());
    const auto& sourceContext = source->context();
    if (sourceContext.client() != clientId) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The subject token is not bound to this client.");
    }
    if (!sameConstraint(sourceContext.senderConstraint(), senderConstraint)) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The subject token sender binding is invalid.");
    }
    if (audience.empty() || !sourceContext.permitsAudience(audience)) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                "Token exchange cannot widen the audience.");
    }
    if (scopes.empty()) scopes = sourceContext.scopes();
    for (const auto& scope : scopes) {
        if (!sourceContext.permits(scope)) {
            return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                    "Token exchange cannot widen scope.");
        }
    }
    auto familyRaw = security::randomTokenBase64Url(kFamilyEntropyBytes);
    auto accessRaw = security::randomTokenBase64Url(kTokenEntropyBytes);
    if (!familyRaw) return foundation::fail(familyRaw.error());
    if (!accessRaw) return foundation::fail(accessRaw.error());
    foundation::SecretString access{std::string{"opa_"} + accessRaw.value()};
    auto accessDigest = digest(access);
    if (!accessDigest) return foundation::fail(accessDigest.error());
    const auto now = m_clock.now();
    TokenContext context{
        clientId, sourceContext.identity(), sourceContext.provider(),
        sourceContext.assurance(), sourceContext.strength(), std::move(scopes),
        sourceContext.authenticatedAt(), std::vector<std::string>{std::move(audience)},
        std::move(senderConstraint)};
    AccessTokenRecord record{
        accessDigest.value(), TokenFamilyId{std::move(familyRaw).value()},
        context, now, now + m_policy.accessLifetime()};
    auto stored = m_repository.storeAccessOnly(std::move(record));
    if (!stored) return foundation::fail(stored.error());
    return MachineTokenGrant{std::move(access), m_policy.accessLifetime(), std::move(context)};
}

foundation::Result<TokenGrant> TokenService::refresh(
    const client::ClientId& clientId, const foundation::SecretString& refreshToken,
    std::optional<SenderConstraint> senderConstraint)
{
    auto activeClient = m_clients.requireActive(clientId);
    if (!activeClient.has_value()) return foundation::fail(activeClient.error());
    auto fingerprint = digest(refreshToken);
    if (!fingerprint.has_value()) return foundation::fail(fingerprint.error());
    auto current = m_repository.findRefresh(fingerprint.value());
    if (!current.has_value()) return foundation::fail(current.error());
    if (current->context().client() != clientId) {
        return foundation::fail(invalidToken("Refresh token client binding mismatch."));
    }
    if (!sameConstraint(current->context().senderConstraint(), senderConstraint)) {
        return foundation::fail(invalidToken("Refresh token sender binding mismatch."));
    }
    return makeRotation(current.value());
}

foundation::Result<TokenGrant> TokenService::makeRotation(const RefreshTokenRecord& current)
{
    auto accessRaw = security::randomTokenBase64Url(kTokenEntropyBytes);
    auto refreshRaw = security::randomTokenBase64Url(kTokenEntropyBytes);
    if (!accessRaw.has_value()) return foundation::fail(accessRaw.error());
    if (!refreshRaw.has_value()) return foundation::fail(refreshRaw.error());
    foundation::SecretString access{std::string{"opa_"} + accessRaw.value()};
    foundation::SecretString refresh{std::string{"opr_"} + refreshRaw.value()};
    auto accessDigest = digest(access);
    auto refreshDigest = digest(refresh);
    if (!accessDigest.has_value()) return foundation::fail(accessDigest.error());
    if (!refreshDigest.has_value()) return foundation::fail(refreshDigest.error());
    const auto now = m_clock.now();
    AccessTokenRecord accessRecord{accessDigest.value(), current.family(), current.context(),
                                   now, now + m_policy.accessLifetime()};
    // Rotation does not extend the refresh family lifetime.  A stolen token
    // must not be kept alive indefinitely by continuous successful rotation.
    RefreshTokenRecord refreshRecord{refreshDigest.value(), current.family(),
        current.sequence() + 1U, current.context(), now,
        current.expiresAt()};
    const auto rotated = m_repository.rotateRefresh(current.digest(), now,
        std::move(accessRecord), std::move(refreshRecord));
    if (!rotated.has_value()) return foundation::fail(rotated.error());
    return TokenGrant{std::move(access), std::move(refresh),
                      m_policy.accessLifetime(), current.context()};
}

foundation::Result<TokenClaims> TokenService::introspect(
    const foundation::SecretString& accessToken)
{
    auto fingerprint = digest(accessToken);
    if (!fingerprint.has_value()) return foundation::fail(fingerprint.error());
    auto record = m_repository.findAccess(fingerprint.value());
    if (!record.has_value()) return foundation::fail(record.error());
    if (!record->usableAt(m_clock.now())) {
        return foundation::fail(invalidToken("The access token is inactive."));
    }
    auto client = m_clients.requireActive(record->context().client());
    if (!client.has_value()) return foundation::fail(invalidToken("The OAuth client is inactive."));
    return TokenClaims{true, record->context(), record->issuedAt(), record->expiresAt()};
}

foundation::Status TokenService::revoke(const foundation::SecretString& token)
{
    auto fingerprint = digest(token);
    if (!fingerprint.has_value()) return foundation::ok();
    return m_repository.revokeToken(fingerprint.value(), m_clock.now());
}

foundation::Status TokenService::revokeForClient(
    const client::ClientId& clientId, const foundation::SecretString& token)
{
    auto fingerprint = digest(token);
    if (!fingerprint) return foundation::ok();
    auto access = m_repository.findAccess(fingerprint.value());
    if (access && access->context().client() == clientId) {
        return m_repository.revokeToken(fingerprint.value(), m_clock.now());
    }
    auto refresh = m_repository.findRefresh(fingerprint.value());
    if (refresh && refresh->context().client() == clientId) {
        return m_repository.revokeToken(fingerprint.value(), m_clock.now());
    }
    return foundation::ok();
}

foundation::Result<session::DelegatedAccess> TokenService::authenticateDelegated(
    const foundation::SecretString& token)
{
    auto claims = introspect(token);
    if (!claims.has_value()) return foundation::fail(claims.error());
    const auto& context = claims->context();
    auto authenticated = session::AuthenticatedSession::fromDelegatedAccess(
        context.identity(), context.provider(), context.assurance(), context.strength(),
        context.authenticatedAt(), m_clock.now(), claims->expiresAt());
    if (!authenticated.has_value()) return foundation::fail(authenticated.error());
    std::vector<std::string> scopes = context.scopes();
    std::vector<std::string> audiences = context.audiences();
    std::optional<session::DelegatedSenderConstraint> senderConstraint;
    if (context.senderConstraint()) {
        const auto kind = context.senderConstraint()->kind() == SenderConstraintKind::Dpop
            ? session::DelegatedSenderConstraintKind::Dpop
            : session::DelegatedSenderConstraintKind::Mtls;
        senderConstraint.emplace(kind, std::string{context.senderConstraint()->value()});
    }
    return session::DelegatedAccess{std::move(authenticated).value(),
                                    std::string{context.client().value()},
                                    std::move(scopes), std::move(audiences),
                                    std::move(senderConstraint)};
}

}
