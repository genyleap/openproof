module;

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

module openproof.provider.local;

import openproof.security;

namespace openproof::provider::local {
namespace {

constexpr std::size_t kIdentifierEntropyBytes = 32U;

[[nodiscard]] foundation::Error authenticationFailure(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(
            foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

[[nodiscard]] std::optional<std::string_view> parameter(
    const idp::SecretAttributeMap& parameters, std::string_view name)
{
    const auto found = parameters.find(name);
    return found == parameters.end()
               ? std::nullopt
               : std::optional<std::string_view>{found->second.expose()};
}

}

struct InMemoryLocalAccountDirectory::Account final {
    Account(credentials::PasswordHash passwordHash,
            std::optional<credentials::TotpSecret> totpSecret,
            std::optional<identity::core::IdentityId> canonicalIdentity = std::nullopt)
        : identity(std::move(canonicalIdentity)),
          password(std::move(passwordHash)), totp(std::move(totpSecret))
    {
    }

    std::optional<identity::core::IdentityId> identity;
    credentials::PasswordHash password;
    std::optional<credentials::TotpSecret> totp;
    std::optional<std::uint64_t> lastAcceptedTotpStep;
    std::mutex mutex;
};

InMemoryLocalAccountDirectory::InMemoryLocalAccountDirectory(
    credentials::PasswordHasher passwordHasher,
    credentials::TotpPolicy totpPolicy,
    credentials::PasswordHash dummyHash)
    : m_passwordHasher(std::move(passwordHasher)), m_totpPolicy(totpPolicy),
      m_dummyHash(std::move(dummyHash))
{
}

InMemoryLocalAccountDirectory::~InMemoryLocalAccountDirectory() = default;

foundation::Result<std::unique_ptr<InMemoryLocalAccountDirectory>>
InMemoryLocalAccountDirectory::create(
    credentials::PasswordHasher passwordHasher,
    credentials::TotpPolicy totpPolicy)
{
    const foundation::SecretString dummyPassword{
        "openproof-dummy-password-never-valid"};
    auto dummyHash = passwordHasher.hash(dummyPassword);
    if (!dummyHash.has_value()) {
        return foundation::fail(dummyHash.error());
    }
    return std::unique_ptr<InMemoryLocalAccountDirectory>{
        new InMemoryLocalAccountDirectory{
            std::move(passwordHasher), totpPolicy, std::move(dummyHash).value()}};
}

foundation::Status InMemoryLocalAccountDirectory::enroll(
    idp::ExternalSubject subject, const foundation::SecretString& password,
    std::optional<credentials::TotpSecret> totp)
{
    if (subject.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A local account subject must not be empty.");
    }
    auto passwordHash = m_passwordHasher.hash(password);
    if (!passwordHash.has_value()) {
        return foundation::fail(passwordHash.error());
    }
    const std::lock_guard<std::mutex> guard{m_mutex};
    if (m_accounts.contains(subject)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The local account already exists.");
    }
    m_accounts.emplace(std::move(subject), std::make_unique<Account>(
        std::move(passwordHash).value(), std::move(totp)));
    return foundation::ok();
}


foundation::Status InMemoryLocalAccountDirectory::enrollPending(
    identity::core::IdentityId canonicalIdentity, idp::ExternalSubject subject,
    const foundation::SecretString& password,
    std::optional<credentials::TotpSecret> totp)
{
    if (canonicalIdentity.empty() || subject.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A pending local account requires identity and subject.");
    }
    auto passwordHash = m_passwordHasher.hash(password);
    if (!passwordHash.has_value()) return foundation::fail(passwordHash.error());
    const std::lock_guard<std::mutex> guard{m_mutex};
    if (m_accounts.contains(subject)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The local account already exists.");
    }
    m_accounts.emplace(std::move(subject), std::make_unique<Account>(
        std::move(passwordHash).value(), std::move(totp), std::move(canonicalIdentity)));
    return foundation::ok();
}

foundation::Status InMemoryLocalAccountDirectory::rebindSubject(
    const identity::core::IdentityId& identity,
    const idp::ExternalSubject& previous,
    idp::ExternalSubject replacement)
{
    if (identity.empty() || previous.empty() || replacement.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A local account rebind requires valid identifiers.");
    }
    const std::lock_guard<std::mutex> guard{m_mutex};
    if (m_accounts.contains(replacement)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The replacement local account subject already exists.");
    }
    const auto found = m_accounts.find(previous);
    if (found == m_accounts.end()) {
        return foundation::fail(authenticationFailure("Local account is unknown."));
    }
    if (found->second->identity.has_value() && found->second->identity.value() != identity) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                "The local account is owned by another identity.");
    }
    auto account = std::move(found->second);
    account->identity = identity;
    m_accounts.erase(found);
    m_accounts.emplace(std::move(replacement), std::move(account));
    return foundation::ok();
}

foundation::Status InMemoryLocalAccountDirectory::removePending(
    const identity::core::IdentityId& identity,
    const idp::ExternalSubject& subject)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto found = m_accounts.find(subject);
    if (found == m_accounts.end()) return foundation::ok();
    if (!found->second->identity.has_value() || found->second->identity.value() != identity) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                "The pending local account is owned by another identity.");
    }
    m_accounts.erase(found);
    return foundation::ok();
}

foundation::Status InMemoryLocalAccountDirectory::changePassword(
    const idp::ExternalSubject& subject, const foundation::SecretString& password)
{
    auto passwordHash = m_passwordHasher.hash(password);
    if (!passwordHash.has_value()) {
        return foundation::fail(passwordHash.error());
    }
    Account* account = nullptr;
    {
        const std::lock_guard<std::mutex> guard{m_mutex};
        const auto found = m_accounts.find(subject);
        if (found != m_accounts.end()) {
            account = found->second.get();
        }
    }
    if (account == nullptr) {
        return foundation::fail(authenticationFailure("Local account is unknown."));
    }
    const std::lock_guard<std::mutex> accountGuard{account->mutex};
    account->password = std::move(passwordHash).value();
    return foundation::ok();
}

foundation::Result<LocalVerification> InMemoryLocalAccountDirectory::verify(
    const idp::ExternalSubject& subject, const foundation::SecretString& password,
    std::optional<std::string_view> totp, foundation::Instant now)
{
    Account* account = nullptr;
    {
        const std::lock_guard<std::mutex> guard{m_mutex};
        const auto found = m_accounts.find(subject);
        if (found != m_accounts.end()) {
            account = found->second.get();
        }
    }
    if (account == nullptr) {
        const auto dummyResult = m_passwordHasher.verify(password, m_dummyHash);
        if (!dummyResult.has_value()) {
            return foundation::fail(dummyResult.error());
        }
        return foundation::fail(authenticationFailure("Local account is unknown."));
    }
    const std::lock_guard<std::mutex> accountGuard{account->mutex};
    auto passwordMatches = m_passwordHasher.verify(password, account->password);
    if (!passwordMatches.has_value()) {
        return foundation::fail(passwordMatches.error());
    }
    if (!passwordMatches.value()) {
        return foundation::fail(authenticationFailure("Local password did not verify."));
    }
    if (!account->totp.has_value()) {
        return LocalVerification::Password;
    }
    if (!totp.has_value()) {
        return foundation::fail(authenticationFailure("A second factor is required."));
    }
    auto accepted = credentials::verifyTotp(
        account->totp.value(), m_totpPolicy, totp.value(), now,
        account->lastAcceptedTotpStep);
    if (!accepted.has_value()) {
        return foundation::fail(accepted.error());
    }
    account->lastAcceptedTotpStep = accepted.value();
    return LocalVerification::PasswordAndTotp;
}

LocalAuthenticationProvider::LocalAuthenticationProvider(
    idp::ProviderId id, LocalAccountDirectory& accounts,
    const foundation::ClockSource& clock,
    foundation::Duration challengeLifetime)
    : m_id(std::move(id)), m_accounts(&accounts), m_clock(&clock),
      m_challengeLifetime(challengeLifetime)
{
}

idp::ProviderId LocalAuthenticationProvider::id() const { return m_id; }

idp::InteractionModel LocalAuthenticationProvider::interactionModel() const noexcept
{
    return idp::InteractionModel::ChallengeResponse;
}

idp::AssuranceLevel LocalAuthenticationProvider::maximumClaimableAssurance() const noexcept
{
    return idp::AssuranceLevel::Ial2;
}

foundation::Result<idp::AuthenticationChallenge>
LocalAuthenticationProvider::beginAuthentication(const idp::AuthenticationRequest& request)
{
    if (m_id.empty() || request.provider() != m_id
        || m_challengeLifetime <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The local authentication request is invalid.");
    }
    const auto subjectParameter = request.parameters().find("subject");
    if (subjectParameter == request.parameters().end() || subjectParameter->second.empty()
        || subjectParameter->second.size() > 320U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The local authentication request is invalid.");
    }
    auto identifier = security::randomTokenBase64Url(kIdentifierEntropyBytes);
    if (!identifier.has_value()) {
        return foundation::fail(identifier.error());
    }
    idp::ChallengeId challengeId{std::move(identifier).value()};
    const foundation::Instant expiresAt = m_clock->now() + m_challengeLifetime;
    {
        const std::lock_guard<std::mutex> guard{m_mutex};
        const auto inserted = m_pending.emplace(
            challengeId, Pending{idp::ExternalSubject{subjectParameter->second}, expiresAt});
        if (!inserted.second) {
            return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                    "The authentication challenge could not be created.");
        }
    }
    idp::AuthenticationChallenge challenge{challengeId, expiresAt};
    challenge.setParameter("method", "password_totp");
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome>
LocalAuthenticationProvider::completeAuthentication(
    const idp::AuthenticationResponse& response)
{
    std::optional<Pending> pending;
    {
        const std::lock_guard<std::mutex> guard{m_mutex};
        const auto found = m_pending.find(response.challengeId());
        if (found == m_pending.end()) {
            return foundation::fail(authenticationFailure("Local challenge is unknown."));
        }
        pending = std::move(found->second);
        m_pending.erase(found);
    }
    const foundation::Instant now = m_clock->now();
    if (now >= pending->expiresAt) {
        return foundation::fail(authenticationFailure("Local challenge expired."));
    }
    const auto passwordValue = parameter(response.parameters(), "password");
    if (!passwordValue.has_value()) {
        return foundation::fail(authenticationFailure("Local password is missing."));
    }
    foundation::SecretString password{std::string{passwordValue.value()}};
    const auto verified = m_accounts->verify(
        pending->subject, password, parameter(response.parameters(), "totp"), now);
    if (!verified.has_value()) {
        return foundation::fail(authenticationFailure(
            std::string{"Local credential verification failed: "}
            + std::string{verified.error().internalDetail()}));
    }

    idp::VerifiedClaims claims;
    idp::ProviderEvidence evidence;
    evidence.add("method", verified.value() == LocalVerification::Password
                               ? "password" : "password_totp");
    const bool multiFactor = verified.value() == LocalVerification::PasswordAndTotp;
    const idp::AuthenticationFactor factors = multiFactor
        ? idp::AuthenticationFactor::Knowledge | idp::AuthenticationFactor::Possession
        : idp::AuthenticationFactor::Knowledge;
    return idp::AuthenticationOutcome::create(
        m_id, std::move(pending->subject), std::move(claims),
        multiFactor ? idp::AssuranceLevel::Ial2 : idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{factors, false}, std::move(evidence), now);
}

}
