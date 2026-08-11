module;

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

module openproof.authentication;

import openproof.security;

namespace openproof::authentication {

namespace {

constexpr std::size_t kIdentifierEntropyBytes = 32U;
constexpr std::size_t kContinuationEntropyBytes = 32U;
constexpr std::string_view kChallengeIdMetadata = "challenge_id";
constexpr std::string_view kRequestedAssuranceMetadata = "requested_assurance";

[[nodiscard]] foundation::Error authenticationFailure(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(
            foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

[[nodiscard]] std::optional<provider::AssuranceLevel>
parseAssurance(std::string_view value) noexcept
{
    constexpr provider::AssuranceLevel kLevels[] = {
        provider::AssuranceLevel::Ial0, provider::AssuranceLevel::Ial1,
        provider::AssuranceLevel::Ial2, provider::AssuranceLevel::Ial3,
        provider::AssuranceLevel::Ial4,
    };
    for (const provider::AssuranceLevel level : kLevels) {
        if (provider::assuranceLevelName(level) == value) {
            return level;
        }
    }
    return std::nullopt;
}

}

foundation::Status ProviderTrustPolicy::trust(provider::ProviderId providerId,
                                              provider::AssuranceLevel maximum)
{
    if (providerId.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A provider trust rule must name a provider.");
    }
    if (m_maximums.contains(providerId)) {
        return foundation::fail(
            foundation::ErrorCode::AlreadyExists,
            "A trust rule for that provider already exists.",
            "Duplicate provider assurance policy was rejected instead of silently replacing "
            "the operator-reviewed cap.");
    }
    m_maximums.emplace(std::move(providerId), maximum);
    return foundation::ok();
}

std::optional<provider::AssuranceLevel>
ProviderTrustPolicy::maximumFor(const provider::ProviderId& providerId) const noexcept
{
    const auto position = m_maximums.find(providerId);
    if (position == m_maximums.end()) {
        return std::nullopt;
    }
    return position->second;
}

AuthenticationStart::AuthenticationStart(provider::TransactionId transactionId,
                                         provider::AuthenticationChallenge challenge,
                                         foundation::SecretString continuationToken)
    : m_transactionId(std::move(transactionId))
    , m_challenge(std::move(challenge))
    , m_continuationToken(std::move(continuationToken))
{
}

const provider::TransactionId& AuthenticationStart::transactionId() const noexcept
{
    return m_transactionId;
}

const provider::AuthenticationChallenge& AuthenticationStart::challenge() const noexcept
{
    return m_challenge;
}

const foundation::SecretString& AuthenticationStart::continuationToken() const noexcept
{
    return m_continuationToken;
}

VerifiedAuthentication::VerifiedAuthentication(provider::AuthenticationOutcome outcome,
                                               identity::core::IdentityId identity)
    : m_outcome(std::move(outcome))
    , m_identity(std::move(identity))
{
}

const provider::AuthenticationOutcome& VerifiedAuthentication::outcome() const noexcept
{
    return m_outcome;
}

const identity::core::IdentityId& VerifiedAuthentication::identity() const noexcept
{
    return m_identity;
}

AuthenticationService::AuthenticationService(
    provider::ProviderRegistry& providers,
    provider::AuthenticationTransactionStore& transactions,
    identity::core::ExternalIdentityDirectory& identities,
    const foundation::ClockSource& clock, ProviderTrustPolicy trustPolicy,
    foundation::Duration maximumTransactionLifetime)
    : m_providers(providers)
    , m_transactions(transactions)
    , m_identities(identities)
    , m_clock(clock)
    , m_trustPolicy(std::move(trustPolicy))
    , m_maximumTransactionLifetime(maximumTransactionLifetime)
{
    contract_assert(maximumTransactionLifetime > foundation::Duration::zero());
}

std::optional<provider::AssuranceLevel> AuthenticationService::effectiveMaximum(
    provider::AuthenticationProvider& implementation,
    const provider::ProviderId& providerId) const noexcept
{
    const std::optional<provider::AssuranceLevel> configured =
        m_trustPolicy.maximumFor(providerId);
    if (!configured.has_value()) {
        return std::nullopt;
    }
    return std::min(*configured, implementation.maximumClaimableAssurance());
}

foundation::Result<AuthenticationStart> AuthenticationService::begin(
    const provider::AuthenticationRequest& request,
    const provider::BindingDigest& binding,
    foundation::CorrelationId correlation)
{
    provider::AuthenticationProvider* const implementation =
        m_providers.find(request.provider());
    if (implementation == nullptr) {
        return foundation::fail(authenticationFailure(
            "Authentication start refused: provider is not registered."));
    }

    const std::optional<provider::AssuranceLevel> maximum =
        effectiveMaximum(*implementation, request.provider());
    if (!maximum.has_value()) {
        return foundation::fail(authenticationFailure(
            "Authentication start refused: provider has no operator trust policy."));
    }
    if (request.requestedAssurance().has_value()
        && !provider::meetsAssurance(*maximum, *request.requestedAssurance())) {
        return foundation::fail(
            foundation::ErrorCode::AssuranceInsufficient,
            std::string{foundation::defaultErrorMessage(
                foundation::ErrorCode::AssuranceInsufficient)},
            "Requested assurance exceeds the lower of the provider-declared and "
            "operator-configured caps.");
    }

    foundation::Result<provider::AuthenticationChallenge> challenge = [&]() {
        try {
            foundation::Result<provider::AuthenticationChallenge> providerResult =
                implementation->beginAuthentication(request);
            if (!providerResult.has_value()) {
                return foundation::Result<provider::AuthenticationChallenge>{foundation::fail(
                    authenticationFailure(
                        "Authentication provider rejected the start operation."))};
            }
            return providerResult;
        } catch (...) {
            return foundation::Result<provider::AuthenticationChallenge>{foundation::fail(
                authenticationFailure(
                    "Authentication provider threw while starting an exchange."))};
        }
    }();
    if (!challenge.has_value()) {
        return foundation::fail(challenge.error());
    }

    const foundation::Instant now = m_clock.now();
    if (challenge->id().empty() || challenge->isExpiredAt(now)) {
        return foundation::fail(authenticationFailure(
            "Provider returned an empty or already-expired challenge."));
    }

    foundation::Result<std::string> generatedId =
        security::randomTokenBase64Url(kIdentifierEntropyBytes);
    if (!generatedId.has_value()) {
        return foundation::fail(generatedId.error());
    }
    foundation::Result<std::string> generatedContinuation =
        security::randomTokenBase64Url(kContinuationEntropyBytes);
    if (!generatedContinuation.has_value()) {
        return foundation::fail(generatedContinuation.error());
    }

    provider::TransactionId transactionId{std::move(generatedId).value()};
    foundation::SecretString continuationToken{std::move(generatedContinuation).value()};
    const foundation::Duration challengeLifetime = challenge->expiresAt() - now;
    const foundation::Duration lifetime =
        std::min(challengeLifetime, m_maximumTransactionLifetime);

    foundation::Result<provider::AuthenticationTransaction> transaction =
        provider::AuthenticationTransaction::create(
            transactionId, request.provider(), implementation->interactionModel(),
            continuationToken.clone(), binding, std::move(correlation), now, lifetime);
    if (!transaction.has_value()) {
        return foundation::fail(transaction.error());
    }
    transaction->setMetadata(std::string{kChallengeIdMetadata},
                             std::string{challenge->id().value()});
    if (request.requestedAssurance().has_value()) {
        transaction->setMetadata(
            std::string{kRequestedAssuranceMetadata},
            std::string{provider::assuranceLevelName(*request.requestedAssurance())});
    }

    const foundation::Status recorded = m_transactions.begin(std::move(transaction).value());
    if (!recorded.has_value()) {
        return foundation::fail(recorded.error());
    }

    return AuthenticationStart{std::move(transactionId), std::move(challenge).value(),
                               std::move(continuationToken)};
}

foundation::Result<VerifiedAuthentication> AuthenticationService::complete(
    const provider::TransactionId& transactionId,
    const foundation::SecretString& continuationToken,
    const provider::BindingDigest& binding,
    const provider::AuthenticationResponse& response)
{
    const foundation::Instant now = m_clock.now();
    foundation::Result<provider::AuthenticationTransaction> transaction =
        m_transactions.consume(transactionId, continuationToken, binding, now);
    if (!transaction.has_value()) {
        return foundation::fail(transaction.error());
    }

    const auto expectedChallenge = transaction->metadata().find(kChallengeIdMetadata);
    if (expectedChallenge == transaction->metadata().end()
        || expectedChallenge->second != response.challengeId().value()) {
        return foundation::fail(authenticationFailure(
            "Authentication completion refused: challenge identifier does not match the "
            "server-side transaction."));
    }

    provider::AuthenticationProvider* const implementation =
        m_providers.find(transaction->provider());
    if (implementation == nullptr) {
        return foundation::fail(authenticationFailure(
            "Authentication completion refused: transaction provider is no longer registered."));
    }

    const std::optional<provider::AssuranceLevel> maximum =
        effectiveMaximum(*implementation, transaction->provider());
    if (!maximum.has_value()) {
        return foundation::fail(authenticationFailure(
            "Authentication completion refused: provider trust policy is absent."));
    }

    foundation::Result<provider::AuthenticationOutcome> outcome = [&]() {
        try {
            foundation::Result<provider::AuthenticationOutcome> providerResult =
                implementation->completeAuthentication(response);
            if (!providerResult.has_value()) {
                return foundation::Result<provider::AuthenticationOutcome>{foundation::fail(
                    authenticationFailure(
                        "Authentication provider rejected the completion operation."))};
            }
            return providerResult;
        } catch (...) {
            return foundation::Result<provider::AuthenticationOutcome>{foundation::fail(
                authenticationFailure(
                    "Authentication provider threw while completing an exchange."))};
        }
    }();
    if (!outcome.has_value()) {
        return foundation::fail(outcome.error());
    }
    if (outcome->provider() != transaction->provider()) {
        return foundation::fail(authenticationFailure(
            "Provider returned an outcome under a different provider identifier."));
    }
    if (!provider::meetsAssurance(*maximum, outcome->claimedAssurance())) {
        return foundation::fail(authenticationFailure(
            "Provider outcome exceeded its effective assurance cap."));
    }

    const auto requested = transaction->metadata().find(kRequestedAssuranceMetadata);
    if (requested != transaction->metadata().end()) {
        const std::optional<provider::AssuranceLevel> required =
            parseAssurance(requested->second);
        if (!required.has_value()
            || !provider::meetsAssurance(outcome->claimedAssurance(), *required)) {
            return foundation::fail(
                foundation::ErrorCode::AssuranceInsufficient,
                std::string{foundation::defaultErrorMessage(
                    foundation::ErrorCode::AssuranceInsufficient)},
                "Provider completed the exchange below the assurance requested at start.");
        }
    }

    if (outcome->verifiedAt() < transaction->createdAt() || outcome->verifiedAt() > now) {
        return foundation::fail(authenticationFailure(
            "Provider returned a verification timestamp outside the transaction window."));
    }

    const identity::core::ExternalIdentityRef external{outcome->provider(), outcome->subject()};
    foundation::Result<std::optional<identity::core::IdentityId>> owner =
        m_identities.ownerOf(external);
    if (!owner.has_value()) {
        return foundation::fail(authenticationFailure(
            "Authentication completion could not resolve the external identity directory."));
    }
    if (!owner->has_value()) {
        return foundation::fail(authenticationFailure(
            "Authentication completion refused: the external identity has no explicit link to "
            "a canonical identity."));
    }

    identity::core::IdentityId identity = std::move(owner).value().value();
    return VerifiedAuthentication{std::move(outcome).value(), std::move(identity)};
}

}
