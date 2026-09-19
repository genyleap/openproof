module;

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.authentication;

import openproof.security;

namespace openproof::authentication {

namespace {

constexpr std::size_t kIdentifierEntropyBytes = 32U;
constexpr std::size_t kContinuationEntropyBytes = 32U;
constexpr std::string_view kChallengeIdMetadata = "challenge_id";
constexpr std::string_view kRequestedAssuranceMetadata = "requested_assurance";
constexpr std::string_view kConnectionIdentityMetadata = "connection_identity";
constexpr std::string_view kHandoffProvider = "openproof-browser-handoff";
constexpr std::string_view kHandoffIdentityMetadata = "handoff_identity";
constexpr std::string_view kHandoffProviderMetadata = "handoff_provider";
constexpr std::string_view kHandoffReturnMetadata = "handoff_return";
constexpr foundation::Duration kBrowserHandoffLifetime = std::chrono::minutes{2};

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

[[nodiscard]] std::optional<std::string> presentationClaim(
    const provider::VerifiedClaims& claims, provider::ClaimName name,
    std::size_t maximum)
{
    const auto value = claims.get(name);
    if (!value || value->empty() || value->size() > maximum) return std::nullopt;
    return std::string{*value};
}

[[nodiscard]] identity::core::ExternalIdentityRef externalFromOutcome(
    const provider::AuthenticationOutcome& outcome)
{
    return identity::core::ExternalIdentityRef{
        outcome.provider(), outcome.subject(),
        presentationClaim(outcome.claims(), provider::ClaimName::DisplayName, 256U),
        presentationClaim(outcome.claims(), provider::ClaimName::PreferredUsername, 128U),
        presentationClaim(outcome.claims(), provider::ClaimName::PictureUrl, 2048U)};
}

}

foundation::Status ProviderTrustPolicy::trust(provider::ProviderId providerId,
                                              provider::AssuranceLevel maximum,
                                              bool allowSelfProvisioning)
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
    m_selfProvisioning.emplace(providerId, allowSelfProvisioning);
    m_maximums.emplace(std::move(providerId), maximum);
    return foundation::ok();
}

bool ProviderTrustPolicy::maySelfProvision(const provider::ProviderId& providerId) const noexcept
{
    const auto found = m_selfProvisioning.find(providerId);
    return found != m_selfProvisioning.end() && found->second;
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

BrowserConnectionHandoff::BrowserConnectionHandoff(
    foundation::SecretString ticket, foundation::Instant expiresAt)
    : m_ticket(std::move(ticket)), m_expiresAt(expiresAt)
{
}

const foundation::SecretString& BrowserConnectionHandoff::ticket() const noexcept
{
    return m_ticket;
}

foundation::Instant BrowserConnectionHandoff::expiresAt() const noexcept
{
    return m_expiresAt;
}

AuthenticationService::AuthenticationService(
    provider::ProviderRegistry& providers,
    provider::AuthenticationTransactionStore& transactions,
    identity::core::ExternalIdentityDirectory& identities,
    const foundation::ClockSource& clock, ProviderTrustPolicy trustPolicy,
    foundation::Duration maximumTransactionLifetime,
    identity::core::IdentityRepository* lifecycleRepository,
    identity::core::OrganizationId organization,
    identity::profile::IdentityProfileRepository* profileRepository)
    : m_providers(providers)
    , m_transactions(transactions)
    , m_identities(identities)
    , m_clock(clock)
    , m_trustPolicy(std::move(trustPolicy))
    , m_maximumTransactionLifetime(maximumTransactionLifetime)
    , m_lifecycleRepository(lifecycleRepository)
    , m_organization(std::move(organization))
    , m_profileRepository(profileRepository)
{
    foundation::requireInvariant(maximumTransactionLifetime > foundation::Duration::zero(), "authentication transaction lifetime must be positive");
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
    return beginInternal(request, binding, std::move(correlation), nullptr);
}

foundation::Result<AuthenticationStart> AuthenticationService::beginConnection(
    const provider::AuthenticationRequest& request,
    const provider::BindingDigest& binding,
    foundation::CorrelationId correlation,
    const identity::core::IdentityId& identity)
{
    if (identity.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A connection ceremony requires a canonical identity.");
    }
    auto active = requireActiveIdentity(identity);
    if (!active) return foundation::fail(active.error());
    return beginInternal(request, binding, std::move(correlation), &identity);
}

foundation::Result<AuthenticationStart> AuthenticationService::beginInternal(
    const provider::AuthenticationRequest& request,
    const provider::BindingDigest& binding,
    foundation::CorrelationId correlation,
    const identity::core::IdentityId* connectionTarget)
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
    if (connectionTarget != nullptr) {
        transaction->setMetadata(std::string{kConnectionIdentityMetadata},
                                 std::string{connectionTarget->value()});
    }

    const foundation::Status recorded = m_transactions.begin(std::move(transaction).value());
    if (!recorded.has_value()) {
        return foundation::fail(recorded.error());
    }

    return AuthenticationStart{std::move(transactionId), std::move(challenge).value(),
                               std::move(continuationToken)};
}

foundation::Result<AuthenticationService::CompletedExchange>
AuthenticationService::completeExchange(
    const provider::TransactionId& transactionId,
    const foundation::SecretString& continuationToken,
    const provider::BindingDigest& binding,
    const provider::AuthenticationResponse& response,
    bool requireConnection)
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
    // The provider may legitimately read the same real clock after the broker
    // consumed the transaction. Using the pre-call timestamp as an upper bound
    // makes every millisecond crossed inside provider verification look like a
    // future assertion. Bound against a fresh post-verification reading.
    const foundation::Instant completionFinishedAt = m_clock.now();
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

    if (outcome->verifiedAt() < transaction->createdAt()
        || outcome->verifiedAt() > completionFinishedAt) {
        return foundation::fail(authenticationFailure(
            "Provider returned a verification timestamp outside the transaction window."));
    }

    const auto connection = transaction->metadata().find(kConnectionIdentityMetadata);
    const bool isConnection = connection != transaction->metadata().end();
    if (isConnection != requireConnection || (isConnection && connection->second.empty())) {
        return foundation::fail(authenticationFailure(
            "Authentication completion refused: ceremony purpose does not match the endpoint."));
    }
    std::optional<identity::core::IdentityId> connectionTarget;
    if (isConnection) {
        connectionTarget.emplace(connection->second);
    }
    return CompletedExchange{
        std::move(outcome).value(), std::move(connectionTarget), completionFinishedAt};
}

foundation::Status AuthenticationService::requireActiveIdentity(
    const identity::core::IdentityId& identity) const
{
    if (m_lifecycleRepository == nullptr) return foundation::ok();
    if (m_organization.empty()) {
        return foundation::fail(authenticationFailure(
            "Authentication lifecycle gate is configured without an organization."));
    }
    auto canonical = m_lifecycleRepository->findById(m_organization, identity);
    if (!canonical) return foundation::fail(canonical.error());
    if (!canonical->has_value() || !canonical->value().canAuthenticate()) {
        return foundation::fail(authenticationFailure(
            "Authentication refused by canonical identity lifecycle state."));
    }
    return foundation::ok();
}

foundation::Status AuthenticationService::attachVerified(
    const identity::core::IdentityId& identity,
    const identity::core::ExternalIdentityRef& external,
    foundation::Instant verifiedAt)
{
    auto link = identity::core::IdentityLink::request(
        identity, external, verifiedAt, std::chrono::minutes{5});
    if (!link) return foundation::fail(link.error());
    auto required = link->requireVerification(verifiedAt);
    if (!required) return foundation::fail(required.error());
    auto verified = link->markVerified(verifiedAt);
    if (!verified) return foundation::fail(verified.error());
    auto completed = link->complete(verifiedAt);
    if (!completed) return foundation::fail(completed.error());
    return m_identities.attach(link.value());
}

foundation::Result<VerifiedAuthentication> AuthenticationService::complete(
    const provider::TransactionId& transactionId,
    const foundation::SecretString& continuationToken,
    const provider::BindingDigest& binding,
    const provider::AuthenticationResponse& response)
{
    auto exchange = completeExchange(
        transactionId, continuationToken, binding, response, false);
    if (!exchange) return foundation::fail(exchange.error());
    auto outcome = std::move(exchange->outcome);
    const auto completedAt = exchange->completedAt;
    const auto external = externalFromOutcome(outcome);
    foundation::Result<std::optional<identity::core::IdentityId>> owner =
        m_identities.ownerOf(external);
    if (!owner.has_value()) {
        return foundation::fail(authenticationFailure(
            "Authentication completion could not resolve the external identity directory."));
    }
    identity::core::IdentityId identity;
    if (!owner->has_value()) {
        if (!m_trustPolicy.maySelfProvision(outcome.provider())
            || m_lifecycleRepository == nullptr || m_organization.empty()) {
            return foundation::fail(authenticationFailure(
                "Authentication completion refused: the external identity has no explicit link to "
                "a canonical identity."));
        }
        auto generated = security::randomTokenBase64Url(24U);
        if (!generated) return foundation::fail(generated.error());
        identity = identity::core::IdentityId{"opi_" + std::move(generated).value()};
        auto canonical = identity::core::Identity::create(
            identity, identity::core::SubjectKind::Human, completedAt);
        if (!canonical) return foundation::fail(canonical.error());
        auto added = m_lifecycleRepository->add(m_organization, canonical.value());
        if (!added) return foundation::fail(added.error());
        if (m_profileRepository != nullptr) {
            auto profile = identity::profile::IdentityProfile::create(identity, completedAt);
            if (!profile) {
                static_cast<void>(m_lifecycleRepository->changeStatus(
                    m_organization, identity, identity::core::IdentityStatus::Deleted));
                return foundation::fail(profile.error());
            }
            auto applied = profile->applyVerifiedClaims(outcome.claims(), completedAt);
            if (!applied) {
                static_cast<void>(m_lifecycleRepository->changeStatus(
                    m_organization, identity, identity::core::IdentityStatus::Deleted));
                return foundation::fail(applied.error());
            }
            auto saved = m_profileRepository->save(profile.value());
            if (!saved) {
                static_cast<void>(m_lifecycleRepository->changeStatus(
                    m_organization, identity, identity::core::IdentityStatus::Deleted));
                return foundation::fail(saved.error());
            }
        }
        auto attached = attachVerified(identity, external, completedAt);
        if (!attached) {
            static_cast<void>(m_lifecycleRepository->changeStatus(
                m_organization, identity, identity::core::IdentityStatus::Deleted));
            return foundation::fail(attached.error());
        }
    } else {
        identity = std::move(owner).value().value();
    }
    auto active = requireActiveIdentity(identity);
    if (!active) return foundation::fail(active.error());
    auto presentationSaved = m_identities.updatePresentation(external);
    if (!presentationSaved) return foundation::fail(presentationSaved.error());
    if (m_profileRepository != nullptr) {
        auto stored = m_profileRepository->find(identity);
        if (!stored) return foundation::fail(stored.error());
        if (!stored->has_value()) {
            auto profile = identity::profile::IdentityProfile::create(identity, completedAt);
            if (!profile) return foundation::fail(profile.error());
            auto applied = profile->applyVerifiedClaims(outcome.claims(), completedAt);
            if (!applied) return foundation::fail(applied.error());
            auto saved = m_profileRepository->save(profile.value());
            if (!saved) return foundation::fail(saved.error());
        } else {
            auto profile = stored->value();
            auto refreshed = profile.refreshPresentationClaims(outcome.claims(), completedAt);
            if (!refreshed) return foundation::fail(refreshed.error());
            auto saved = m_profileRepository->save(profile);
            if (!saved) return foundation::fail(saved.error());
        }
    }
    return VerifiedAuthentication{std::move(outcome), std::move(identity)};
}

foundation::Result<identity::core::ExternalIdentityRef>
AuthenticationService::completeConnection(
    const provider::TransactionId& transactionId,
    const foundation::SecretString& continuationToken,
    const provider::BindingDigest& binding,
    const provider::AuthenticationResponse& response)
{
    auto exchange = completeExchange(
        transactionId, continuationToken, binding, response, true);
    if (!exchange) return foundation::fail(exchange.error());
    const auto& target = *exchange->connectionTarget;
    auto active = requireActiveIdentity(target);
    if (!active) return foundation::fail(active.error());
    const auto external = externalFromOutcome(exchange->outcome);
    const std::lock_guard guard{m_connectionMutex};
    auto owner = m_identities.ownerOf(external);
    if (!owner) return foundation::fail(owner.error());
    if (owner->has_value() && owner->value() != target) {
        return foundation::fail(
            foundation::ErrorCode::Conflict,
            "That external account is already connected to another OpenProof identity.");
    }
    if (!owner->has_value()) {
        auto attached = attachVerified(target, external, exchange->completedAt);
        if (!attached) return foundation::fail(attached.error());
    }
    auto presentationSaved = m_identities.updatePresentation(external);
    if (!presentationSaved) return foundation::fail(presentationSaved.error());
    if (m_profileRepository != nullptr) {
        auto stored = m_profileRepository->find(target);
        if (!stored) return foundation::fail(stored.error());
        if (stored->has_value()) {
            auto profile = stored->value();
            auto refreshed = profile.refreshPresentationClaims(
                exchange->outcome.claims(), exchange->completedAt);
            if (!refreshed) return foundation::fail(refreshed.error());
            auto saved = m_profileRepository->save(profile);
            if (!saved) return foundation::fail(saved.error());
        } else {
            auto profile = identity::profile::IdentityProfile::create(
                target, exchange->completedAt);
            if (!profile) return foundation::fail(profile.error());
            auto refreshed = profile->refreshPresentationClaims(
                exchange->outcome.claims(), exchange->completedAt);
            if (!refreshed) return foundation::fail(refreshed.error());
            auto saved = m_profileRepository->save(profile.value());
            if (!saved) return foundation::fail(saved.error());
        }
    }
    return external;
}

foundation::Status AuthenticationService::updateConnectionPresentation(
    const identity::core::ExternalIdentityRef& external,
    std::optional<std::string> displayName,
    std::optional<std::string> preferredUsername,
    std::optional<std::string> pictureUrl)
{
    const std::lock_guard guard{m_connectionMutex};
    auto owner = m_identities.ownerOf(external);
    if (!owner) return foundation::fail(owner.error());
    if (!owner->has_value()) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "That connected account was not found.");
    }
    return m_identities.updatePresentation(identity::core::ExternalIdentityRef{
        external.providerId(), external.subject(), std::move(displayName),
        std::move(preferredUsername), std::move(pictureUrl)});
}

foundation::Result<std::vector<identity::core::ExternalIdentityRef>>
AuthenticationService::connections(const identity::core::IdentityId& identity) const
{
    auto active = requireActiveIdentity(identity);
    if (!active) return foundation::fail(active.error());
    const std::lock_guard guard{m_connectionMutex};
    auto attached = m_identities.externalIdentitiesOf(identity);
    if (!attached) return foundation::fail(attached.error());
    std::vector<identity::core::ExternalIdentityRef> output;
    output.reserve(attached->size());
    for (const auto& external : attached.value()) {
        if (m_providers.find(external.providerId()) != nullptr) output.push_back(external);
    }
    return output;
}

foundation::Status AuthenticationService::disconnect(
    const identity::core::IdentityId& identity,
    const identity::core::ExternalIdentityRef& external)
{
    auto active = requireActiveIdentity(identity);
    if (!active) return active;
    if (m_providers.find(external.providerId()) == nullptr) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Only authentication connections can be disconnected here.");
    }
    const std::lock_guard guard{m_connectionMutex};
    auto detached = m_identities.detachIfAnotherAuthenticationMethod(
        external, identity, m_providers.ids());
    if (!detached) return detached;

    if (m_profileRepository != nullptr) {
        auto stored = m_profileRepository->find(identity);
        if (!stored) return foundation::fail(stored.error());
        if (stored->has_value()
            && stored->value().avatarSource() == external.providerId().value()) {
            auto profile = stored->value();
            auto reset = profile.setAvatarSource("auto", m_clock.now());
            if (!reset) return reset;
            auto saved = m_profileRepository->save(profile);
            if (!saved) return saved;
        }
    }
    return foundation::ok();
}

foundation::Result<BrowserConnectionHandoff>
AuthenticationService::issueBrowserConnectionHandoff(
    const identity::core::IdentityId& identity,
    const provider::ProviderId& providerId,
    std::string returnTarget,
    foundation::CorrelationId correlation)
{
    if (identity.empty() || providerId.empty() || returnTarget.empty()
        || returnTarget.size() > 2048U || correlation.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The browser connection handoff is invalid.");
    }
    auto active = requireActiveIdentity(identity);
    if (!active) return foundation::fail(active.error());
    auto generatedId = security::randomTokenBase64Url(kIdentifierEntropyBytes);
    auto generatedSecret = security::randomTokenBase64Url(kContinuationEntropyBytes);
    if (!generatedId) return foundation::fail(generatedId.error());
    if (!generatedSecret) return foundation::fail(generatedSecret.error());

    provider::TransactionId transactionId{generatedId.value()};
    foundation::SecretString secret{generatedSecret.value()};
    const foundation::Instant now = m_clock.now();
    const foundation::Duration lifetime =
        std::min(kBrowserHandoffLifetime, m_maximumTransactionLifetime);
    auto transaction = provider::AuthenticationTransaction::create(
        transactionId, provider::ProviderId{std::string{kHandoffProvider}},
        provider::InteractionModel::Redirect, secret.clone(), provider::BindingDigest{},
        std::move(correlation), now, lifetime);
    if (!transaction) return foundation::fail(transaction.error());
    transaction->setMetadata(std::string{kHandoffIdentityMetadata},
                             std::string{identity.value()});
    transaction->setMetadata(std::string{kHandoffProviderMetadata},
                             std::string{providerId.value()});
    transaction->setMetadata(std::string{kHandoffReturnMetadata},
                             std::move(returnTarget));
    auto recorded = m_transactions.begin(std::move(transaction).value());
    if (!recorded) return foundation::fail(recorded.error());

    return BrowserConnectionHandoff{
        foundation::SecretString{std::string{transactionId.value()} + "."
                                 + secret.expose()},
        now + lifetime};
}

foundation::Result<BrowserConnectionTarget>
AuthenticationService::consumeBrowserConnectionHandoff(
    const foundation::SecretString& ticket)
{
    const std::string_view presented = ticket.expose();
    const auto separator = presented.find('.');
    if (separator == std::string_view::npos || separator == 0U
        || separator + 1U >= presented.size() || presented.size() > 256U
        || presented.find('.', separator + 1U) != std::string_view::npos) {
        return foundation::fail(authenticationFailure(
            "Browser handoff redemption refused: malformed ticket."));
    }
    auto consumed = m_transactions.consume(
        provider::TransactionId{std::string{presented.substr(0U, separator)}},
        foundation::SecretString{std::string{presented.substr(separator + 1U)}},
        provider::BindingDigest{}, m_clock.now());
    if (!consumed) {
        return foundation::fail(authenticationFailure(
            "Browser handoff redemption refused: ticket is unknown, expired, invalid, or already consumed."));
    }
    if (consumed->provider().value() != kHandoffProvider) {
        return foundation::fail(authenticationFailure(
            "Browser handoff redemption refused: transaction purpose mismatch."));
    }
    const auto identity = consumed->metadata().find(kHandoffIdentityMetadata);
    const auto providerId = consumed->metadata().find(kHandoffProviderMetadata);
    const auto returnTarget = consumed->metadata().find(kHandoffReturnMetadata);
    if (identity == consumed->metadata().end() || identity->second.empty()
        || providerId == consumed->metadata().end() || providerId->second.empty()
        || returnTarget == consumed->metadata().end() || returnTarget->second.empty()) {
        return foundation::fail(authenticationFailure(
            "Browser handoff redemption refused: server-bound state is incomplete."));
    }
    auto active = requireActiveIdentity(identity::core::IdentityId{identity->second});
    if (!active) return foundation::fail(active.error());
    return BrowserConnectionTarget{
        identity::core::IdentityId{identity->second},
        provider::ProviderId{providerId->second}, returnTarget->second};
}

}
