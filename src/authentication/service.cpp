module;

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
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
constexpr std::string_view kAuthenticationHandoffProvider =
    "openproof-browser-auth-handoff";
constexpr std::string_view kAuthenticationHandoffResultProvider =
    "openproof-browser-auth-result";
constexpr std::string_view kAuthenticationHandoffResultIdMetadata =
    "auth_handoff_result_id";
constexpr std::string_view kAuthenticationHandoffRedeemDigestMetadata =
    "auth_handoff_redeem_digest";
constexpr std::string_view kAuthenticationHandoffIdentityMetadata =
    "auth_handoff_identity";
constexpr std::string_view kAuthenticationHandoffSubjectMetadata =
    "auth_handoff_subject";
constexpr std::string_view kAuthenticationHandoffAssuranceMetadata =
    "auth_handoff_assurance";
constexpr std::string_view kAuthenticationHandoffFactorsMetadata =
    "auth_handoff_factors";
constexpr std::string_view kAuthenticationHandoffPhishingMetadata =
    "auth_handoff_phishing";
constexpr std::string_view kAuthenticationHandoffVerifiedAtMetadata =
    "auth_handoff_verified_at";
constexpr foundation::Duration kBrowserHandoffLifetime = std::chrono::minutes{2};

[[nodiscard]] std::string digestHex(const security::Sha256Digest& digest)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output;
    output.reserve(digest.size() * 2U);
    for (const std::byte value : digest) {
        const auto byte = static_cast<unsigned int>(std::to_integer<unsigned char>(value));
        output.push_back(kHex[(byte >> 4U) & 0x0fU]);
        output.push_back(kHex[byte & 0x0fU]);
    }
    return output;
}

[[nodiscard]] std::optional<security::Sha256Digest> parseDigestHex(
    std::string_view text) noexcept
{
    if (text.size() != security::Sha256Digest{}.size() * 2U) return std::nullopt;
    const auto nibble = [](char value) -> std::optional<unsigned int> {
        if (value >= '0' && value <= '9') return static_cast<unsigned int>(value - '0');
        if (value >= 'a' && value <= 'f') return static_cast<unsigned int>(value - 'a' + 10);
        if (value >= 'A' && value <= 'F') return static_cast<unsigned int>(value - 'A' + 10);
        return std::nullopt;
    };
    security::Sha256Digest digest{};
    for (std::size_t index = 0; index < digest.size(); ++index) {
        const auto high = nibble(text[index * 2U]);
        const auto low = nibble(text[index * 2U + 1U]);
        if (!high || !low) return std::nullopt;
        digest[index] = static_cast<std::byte>((*high << 4U) | *low);
    }
    return digest;
}

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

BrowserAuthenticationHandoff::BrowserAuthenticationHandoff(
    foundation::SecretString publisherTicket,
    foundation::SecretString redeemTicket,
    foundation::Instant expiresAt)
    : m_publisherTicket(std::move(publisherTicket)),
      m_redeemTicket(std::move(redeemTicket)),
      m_expiresAt(expiresAt)
{
}

const foundation::SecretString&
BrowserAuthenticationHandoff::publisherTicket() const noexcept
{
    return m_publisherTicket;
}

const foundation::SecretString&
BrowserAuthenticationHandoff::redeemTicket() const noexcept
{
    return m_redeemTicket;
}

foundation::Instant BrowserAuthenticationHandoff::expiresAt() const noexcept
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
        bool convergedByVerifiedEmail = false;
        if (m_profileRepository != nullptr
            && m_lifecycleRepository != nullptr
            && !m_organization.empty()
            && m_trustPolicy.maySelfProvision(outcome.provider())
            && outcome.claims().isTrue(provider::ClaimName::EmailVerified)) {
            const auto verifiedEmail = outcome.claims().get(provider::ClaimName::Email);
            if (verifiedEmail.has_value() && !verifiedEmail->empty()) {
                auto candidates = m_profileRepository->findVerifiedByEmail(*verifiedEmail);
                if (!candidates) return foundation::fail(candidates.error());

                std::vector<identity::core::IdentityId> activeCandidates;
                activeCandidates.reserve(candidates->size());
                std::size_t blockedCandidates = 0U;
                for (const auto& candidate : candidates.value()) {
                    auto canonical = m_lifecycleRepository->findById(m_organization, candidate);
                    if (!canonical) return foundation::fail(canonical.error());
                    if (!canonical->has_value()) continue;
                    if (canonical->value().canAuthenticate()) {
                        activeCandidates.push_back(candidate);
                        continue;
                    }
                    const auto status = canonical->value().status();
                    if (status != identity::core::IdentityStatus::Deleted
                        && status != identity::core::IdentityStatus::Merged) {
                        ++blockedCandidates;
                    }
                }

                if (activeCandidates.size() > 1U
                    || (blockedCandidates > 0U && !activeCandidates.empty())) {
                    return foundation::fail(
                        foundation::ErrorCode::Conflict,
                        "That verified email is already associated with multiple identities.",
                        "Federated sign-in refused to guess between canonical identities that "
                        "share the same verified email. An explicit merge is required.");
                }
                if (activeCandidates.empty() && blockedCandidates > 0U) {
                    return foundation::fail(authenticationFailure(
                        "Federated sign-in refused to self-provision because the verified email "
                        "belongs to an existing non-authenticating canonical identity."));
                }
                if (activeCandidates.size() == 1U) {
                    identity = activeCandidates.front();
                    auto attached = attachVerified(identity, external, completedAt);
                    if (!attached) return foundation::fail(attached.error());
                    convergedByVerifiedEmail = true;
                }
            }
        }

        if (!convergedByVerifiedEmail
            && (!m_trustPolicy.maySelfProvision(outcome.provider())
                || m_lifecycleRepository == nullptr || m_organization.empty())) {
            return foundation::fail(authenticationFailure(
                "Authentication completion refused: the external identity has no explicit link to "
                "a canonical identity."));
        }
        if (convergedByVerifiedEmail) {
            // Continue below so provider presentation claims refresh on the canonical identity.
        } else {
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

foundation::Result<VerifiedAuthentication>
AuthenticationService::acceptVerifiedEmail(
    const identity::core::ExternalIdentityRef& external)
{
    auto owner = m_identities.ownerOf(external);
    if (!owner) return foundation::fail(owner.error());
    if (!owner->has_value()) {
        return foundation::fail(
            foundation::ErrorCode::AuthenticationFailed,
            "The verified email is not linked to an active identity.");
    }
    auto active = requireActiveIdentity(owner->value());
    if (!active) return foundation::fail(active.error());

    provider::VerifiedClaims claims;
    claims.set(provider::ClaimName::Email, std::string{external.subject().value()});
    claims.set(provider::ClaimName::EmailVerified, "true");
    provider::ProviderEvidence evidence;
    evidence.add("method", "email_verification_link");
    auto outcome = provider::AuthenticationOutcome::create(
        external.providerId(), external.subject(), std::move(claims),
        provider::AssuranceLevel::Ial1,
        provider::AuthenticationStrength{provider::AuthenticationFactor::Possession, false},
        std::move(evidence), m_clock.now());
    if (!outcome) return foundation::fail(outcome.error());
    return VerifiedAuthentication{
        std::move(outcome).value(), std::move(owner).value().value()};
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

    identity::core::ExternalIdentityRef presented{
        external.providerId(), external.subject(), std::move(displayName),
        std::move(preferredUsername), std::move(pictureUrl)};
    auto connectionSaved = m_identities.updatePresentation(presented);
    if (!connectionSaved) return connectionSaved;

    if (m_profileRepository == nullptr) return foundation::ok();

    provider::VerifiedClaims presentationClaims;
    if (presented.displayName()) {
        presentationClaims.set(
            provider::ClaimName::DisplayName, std::string{*presented.displayName()});
    }
    if (presented.preferredUsername()) {
        presentationClaims.set(
            provider::ClaimName::PreferredUsername,
            std::string{*presented.preferredUsername()});
    }
    if (presented.pictureUrl()) {
        presentationClaims.set(
            provider::ClaimName::PictureUrl, std::string{*presented.pictureUrl()});
    }
    if (presentationClaims.empty()) return foundation::ok();

    const auto now = m_clock.now();
    auto stored = m_profileRepository->find(owner->value());
    if (!stored) return foundation::fail(stored.error());

    if (stored->has_value()) {
        auto profile = stored->value();
        auto refreshed = profile.refreshPresentationClaims(presentationClaims, now);
        if (!refreshed) return refreshed;
        return m_profileRepository->save(profile);
    }

    auto profile = identity::profile::IdentityProfile::create(owner->value(), now);
    if (!profile) return foundation::fail(profile.error());
    auto refreshed = profile->refreshPresentationClaims(presentationClaims, now);
    if (!refreshed) return refreshed;
    return m_profileRepository->save(profile.value());
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

foundation::Result<BrowserAuthenticationHandoff>
AuthenticationService::issueBrowserAuthenticationHandoff(
    const provider::ProviderId& providerId,
    foundation::CorrelationId correlation)
{
    if (providerId.empty() || correlation.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The browser authentication handoff is invalid.");
    }
    auto* implementation = m_providers.find(providerId);
    if (implementation == nullptr
        || implementation->interactionModel() != provider::InteractionModel::ChallengeResponse) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "That authentication provider is not available.");
    }

    auto publisherIdValue = security::randomTokenBase64Url(kIdentifierEntropyBytes);
    auto publisherSecretValue = security::randomTokenBase64Url(kContinuationEntropyBytes);
    auto resultIdValue = security::randomTokenBase64Url(kIdentifierEntropyBytes);
    auto redeemSecretValue = security::randomTokenBase64Url(kContinuationEntropyBytes);
    if (!publisherIdValue || !publisherSecretValue || !resultIdValue || !redeemSecretValue) {
        if (!publisherIdValue) return foundation::fail(publisherIdValue.error());
        if (!publisherSecretValue) return foundation::fail(publisherSecretValue.error());
        if (!resultIdValue) return foundation::fail(resultIdValue.error());
        return foundation::fail(redeemSecretValue.error());
    }

    provider::TransactionId publisherId{publisherIdValue.value()};
    provider::TransactionId resultId{resultIdValue.value()};
    foundation::SecretString publisherSecret{publisherSecretValue.value()};
    foundation::SecretString redeemSecret{redeemSecretValue.value()};
    auto redeemDigest = security::sha256(redeemSecret.expose());
    if (!redeemDigest) return foundation::fail(redeemDigest.error());

    const foundation::Instant now = m_clock.now();
    const foundation::Duration lifetime =
        std::min(kBrowserHandoffLifetime, m_maximumTransactionLifetime);
    auto transaction = provider::AuthenticationTransaction::create(
        publisherId, provider::ProviderId{std::string{kAuthenticationHandoffProvider}},
        provider::InteractionModel::Redirect, publisherSecret.clone(),
        provider::BindingDigest{}, std::move(correlation), now, lifetime);
    if (!transaction) return foundation::fail(transaction.error());
    transaction->setMetadata(std::string{kHandoffProviderMetadata},
                             std::string{providerId.value()});
    transaction->setMetadata(std::string{kAuthenticationHandoffResultIdMetadata},
                             std::string{resultId.value()});
    transaction->setMetadata(std::string{kAuthenticationHandoffRedeemDigestMetadata},
                             digestHex(redeemDigest.value()));
    auto recorded = m_transactions.begin(std::move(transaction).value());
    if (!recorded) return foundation::fail(recorded.error());

    return BrowserAuthenticationHandoff{
        foundation::SecretString{std::string{publisherId.value()} + "."
                                 + publisherSecret.expose()},
        foundation::SecretString{std::string{resultId.value()} + "."
                                 + redeemSecret.expose()},
        now + lifetime};
}

foundation::Status AuthenticationService::publishBrowserAuthenticationHandoff(
    const foundation::SecretString& publisherTicket,
    const VerifiedAuthentication& authentication)
{
    const std::string_view presented = publisherTicket.expose();
    const auto separator = presented.find('.');
    if (separator == std::string_view::npos || separator == 0U
        || separator + 1U >= presented.size() || presented.size() > 256U
        || presented.find('.', separator + 1U) != std::string_view::npos) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff publication refused: malformed ticket."));
    }
    auto consumed = m_transactions.consume(
        provider::TransactionId{std::string{presented.substr(0U, separator)}},
        foundation::SecretString{std::string{presented.substr(separator + 1U)}},
        provider::BindingDigest{}, m_clock.now());
    if (!consumed) return foundation::fail(consumed.error());
    if (consumed->provider().value() != kAuthenticationHandoffProvider) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff publication refused: purpose mismatch."));
    }

    const auto providerMetadata = consumed->metadata().find(kHandoffProviderMetadata);
    const auto resultIdMetadata =
        consumed->metadata().find(kAuthenticationHandoffResultIdMetadata);
    const auto digestMetadata =
        consumed->metadata().find(kAuthenticationHandoffRedeemDigestMetadata);
    if (providerMetadata == consumed->metadata().end()
        || resultIdMetadata == consumed->metadata().end()
        || digestMetadata == consumed->metadata().end()
        || providerMetadata->second.empty() || resultIdMetadata->second.empty()) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff publication refused: state is incomplete."));
    }
    if (authentication.outcome().provider().value() != providerMetadata->second) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff publication refused: provider mismatch."));
    }
    auto redeemDigest = parseDigestHex(digestMetadata->second);
    if (!redeemDigest) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff publication refused: invalid redeem digest."));
    }

    const foundation::Instant now = m_clock.now();
    if (consumed->expiresAt() <= now) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This authentication request has expired.");
    }
    provider::AttributeMap metadata;
    metadata.emplace(std::string{kAuthenticationHandoffIdentityMetadata},
                     std::string{authentication.identity().value()});
    metadata.emplace(std::string{kHandoffProviderMetadata},
                     std::string{authentication.outcome().provider().value()});
    metadata.emplace(std::string{kAuthenticationHandoffSubjectMetadata},
                     std::string{authentication.outcome().subject().value()});
    metadata.emplace(std::string{kAuthenticationHandoffAssuranceMetadata},
                     std::string{provider::assuranceLevelName(
                         authentication.outcome().claimedAssurance())});
    metadata.emplace(std::string{kAuthenticationHandoffFactorsMetadata},
                     std::to_string(static_cast<unsigned int>(
                         static_cast<std::uint8_t>(
                             authentication.outcome().strength().factors()))));
    metadata.emplace(std::string{kAuthenticationHandoffPhishingMetadata},
                     authentication.outcome().strength().isPhishingResistant()
                         ? "1" : "0");
    metadata.emplace(std::string{kAuthenticationHandoffVerifiedAtMetadata},
                     std::to_string(authentication.outcome().verifiedAt()
                                        .time_since_epoch().count()));

    auto result = provider::AuthenticationTransaction::restore(
        provider::TransactionId{resultIdMetadata->second},
        provider::ProviderId{std::string{kAuthenticationHandoffResultProvider}},
        provider::InteractionModel::Redirect, *redeemDigest,
        provider::BindingDigest{}, consumed->correlation(),
        provider::TransactionState::Pending, now, consumed->expiresAt(),
        std::move(metadata));
    if (!result) return foundation::fail(result.error());
    return m_transactions.begin(std::move(result).value());
}

foundation::Result<VerifiedAuthentication>
AuthenticationService::redeemBrowserAuthenticationHandoff(
    const foundation::SecretString& redeemTicket)
{
    const std::string_view presented = redeemTicket.expose();
    const auto separator = presented.find('.');
    if (separator == std::string_view::npos || separator == 0U
        || separator + 1U >= presented.size() || presented.size() > 256U
        || presented.find('.', separator + 1U) != std::string_view::npos) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff redemption refused: malformed ticket."));
    }
    auto consumed = m_transactions.consume(
        provider::TransactionId{std::string{presented.substr(0U, separator)}},
        foundation::SecretString{std::string{presented.substr(separator + 1U)}},
        provider::BindingDigest{}, m_clock.now());
    if (!consumed) return foundation::fail(consumed.error());
    if (consumed->provider().value() != kAuthenticationHandoffResultProvider) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff redemption refused: purpose mismatch."));
    }

    const auto identityMetadata =
        consumed->metadata().find(kAuthenticationHandoffIdentityMetadata);
    const auto providerMetadata = consumed->metadata().find(kHandoffProviderMetadata);
    const auto subjectMetadata =
        consumed->metadata().find(kAuthenticationHandoffSubjectMetadata);
    const auto assuranceMetadata =
        consumed->metadata().find(kAuthenticationHandoffAssuranceMetadata);
    const auto factorsMetadata =
        consumed->metadata().find(kAuthenticationHandoffFactorsMetadata);
    const auto phishingMetadata =
        consumed->metadata().find(kAuthenticationHandoffPhishingMetadata);
    const auto verifiedAtMetadata =
        consumed->metadata().find(kAuthenticationHandoffVerifiedAtMetadata);
    if (identityMetadata == consumed->metadata().end()
        || providerMetadata == consumed->metadata().end()
        || subjectMetadata == consumed->metadata().end()
        || assuranceMetadata == consumed->metadata().end()
        || factorsMetadata == consumed->metadata().end()
        || phishingMetadata == consumed->metadata().end()
        || verifiedAtMetadata == consumed->metadata().end()) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff redemption refused: state is incomplete."));
    }

    const auto assurance = parseAssurance(assuranceMetadata->second);
    unsigned int factorsValue{};
    const auto factorsParsed = std::from_chars(
        factorsMetadata->second.data(),
        factorsMetadata->second.data() + factorsMetadata->second.size(),
        factorsValue, 10);
    std::int64_t verifiedAtValue{};
    const auto verifiedAtParsed = std::from_chars(
        verifiedAtMetadata->second.data(),
        verifiedAtMetadata->second.data() + verifiedAtMetadata->second.size(),
        verifiedAtValue, 10);
    if (!assurance
        || factorsParsed.ec != std::errc{}
        || factorsParsed.ptr
            != factorsMetadata->second.data() + factorsMetadata->second.size()
        || factorsValue > 7U
        || (phishingMetadata->second != "0" && phishingMetadata->second != "1")
        || verifiedAtParsed.ec != std::errc{}
        || verifiedAtParsed.ptr
            != verifiedAtMetadata->second.data() + verifiedAtMetadata->second.size()
        || verifiedAtValue < 0) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff redemption refused: result is invalid."));
    }

    provider::ProviderId providerId{providerMetadata->second};
    auto* implementation = m_providers.find(providerId);
    const auto maximum = implementation == nullptr
        ? std::optional<provider::AssuranceLevel>{}
        : effectiveMaximum(*implementation, providerId);
    if (!maximum || !provider::meetsAssurance(*maximum, *assurance)) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff redemption refused: provider trust changed."));
    }

    identity::core::IdentityId identity{identityMetadata->second};
    auto active = requireActiveIdentity(identity);
    if (!active) return foundation::fail(active.error());
    identity::core::ExternalIdentityRef external{
        providerId, provider::ExternalSubject{subjectMetadata->second}};
    auto owner = m_identities.ownerOf(external);
    if (!owner || !owner->has_value() || owner->value() != identity) {
        return foundation::fail(authenticationFailure(
            "Browser authentication handoff redemption refused: identity link changed."));
    }

    provider::VerifiedClaims claims;
    provider::ProviderEvidence evidence;
    auto outcome = provider::AuthenticationOutcome::create(
        std::move(providerId),
        provider::ExternalSubject{subjectMetadata->second},
        std::move(claims), *assurance,
        provider::AuthenticationStrength{
            static_cast<provider::AuthenticationFactor>(
                static_cast<std::uint8_t>(factorsValue)),
            phishingMetadata->second == "1"},
        std::move(evidence),
        foundation::Instant{foundation::Duration{verifiedAtValue}});
    if (!outcome) return foundation::fail(outcome.error());
    return VerifiedAuthentication{std::move(outcome).value(), std::move(identity)};
}

}
