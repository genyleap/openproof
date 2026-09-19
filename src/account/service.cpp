module;

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.account;

import openproof.security;

namespace openproof::account {
namespace {

constexpr std::size_t kIdentityEntropyBytes = 24U;
constexpr std::size_t kVerificationIdEntropyBytes = 24U;
constexpr std::size_t kEmailSecretEntropyBytes = 24U;

[[nodiscard]] bool validEmail(std::string_view value) noexcept
{
    if (value.size() < 3U || value.size() > 320U || value.front() == '@'
        || value.back() == '@' || value.contains(' ')) return false;
    const auto at = value.rfind('@');
    return at != std::string_view::npos && at > 0U && at + 1U < value.size()
        && value.substr(at + 1U).contains('.');
}

[[nodiscard]] foundation::Result<std::string> normalizeEmail(std::string value)
{
    if (!validEmail(value)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The email address is invalid.");
    }
    std::ranges::transform(value, value.begin(), [](char symbol) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(symbol)));
    });
    return value;
}

[[nodiscard]] foundation::Result<std::string> normalizePhone(std::string value)
{
    if (value.size() < 8U || value.size() > 16U || value.front() != '+') {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The phone number must use E.164 form.");
    }
    if (!std::ranges::all_of(value.substr(1U), [](char symbol) {
            return symbol >= '0' && symbol <= '9';
        })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The phone number must use E.164 form.");
    }
    return value;
}

[[nodiscard]] foundation::Result<std::string> numericCode(std::size_t digits)
{
    std::string output;
    output.reserve(digits);
    while (output.size() < digits) {
        auto bytes = security::randomBytes(digits * 2U);
        if (!bytes.has_value()) return foundation::fail(bytes.error());
        for (std::byte raw : bytes.value()) {
            const auto value = std::to_integer<unsigned int>(raw);
            if (value >= 250U) continue;
            output.push_back(static_cast<char>('0' + (value % 10U)));
            if (output.size() == digits) break;
        }
    }
    return output;
}

[[nodiscard]] foundation::Error genericVerificationFailure(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

}

VerificationKey::VerificationKey(foundation::SecretString key)
    : m_key(std::move(key))
{
}

foundation::Result<VerificationKey> VerificationKey::create(foundation::SecretString key)
{
    if (key.size() < 32U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A verification key must contain at least 32 bytes.");
    }
    return VerificationKey{std::move(key)};
}

AccountPolicy::AccountPolicy(
    foundation::Duration emailVerificationLifetime,
    foundation::Duration phoneVerificationLifetime,
    foundation::Duration passwordResetLifetime,
    std::uint32_t maximumAttempts)
    : m_emailLifetime(emailVerificationLifetime),
      m_phoneLifetime(phoneVerificationLifetime),
      m_resetLifetime(passwordResetLifetime),
      m_maximumAttempts(maximumAttempts)
{
}

foundation::Result<AccountPolicy> AccountPolicy::create(
    foundation::Duration emailVerificationLifetime,
    foundation::Duration phoneVerificationLifetime,
    foundation::Duration passwordResetLifetime,
    std::uint32_t maximumAttempts)
{
    if (emailVerificationLifetime <= foundation::Duration::zero()
        || phoneVerificationLifetime <= foundation::Duration::zero()
        || passwordResetLifetime <= foundation::Duration::zero()
        || emailVerificationLifetime > std::chrono::hours{48}
        || phoneVerificationLifetime > std::chrono::minutes{30}
        || passwordResetLifetime > std::chrono::hours{2}
        || maximumAttempts == 0U || maximumAttempts > 20U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The account verification policy is invalid.");
    }
    return AccountPolicy{emailVerificationLifetime, phoneVerificationLifetime,
                         passwordResetLifetime, maximumAttempts};
}

foundation::Duration AccountPolicy::emailVerificationLifetime() const noexcept
{ return m_emailLifetime; }
foundation::Duration AccountPolicy::phoneVerificationLifetime() const noexcept
{ return m_phoneLifetime; }
foundation::Duration AccountPolicy::passwordResetLifetime() const noexcept
{ return m_resetLifetime; }
std::uint32_t AccountPolicy::maximumAttempts() const noexcept { return m_maximumAttempts; }

AccountService::AccountService(
    identity::core::OrganizationId organization,
    identity::provider::ProviderId localProvider,
    identity::provider::ProviderId phoneProvider,
    identity::core::IdentityRepository& identities,
    identity::core::ExternalIdentityDirectory& externalIdentities,
    identity::profile::IdentityProfileRepository& profiles,
    provider::local::LocalAccountDirectory& localAccounts,
    AccountRepository& repository,
    session::SessionService& sessions,
    const foundation::ClockSource& clock,
    VerificationKey key, AccountPolicy policy,
    VerificationDelivery& delivery)
    : m_organization(std::move(organization)), m_localProvider(std::move(localProvider)),
      m_phoneProvider(std::move(phoneProvider)), m_identities(&identities),
      m_externalIdentities(&externalIdentities), m_profiles(&profiles),
      m_localAccounts(&localAccounts), m_repository(&repository),
      m_sessions(&sessions), m_clock(&clock), m_key(std::move(key)),
      m_policy(policy), m_delivery(&delivery)
{
}

foundation::Result<VerificationDigest> AccountService::digest(
    const VerificationId& id, const foundation::SecretString& secret) const
{
    if (id.empty() || secret.empty() || secret.size() > 256U) {
        return foundation::fail(genericVerificationFailure("Verification input is malformed."));
    }
    std::string bound{id.value()};
    bound.push_back(':');
    bound.append(secret.expose());
    auto value = security::hmacSha256(m_key.m_key, bound);
    foundation::secureWipe(bound.data(), bound.size());
    if (!value.has_value()) return foundation::fail(value.error());
    return VerificationDigest{value.value()};
}

foundation::Result<VerificationDispatch> AccountService::issue(
    const identity::core::IdentityId& identity,
    VerificationPurpose purpose, VerificationChannel channel,
    std::string destination, foundation::Duration lifetime)
{
    auto idRaw = security::randomTokenBase64Url(kVerificationIdEntropyBytes);
    if (!idRaw.has_value()) return foundation::fail(idRaw.error());
    VerificationId id{"opv_" + std::move(idRaw).value()};

    foundation::Result<std::string> secretRaw = channel == VerificationChannel::Sms
        ? numericCode(8U) : security::randomTokenBase64Url(kEmailSecretEntropyBytes);
    if (!secretRaw.has_value()) return foundation::fail(secretRaw.error());
    foundation::SecretString secret{std::move(secretRaw).value()};
    auto fingerprint = digest(id, secret);
    if (!fingerprint.has_value()) return foundation::fail(fingerprint.error());
    const auto now = m_clock->now();
    auto challenge = VerificationChallenge::create(
        id, identity, purpose, channel, destination, fingerprint.value(), now, lifetime);
    if (!challenge.has_value()) return foundation::fail(challenge.error());
    const auto expiresAt = challenge->expiresAt();
    auto stored = m_repository->replace(std::move(challenge).value());
    if (!stored.has_value()) return foundation::fail(stored.error());
    return VerificationDispatch{id, identity, purpose, channel, std::move(destination),
                                std::move(secret), expiresAt};
}

foundation::Result<VerificationChallenge> AccountService::consume(
    const VerificationId& id, const foundation::SecretString& secret,
    VerificationPurpose purpose,
    const identity::core::IdentityId* expectedIdentity)
{
    auto fingerprint = digest(id, secret);
    if (!fingerprint.has_value()) return foundation::fail(fingerprint.error());
    auto challenge = m_repository->consume(
        id, fingerprint.value(), m_clock->now(), m_policy.maximumAttempts(),
        expectedIdentity);
    if (!challenge.has_value()) return foundation::fail(challenge.error());
    if (challenge->purpose() != purpose) {
        return foundation::fail(genericVerificationFailure(
            "Verification challenge purpose did not match the endpoint."));
    }
    return challenge;
}

foundation::Result<identity::profile::IdentityProfile>
AccountService::requireProfile(const identity::core::IdentityId& identity) const
{
    auto found = m_profiles->find(identity);
    if (!found.has_value()) return foundation::fail(found.error());
    if (!found->has_value()) return foundation::fail(foundation::ErrorCode::NotFound);
    return found->value();
}

foundation::Status AccountService::attachVerified(
    const identity::core::IdentityId& identity,
    const identity::core::ExternalIdentityRef& external)
{
    auto link = identity::core::IdentityLink::request(
        identity, external, m_clock->now(), std::chrono::minutes{5});
    if (!link.has_value()) return foundation::fail(link.error());
    auto required = link->requireVerification(m_clock->now());
    if (!required.has_value()) return required;
    auto verified = link->markVerified(m_clock->now());
    if (!verified.has_value()) return verified;
    auto completed = link->complete(m_clock->now());
    if (!completed.has_value()) return completed;
    return m_externalIdentities->attach(link.value());
}

foundation::Result<identity::core::IdentityId> AccountService::signup(
    std::string email, const foundation::SecretString& password,
    std::optional<std::string> displayName)
{
    auto normalized = normalizeEmail(std::move(email));
    if (!normalized.has_value()) return foundation::fail(normalized.error());
    const identity::core::ExternalIdentityRef external{
        m_localProvider, identity::provider::ExternalSubject{normalized.value()}};
    auto existing = m_externalIdentities->ownerOf(external);
    if (!existing.has_value()) return foundation::fail(existing.error());
    if (existing->has_value()) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "An account with that identifier already exists.");
    }
    auto reserved = m_repository->reservedOwner(external, m_clock->now());
    if (!reserved.has_value()) return foundation::fail(reserved.error());
    if (reserved->has_value()) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "An account with that identifier is already pending verification.");
    }

    auto idRaw = security::randomTokenBase64Url(kIdentityEntropyBytes);
    if (!idRaw.has_value()) return foundation::fail(idRaw.error());
    identity::core::IdentityId identity{"opi_" + std::move(idRaw).value()};
    auto canonical = identity::core::Identity::create(
        identity, identity::core::SubjectKind::Human, m_clock->now());
    if (!canonical.has_value()) return foundation::fail(canonical.error());
    auto deactivated = canonical->changeStatus(identity::core::IdentityStatus::Deactivated);
    if (!deactivated.has_value()) return foundation::fail(deactivated.error());
    auto added = m_identities->add(m_organization, canonical.value());
    if (!added.has_value()) return foundation::fail(added.error());

    auto reservation = m_repository->reserveSubject(
        external, identity, m_clock->now(),
        m_clock->now() + m_policy.emailVerificationLifetime());
    if (!reservation.has_value()) {
        static_cast<void>(m_identities->changeStatus(
            m_organization, identity, identity::core::IdentityStatus::Deleted));
        return foundation::fail(reservation.error());
    }

    auto enrolled = m_localAccounts->enrollPending(
        identity, identity::provider::ExternalSubject{normalized.value()}, password, std::nullopt);
    if (!enrolled.has_value()) {
        static_cast<void>(m_repository->releaseSubject(external, identity));
        static_cast<void>(m_identities->changeStatus(
            m_organization, identity, identity::core::IdentityStatus::Deleted));
        return foundation::fail(enrolled.error());
    }

    auto profile = identity::profile::IdentityProfile::create(identity, m_clock->now());
    if (!profile.has_value()) return foundation::fail(profile.error());
    auto emailSet = profile->setEmail(normalized.value(), false, m_clock->now());
    if (!emailSet.has_value()) return foundation::fail(emailSet.error());
    if (displayName.has_value()) {
        auto profileUpdated = profile->updateSelfService(
            std::move(displayName), std::nullopt, std::nullopt, std::nullopt, m_clock->now());
        if (!profileUpdated.has_value()) return foundation::fail(profileUpdated.error());
    }
    auto saved = m_profiles->save(profile.value());
    if (!saved.has_value()) {
        static_cast<void>(m_localAccounts->removePending(
            identity, identity::provider::ExternalSubject{normalized.value()}));
        static_cast<void>(m_repository->releaseSubject(external, identity));
        static_cast<void>(m_identities->changeStatus(
            m_organization, identity, identity::core::IdentityStatus::Deleted));
        return foundation::fail(saved.error());
    }

    auto dispatch = issue(identity, VerificationPurpose::SignupEmail,
                          VerificationChannel::Email, normalized.value(),
                          m_policy.emailVerificationLifetime());
    if (!dispatch.has_value()) return foundation::fail(dispatch.error());
    auto delivered = m_delivery->deliver(dispatch.value());
    if (!delivered.has_value()) return foundation::fail(delivered.error());
    return identity;
}

foundation::Status AccountService::resendSignupVerification(std::string email)
{
    auto normalized = normalizeEmail(std::move(email));
    if (!normalized.has_value()) return foundation::fail(normalized.error());
    const identity::core::ExternalIdentityRef external{
        m_localProvider, identity::provider::ExternalSubject{normalized.value()}};
    auto reserved = m_repository->reservedOwner(external, m_clock->now());
    if (!reserved.has_value()) return foundation::fail(reserved.error());
    if (!reserved->has_value()) return foundation::ok();
    auto dispatch = issue(reserved->value(), VerificationPurpose::SignupEmail,
                          VerificationChannel::Email, normalized.value(),
                          m_policy.emailVerificationLifetime());
    if (!dispatch.has_value()) return foundation::fail(dispatch.error());
    return m_delivery->deliver(dispatch.value());
}

foundation::Status AccountService::verifyEmail(
    const VerificationId& id, const foundation::SecretString& secret)
{
    auto challenge = consume(id, secret, VerificationPurpose::SignupEmail);
    if (!challenge.has_value()) return foundation::fail(challenge.error());
    const identity::core::ExternalIdentityRef external{
        m_localProvider, identity::provider::ExternalSubject{
            std::string{challenge->destination()}}};
    auto reserved = m_repository->reservedOwner(external, m_clock->now());
    if (!reserved.has_value() || !reserved->has_value()
        || reserved->value() != challenge->identity()) {
        return foundation::fail(genericVerificationFailure(
            "Signup subject reservation is absent or belongs to another identity."));
    }
    auto profile = requireProfile(challenge->identity());
    if (!profile.has_value()) return foundation::fail(profile.error());
    auto set = profile->setEmail(std::string{challenge->destination()}, true, m_clock->now());
    if (!set.has_value()) return set;
    auto saved = m_profiles->save(profile.value());
    if (!saved.has_value()) return saved;
    auto attached = attachVerified(challenge->identity(), external);
    if (!attached.has_value()) {
        static_cast<void>(profile->setEmail(std::string{challenge->destination()}, false, m_clock->now()));
        static_cast<void>(m_profiles->save(profile.value()));
        return attached;
    }
    auto activated = m_identities->changeStatus(
        m_organization, challenge->identity(), identity::core::IdentityStatus::Active);
    if (!activated.has_value()) {
        static_cast<void>(m_externalIdentities->detach(external, challenge->identity()));
        static_cast<void>(profile->setEmail(std::string{challenge->destination()}, false, m_clock->now()));
        static_cast<void>(m_profiles->save(profile.value()));
        return activated;
    }
    return m_repository->releaseSubject(external, challenge->identity());
}

foundation::Status AccountService::beginEmailChange(
    const identity::core::IdentityId& identity, std::string replacementEmail)
{
    auto normalized = normalizeEmail(std::move(replacementEmail));
    if (!normalized.has_value()) return foundation::fail(normalized.error());
    auto profile = requireProfile(identity);
    if (!profile.has_value()) return foundation::fail(profile.error());
    const identity::core::ExternalIdentityRef external{
        m_localProvider, identity::provider::ExternalSubject{normalized.value()}};
    auto owner = m_externalIdentities->ownerOf(external);
    if (!owner.has_value()) return foundation::fail(owner.error());
    if (owner->has_value() && owner->value() != identity) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "That email address is already in use.");
    }
    auto reserved = m_repository->reserveSubject(
        external, identity, m_clock->now(),
        m_clock->now() + m_policy.emailVerificationLifetime());
    if (!reserved.has_value()) return reserved;
    auto dispatch = issue(identity, VerificationPurpose::ChangeEmail,
                          VerificationChannel::Email, normalized.value(),
                          m_policy.emailVerificationLifetime());
    if (!dispatch.has_value()) {
        static_cast<void>(m_repository->releaseSubject(external, identity));
        return foundation::fail(dispatch.error());
    }
    auto delivered = m_delivery->deliver(dispatch.value());
    if (!delivered.has_value()) {
        static_cast<void>(m_repository->releaseSubject(external, identity));
        return delivered;
    }
    return foundation::ok();
}

foundation::Status AccountService::completeEmailChange(
    const identity::core::IdentityId& expectedIdentity,
    const VerificationId& id, const foundation::SecretString& secret,
    const foundation::SecretString* newPassword)
{
    if (newPassword != nullptr
        && (newPassword->expose().size() < 8U || newPassword->expose().size() > 1024U)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The password length is outside the accepted range.");
    }
    auto challenge = consume(
        id, secret, VerificationPurpose::ChangeEmail, &expectedIdentity);
    if (!challenge.has_value()) return foundation::fail(challenge.error());

    const std::string replacement{challenge->destination()};
    const identity::core::ExternalIdentityRef newExternal{
        m_localProvider, identity::provider::ExternalSubject{replacement}};
    const auto releaseReservation = [&]() {
        static_cast<void>(m_repository->releaseSubject(
            newExternal, challenge->identity()));
    };
    auto reservedOwner = m_repository->reservedOwner(newExternal, m_clock->now());
    if (!reservedOwner.has_value()) {
        return foundation::fail(reservedOwner.error());
    }
    if (!reservedOwner->has_value()
        || reservedOwner->value() != challenge->identity()) {
        return foundation::fail(genericVerificationFailure(
            "Email subject reservation is absent or belongs to another identity."));
    }

    auto profile = requireProfile(challenge->identity());
    if (!profile.has_value()) {
        releaseReservation();
        return foundation::fail(profile.error());
    }

    auto connections = m_externalIdentities->externalIdentitiesOf(challenge->identity());
    if (!connections.has_value()) {
        releaseReservation();
        return foundation::fail(connections.error());
    }
    const auto local = std::ranges::find_if(connections.value(), [&](const auto& external) {
        return external.providerId() == m_localProvider;
    });

    if (local == connections->end()) {
        if (newPassword != nullptr) {
            auto enrolled = m_localAccounts->enrollPending(
                challenge->identity(), identity::provider::ExternalSubject{replacement},
                *newPassword, std::nullopt);
            if (!enrolled.has_value()) {
                releaseReservation();
                return enrolled;
            }

            auto attached = attachVerified(challenge->identity(), newExternal);
            if (!attached.has_value()) {
                static_cast<void>(m_localAccounts->removePending(
                    challenge->identity(), identity::provider::ExternalSubject{replacement}));
                releaseReservation();
                return attached;
            }

            auto set = profile->setEmail(replacement, true, m_clock->now());
            if (!set.has_value()) {
                static_cast<void>(m_externalIdentities->detach(
                    newExternal, challenge->identity()));
                static_cast<void>(m_localAccounts->removePending(
                    challenge->identity(), identity::provider::ExternalSubject{replacement}));
                releaseReservation();
                return set;
            }
            auto saved = m_profiles->save(profile.value());
            if (!saved.has_value()) {
                static_cast<void>(m_externalIdentities->detach(
                    newExternal, challenge->identity()));
                static_cast<void>(m_localAccounts->removePending(
                    challenge->identity(), identity::provider::ExternalSubject{replacement}));
                releaseReservation();
                return saved;
            }
            return m_repository->releaseSubject(newExternal, challenge->identity());
        }

        auto set = profile->setEmail(replacement, true, m_clock->now());
        if (!set.has_value()) {
            releaseReservation();
            return set;
        }
        auto saved = m_profiles->save(profile.value());
        if (!saved.has_value()) {
            releaseReservation();
            return saved;
        }
        return m_repository->releaseSubject(newExternal, challenge->identity());
    }

    const std::string previous{local->subject().value()};
    if (previous == replacement) {
        auto set = profile->setEmail(replacement, true, m_clock->now());
        if (!set.has_value()) {
            releaseReservation();
            return set;
        }
        auto saved = m_profiles->save(profile.value());
        if (!saved.has_value()) {
            releaseReservation();
            return saved;
        }
        return m_repository->releaseSubject(newExternal, challenge->identity());
    }

    const identity::core::ExternalIdentityRef oldExternal{
        m_localProvider, identity::provider::ExternalSubject{previous}};
    auto attached = attachVerified(challenge->identity(), newExternal);
    if (!attached.has_value()) {
        releaseReservation();
        return attached;
    }
    auto rebound = m_localAccounts->rebindSubject(
        challenge->identity(), identity::provider::ExternalSubject{previous},
        identity::provider::ExternalSubject{replacement});
    if (!rebound.has_value()) {
        static_cast<void>(m_externalIdentities->detach(newExternal, challenge->identity()));
        releaseReservation();
        return rebound;
    }
    auto set = profile->setEmail(replacement, true, m_clock->now());
    if (!set.has_value()) {
        static_cast<void>(m_localAccounts->rebindSubject(
            challenge->identity(), identity::provider::ExternalSubject{replacement},
            identity::provider::ExternalSubject{previous}));
        static_cast<void>(m_externalIdentities->detach(newExternal, challenge->identity()));
        releaseReservation();
        return set;
    }
    auto saved = m_profiles->save(profile.value());
    if (!saved.has_value()) {
        static_cast<void>(m_localAccounts->rebindSubject(
            challenge->identity(), identity::provider::ExternalSubject{replacement},
            identity::provider::ExternalSubject{previous}));
        static_cast<void>(m_externalIdentities->detach(newExternal, challenge->identity()));
        releaseReservation();
        return saved;
    }
    auto detached = m_externalIdentities->detach(oldExternal, challenge->identity());
    if (!detached.has_value()) {
        releaseReservation();
        return detached;
    }
    return m_repository->releaseSubject(newExternal, challenge->identity());
}

foundation::Status AccountService::beginPhoneVerification(
    const identity::core::IdentityId& identity, std::string phoneNumber)
{
    auto normalized = normalizePhone(std::move(phoneNumber));
    if (!normalized.has_value()) return foundation::fail(normalized.error());
    const identity::core::ExternalIdentityRef external{
        m_phoneProvider, identity::provider::ExternalSubject{normalized.value()}};
    auto owner = m_externalIdentities->ownerOf(external);
    if (!owner.has_value()) return foundation::fail(owner.error());
    if (owner->has_value() && owner->value() != identity) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "That phone number is already in use.");
    }
    auto reserved = m_repository->reserveSubject(
        external, identity, m_clock->now(),
        m_clock->now() + m_policy.phoneVerificationLifetime());
    if (!reserved.has_value()) return reserved;
    auto dispatch = issue(identity, VerificationPurpose::VerifyPhone,
                          VerificationChannel::Sms, normalized.value(),
                          m_policy.phoneVerificationLifetime());
    if (!dispatch.has_value()) return foundation::fail(dispatch.error());
    return m_delivery->deliver(dispatch.value());
}

foundation::Status AccountService::completePhoneVerification(
    const identity::core::IdentityId& expectedIdentity,
    const VerificationId& id, const foundation::SecretString& secret)
{
    auto challenge = consume(id, secret, VerificationPurpose::VerifyPhone);
    if (!challenge.has_value()) return foundation::fail(challenge.error());
    if (challenge->identity() != expectedIdentity) {
        return foundation::fail(genericVerificationFailure(
            "Verification challenge does not belong to the authenticated identity."));
    }
    const identity::core::ExternalIdentityRef external{
        m_phoneProvider, identity::provider::ExternalSubject{
            std::string{challenge->destination()}}};
    auto attached = attachVerified(challenge->identity(), external);
    if (!attached.has_value()) return attached;
    auto profile = requireProfile(challenge->identity());
    if (!profile.has_value()) {
        static_cast<void>(m_externalIdentities->detach(external, challenge->identity()));
        return foundation::fail(profile.error());
    }
    auto set = profile->setPhoneNumber(
        std::string{challenge->destination()}, true, m_clock->now());
    if (!set.has_value()) return set;
    auto saved = m_profiles->save(profile.value());
    if (!saved.has_value()) {
        static_cast<void>(m_externalIdentities->detach(external, challenge->identity()));
        return saved;
    }
    return m_repository->releaseSubject(external, challenge->identity());
}

foundation::Status AccountService::beginPasswordReset(std::string email)
{
    auto normalized = normalizeEmail(std::move(email));
    if (!normalized.has_value()) return foundation::ok();
    const identity::core::ExternalIdentityRef external{
        m_localProvider, identity::provider::ExternalSubject{normalized.value()}};
    auto owner = m_externalIdentities->ownerOf(external);
    if (!owner.has_value() || !owner->has_value()) return foundation::ok();
    auto dispatch = issue(owner->value(), VerificationPurpose::PasswordReset,
                          VerificationChannel::Email, normalized.value(),
                          m_policy.passwordResetLifetime());
    if (!dispatch.has_value()) return foundation::fail(dispatch.error());
    return m_delivery->deliver(dispatch.value());
}

foundation::Status AccountService::completePasswordReset(
    const VerificationId& id, const foundation::SecretString& secret,
    const foundation::SecretString& newPassword)
{
    auto challenge = consume(id, secret, VerificationPurpose::PasswordReset);
    if (!challenge.has_value()) return foundation::fail(challenge.error());
    const identity::core::ExternalIdentityRef external{
        m_localProvider, identity::provider::ExternalSubject{
            std::string{challenge->destination()}}};
    auto owner = m_externalIdentities->ownerOf(external);
    if (!owner.has_value() || !owner->has_value()
        || owner->value() != challenge->identity()) {
        return foundation::fail(genericVerificationFailure(
            "Password reset subject ownership changed during the ceremony."));
    }
    auto changed = m_localAccounts->changePassword(
        external.subject(), newPassword);
    if (!changed.has_value()) return changed;
    auto revoked = m_sessions->revokeAll(challenge->identity());
    if (!revoked.has_value()) return foundation::fail(revoked.error());
    return foundation::ok();
}

foundation::Status AccountService::updateProfile(
    const identity::core::IdentityId& identity,
    std::optional<std::string> displayName,
    std::optional<std::string> preferredUsername,
    std::optional<std::string> locale,
    std::optional<std::string> pictureUrl,
    std::optional<std::string> avatarSource)
{
    auto profile = requireProfile(identity);
    if (!profile.has_value()) return foundation::fail(profile.error());
    const auto now = m_clock->now();
    auto updated = profile->updateSelfService(
        std::move(displayName), std::move(preferredUsername),
        std::move(locale), std::move(pictureUrl), now);
    if (!updated.has_value()) return updated;

    if (avatarSource.has_value()) {
        bool allowed = *avatarSource == "auto";
        if (*avatarSource == "profile") {
            allowed = profile->pictureUrl().has_value();
        } else if (!allowed) {
            auto connections = m_externalIdentities->externalIdentitiesOf(identity);
            if (!connections) return foundation::fail(connections.error());
            allowed = std::ranges::any_of(connections.value(), [&](const auto& external) {
                return external.providerId().value() == *avatarSource
                    && external.pictureUrl().has_value();
            });
        }
        if (!allowed) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The selected avatar source is not available.");
        }
        auto sourceUpdated = profile->setAvatarSource(std::move(*avatarSource), now);
        if (!sourceUpdated) return sourceUpdated;
    }
    return m_profiles->save(profile.value());
}
foundation::Result<identity::profile::IdentityProfile> AccountService::profile(
    const identity::core::IdentityId& identity) const
{
    return requireProfile(identity);
}


}
