module;

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

module openproof.account;

import openproof.security;

namespace openproof::account {
namespace {

[[nodiscard]] foundation::Error invalidVerification(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

}

struct InMemoryAccountRepository::Impl final {
    struct ChallengeState final {
        VerificationChallenge challenge;
        std::uint32_t attempts{};
    };
    struct Reservation final {
        identity::core::IdentityId identity;
        foundation::Instant expiresAt{};
    };

    mutable std::mutex mutex;
    std::map<VerificationId, ChallengeState> challenges;
    std::map<identity::core::ExternalIdentityRef, Reservation> reservations;
};

InMemoryAccountRepository::InMemoryAccountRepository()
    : m_impl(std::make_unique<Impl>())
{
}

InMemoryAccountRepository::~InMemoryAccountRepository() = default;

foundation::Status InMemoryAccountRepository::replace(VerificationChallenge challenge)
{
    std::scoped_lock lock{m_impl->mutex};
    for (auto iterator = m_impl->challenges.begin(); iterator != m_impl->challenges.end();) {
        if (iterator->second.challenge.identity() == challenge.identity()
            && iterator->second.challenge.purpose() == challenge.purpose()) {
            iterator = m_impl->challenges.erase(iterator);
        } else {
            ++iterator;
        }
    }
    const VerificationId id = challenge.id();
    m_impl->challenges.emplace(id, Impl::ChallengeState{std::move(challenge), 0U});
    return foundation::ok();
}

foundation::Result<VerificationChallenge> InMemoryAccountRepository::consume(
    const VerificationId& id, const VerificationDigest& presented,
    foundation::Instant now, std::uint32_t maximumAttempts)
{
    if (maximumAttempts == 0U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Verification attempt policy is invalid.");
    }
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->challenges.find(id);
    if (found == m_impl->challenges.end()) {
        return foundation::fail(invalidVerification("Verification challenge is unknown or consumed."));
    }
    if (found->second.challenge.expiredAt(now) || found->second.attempts >= maximumAttempts) {
        m_impl->challenges.erase(found);
        return foundation::fail(invalidVerification("Verification challenge expired or exhausted."));
    }
    if (!security::constantTimeEquals(
            found->second.challenge.digest().bytes(), presented.bytes())) {
        ++found->second.attempts;
        if (found->second.attempts >= maximumAttempts) m_impl->challenges.erase(found);
        return foundation::fail(invalidVerification("Verification secret did not match."));
    }
    VerificationChallenge output = found->second.challenge;
    m_impl->challenges.erase(found);
    return output;
}

foundation::Status InMemoryAccountRepository::reserveSubject(
    const identity::core::ExternalIdentityRef& external,
    const identity::core::IdentityId& identity,
    foundation::Instant now, foundation::Instant expiresAt)
{
    if (external.providerId().empty() || external.subject().empty() || identity.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An account subject reservation is invalid.");
    }
    std::scoped_lock lock{m_impl->mutex};
    auto found = m_impl->reservations.find(external);
    if (found != m_impl->reservations.end() && now >= found->second.expiresAt) {
        m_impl->reservations.erase(found);
        found = m_impl->reservations.end();
    }
    if (found != m_impl->reservations.end()) {
        if (found->second.identity == identity) {
            found->second.expiresAt = expiresAt;
            return foundation::ok();
        }
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "That account identifier is already reserved.");
    }
    m_impl->reservations.emplace(external, Impl::Reservation{identity, expiresAt});
    return foundation::ok();
}

foundation::Result<std::optional<identity::core::IdentityId>>
InMemoryAccountRepository::reservedOwner(
    const identity::core::ExternalIdentityRef& external,
    foundation::Instant now) const
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->reservations.find(external);
    if (found == m_impl->reservations.end() || now >= found->second.expiresAt) {
        return std::optional<identity::core::IdentityId>{};
    }
    return std::optional<identity::core::IdentityId>{found->second.identity};
}

foundation::Status InMemoryAccountRepository::releaseSubject(
    const identity::core::ExternalIdentityRef& external,
    const identity::core::IdentityId& expectedOwner)
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->reservations.find(external);
    if (found == m_impl->reservations.end()) return foundation::ok();
    if (found->second.identity != expectedOwner) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                "That account reservation belongs to another identity.");
    }
    m_impl->reservations.erase(found);
    return foundation::ok();
}

}
