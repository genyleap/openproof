module;

#include <memory>
#include <optional>

export module openproof.account:repository;

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import :model;

export namespace openproof::account {

/** @brief Persistence contract for verification challenges and unverified alias reservations. */
class AccountRepository {
public:
    AccountRepository(const AccountRepository&) = delete;
    AccountRepository& operator=(const AccountRepository&) = delete;
    virtual ~AccountRepository() = default;

    /** Replaces any active challenge for the same identity/purpose. */
    [[nodiscard]] virtual foundation::Status replace(VerificationChallenge challenge) = 0;

    /**
     * Atomically consumes a matching challenge. Mismatches increment the attempt
     * counter; expiry or max-attempt exhaustion makes the challenge unusable.
     */
    [[nodiscard]] virtual foundation::Result<VerificationChallenge> consume(
        const VerificationId& id, const VerificationDigest& presented,
        foundation::Instant now, std::uint32_t maximumAttempts,
        const identity::core::IdentityId* expectedIdentity = nullptr) = 0;

    /** Atomic purpose-bound consumption. Unsupported external adapters
     * fail closed; the compatibility consume API never substitutes for
     * a purpose check performed under the repository lock.
     */
    [[nodiscard]] virtual foundation::Result<VerificationChallenge> consumeForPurpose(
        const VerificationId&, const VerificationDigest&,
        foundation::Instant, std::uint32_t, VerificationPurpose,
        const identity::core::IdentityId* = nullptr)
    {
        return foundation::fail(foundation::ErrorCode::NotImplemented);
    }

    /** Reserves an unverified provider subject so two pending accounts cannot claim it. */
    [[nodiscard]] virtual foundation::Status reserveSubject(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& identity,
        foundation::Instant now, foundation::Instant expiresAt) = 0;

    [[nodiscard]] virtual foundation::Result<std::optional<identity::core::IdentityId>>
    reservedOwner(const identity::core::ExternalIdentityRef& external,
                  foundation::Instant now) const = 0;

    [[nodiscard]] virtual foundation::Status releaseSubject(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& expectedOwner) = 0;

    /** Generation-aware reservation access for a consumed verification proof.
     * Untagged adapters retain their legacy behavior.
     */
    [[nodiscard]] virtual foundation::Result<std::optional<identity::core::IdentityId>>
    reservedOwnerForChallenge(const identity::core::ExternalIdentityRef& external,
                              foundation::Instant now, const VerificationId&) const
    {
        return reservedOwner(external, now);
    }
    [[nodiscard]] virtual foundation::Status releaseSubjectForChallenge(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& expectedOwner, const VerificationId&)
    {
        return releaseSubject(external, expectedOwner);
    }

protected:
    AccountRepository() = default;
};

class InMemoryAccountRepository final : public AccountRepository {
public:
    InMemoryAccountRepository();
    ~InMemoryAccountRepository() override;

    [[nodiscard]] foundation::Status replace(VerificationChallenge challenge) override;
    [[nodiscard]] foundation::Result<VerificationChallenge> consume(
        const VerificationId& id, const VerificationDigest& presented,
        foundation::Instant now, std::uint32_t maximumAttempts,
        const identity::core::IdentityId* expectedIdentity = nullptr) override;
    [[nodiscard]] foundation::Result<VerificationChallenge> consumeForPurpose(
        const VerificationId& id, const VerificationDigest& presented,
        foundation::Instant now, std::uint32_t maximumAttempts,
        VerificationPurpose expectedPurpose,
        const identity::core::IdentityId* expectedIdentity = nullptr) override;
    [[nodiscard]] foundation::Status reserveSubject(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& identity,
        foundation::Instant now, foundation::Instant expiresAt) override;
    [[nodiscard]] foundation::Result<std::optional<identity::core::IdentityId>>
    reservedOwner(const identity::core::ExternalIdentityRef& external,
                  foundation::Instant now) const override;
    [[nodiscard]] foundation::Status releaseSubject(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& expectedOwner) override;

private:
    [[nodiscard]] foundation::Result<VerificationChallenge> consumeImpl(
        const VerificationId& id, const VerificationDigest& presented,
        foundation::Instant now, std::uint32_t maximumAttempts,
        const identity::core::IdentityId* expectedIdentity,
        std::optional<VerificationPurpose> expectedPurpose);
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}
