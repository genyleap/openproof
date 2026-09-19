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
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}
