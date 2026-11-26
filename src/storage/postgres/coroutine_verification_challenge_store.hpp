#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>

import openproof.account;
import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

namespace openproof::storage::postgres {

/** Tenant-bound native challenge persistence and pending signup provisioning.
 * No plaintext password or raw verification secret is supplied to SQL.
 */
class CoroutineVerificationChallengeStore final {
public:
    CoroutineVerificationChallengeStore(boost::asio::any_io_executor executor,
        foundation::SecretString connectionString,
        identity::core::OrganizationId tenant, std::size_t capacity,
        foundation::Duration acquireTimeout, foundation::Duration connectTimeout,
        foundation::Duration queryTimeout);
    ~CoroutineVerificationChallengeStore();
    CoroutineVerificationChallengeStore(const CoroutineVerificationChallengeStore&) = delete;
    CoroutineVerificationChallengeStore& operator=(const CoroutineVerificationChallengeStore&) = delete;

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    replaceAsync(account::VerificationChallenge challenge);

    /** Reserve the normalized external subject and persist its challenge in
     * one transaction. Provider must come from trusted configuration.
     */
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    reserveAndReplaceAsync(account::VerificationChallenge challenge,
                           identity::provider::ProviderId provider);

    // Public email requests never provision a subject. Lookup and write
    // independently revalidate eligibility; the latter runs under the owner lock.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::optional<identity::core::IdentityId>>>
    findPublicEmailOwnerAsync(identity::provider::ProviderId provider,
        account::VerificationPurpose purpose,std::string destination,foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    replacePublicEmailAsync(account::VerificationChallenge challenge,
        identity::provider::ProviderId provider);

    // Reap only untouched identities created by native signup, never an
    // existing canonical identity or an identity with other associations.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::size_t>>
    reapExpiredSignupsAsync(foundation::Instant now);

    struct PendingSignup final {
        account::VerificationDispatch dispatch;
        bool createdIdentity;
    };
    // The caller completes its bounded KDF before entering this method.
    // The verification key must outlive the awaited operation.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<PendingSignup>>
    provisionSignupAsync(identity::provider::ProviderId provider,std::string email,
        credentials::PasswordHash passwordHash,std::optional<std::string> displayName,
        const account::VerificationKey& key,foundation::Instant now,foundation::Duration lifetime);

    // Consume only a signup proof; promote the pending identity and local
    // link in the same transaction. Does not issue an authentication grant.
    using ActivatedSignup=std::pair<identity::core::ExternalIdentityRef,identity::core::IdentityId>;
    [[nodiscard]] boost::asio::awaitable<foundation::Result<ActivatedSignup>>
    activateSignupAsync(identity::provider::ProviderId provider,account::VerificationId id,
        account::VerificationDigest presented,foundation::Instant now,std::uint32_t maximumAttempts);

    // The new hash must be computed on the bounded KDF worker before
    // entering storage. Proof, password and existing session revocation
    // commit together. No authentication grant is issued.
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    resetPasswordAsync(identity::provider::ProviderId provider,account::VerificationId id,
        account::VerificationDigest presented,credentials::PasswordHash replacement,
        foundation::Instant now,std::uint32_t maximumAttempts);

    /** Compensation only for the exact issued ID, owner and purpose.
     * Idempotent if consumed or superseded; never deletes a newer challenge.
     * Allowed even after the identity becomes inactive in the same tenant.
     */
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    discardAsync(account::VerificationId id, identity::core::IdentityId owner,
                 account::VerificationPurpose purpose);
private:
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    replaceImpl(account::VerificationChallenge challenge,
                std::optional<identity::provider::ProviderId> provider,bool publicEmail=false);
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres
