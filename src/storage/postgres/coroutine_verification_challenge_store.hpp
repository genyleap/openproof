#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <optional>

import openproof.account;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

namespace openproof::storage::postgres {

/** Tenant-bound native challenge persistence for existing active accounts.
 * Only contact verification purposes are supported; signup/reset and
 * their separate authorization/lifecycle requirements remain legacy.
 * No raw verification secret is stored or accepted by this adapter.
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
