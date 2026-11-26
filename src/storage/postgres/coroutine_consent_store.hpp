#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <vector>

import openproof.consent;
import openproof.foundation;
import openproof.identity.core;

namespace openproof::storage::postgres {

/** Bounded native OAuth consent management for a first-party session owner.
 * Callers authenticate the session and validate CSRF before mutations.
 * Storage independently verifies active identity and tenant membership of
 * the identity and application. No tokens or credentials are read.
 */
class CoroutineConsentStore final {
public:
    using Listing = std::vector<consent::ConsentGrant>;
    CoroutineConsentStore(boost::asio::any_io_executor executor,
        foundation::SecretString connectionString, identity::core::OrganizationId tenant,
        std::size_t capacity, foundation::Duration acquireTimeout,
        foundation::Duration connectTimeout, foundation::Duration queryTimeout);
    ~CoroutineConsentStore();
    CoroutineConsentStore(const CoroutineConsentStore&) = delete;
    CoroutineConsentStore& operator=(const CoroutineConsentStore&) = delete;

    [[nodiscard]] boost::asio::awaitable<foundation::Result<Listing>>
    listAsync(identity::core::IdentityId owner);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    revokeAsync(consent::ConsentId id, identity::core::IdentityId owner,
                foundation::Instant now);
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres
