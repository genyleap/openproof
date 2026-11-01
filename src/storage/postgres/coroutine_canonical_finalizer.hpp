#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>

import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

namespace openproof::storage::postgres {

/**
 * Native PostgreSQL canonical identity finalizer.
 *
 * This opt-in adapter handles existing, explicitly linked identities only.
 * It denies self-provisioning rather than implicitly creating new identities.
 * A tenant is mandatory and every authorization is scoped to that tenant.
 * The caller must outlive all in-flight coroutines; none of these operations
 * uses a synchronous PostgreSQL repository on the Asio reactor.
 */
class CoroutinePostgresCanonicalFinalizer final
    : public authentication::CoroutineCanonicalIdentityFinalizer {
public:
    CoroutinePostgresCanonicalFinalizer(
        boost::asio::any_io_executor executor,
        foundation::SecretString connectionString,
        identity::core::OrganizationId organization,
        std::size_t maxConnections,
        foundation::Duration acquireTimeout,
        foundation::Duration connectTimeout,
        foundation::Duration queryTimeout);
    CoroutinePostgresCanonicalFinalizer(
        const CoroutinePostgresCanonicalFinalizer&) = delete;
    CoroutinePostgresCanonicalFinalizer& operator=(
        const CoroutinePostgresCanonicalFinalizer&) = delete;
    ~CoroutinePostgresCanonicalFinalizer() override;

    [[nodiscard]] bool nativeConnectionsEnabled() const noexcept override {
        return true;
    }

    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<identity::core::IdentityId>>
    finishLoginAsync(const identity::provider::AuthenticationOutcome& outcome,
                     foundation::Instant completedAt) override;

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    authorizeConnectionTargetAsync(identity::core::IdentityId target) override;

    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<identity::core::ExternalIdentityRef>>
    finishConnectionAsync(
        const identity::provider::AuthenticationOutcome& outcome,
        identity::core::IdentityId target,
        foundation::Instant completedAt) override;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres
