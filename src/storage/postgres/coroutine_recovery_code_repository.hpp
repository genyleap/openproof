#pragma once

// PostgreSQL implementation of the storage-neutral coroutine recovery-code
// repository SPI. Never inherit or invoke the blocking legacy SPI.
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <vector>

#include "coroutine_recovery_codes.hpp"

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

namespace openproof::storage::postgres {

class CoroutinePostgresRecoveryCodeRepository final
    : public credentials::CoroutineRecoveryCodeRepository {
public:
    CoroutinePostgresRecoveryCodeRepository(
        boost::asio::any_io_executor executor,
        foundation::SecretString connectionString,
        std::size_t maxConnections,
        foundation::Duration acquireTimeout,
        foundation::Duration connectTimeout,
        foundation::Duration queryTimeout);
    CoroutinePostgresRecoveryCodeRepository(
        const CoroutinePostgresRecoveryCodeRepository&) = delete;
    CoroutinePostgresRecoveryCodeRepository& operator=(
        const CoroutinePostgresRecoveryCodeRepository&) = delete;
    ~CoroutinePostgresRecoveryCodeRepository() override;

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    replaceAsync(identity::core::IdentityId identity,
                 std::vector<credentials::RecoveryCodeDigest> digests) override;

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    consumeAsync(identity::core::IdentityId identity,
                 credentials::RecoveryCodeDigest digest) override;

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::size_t>>
    remainingAsync(identity::core::IdentityId identity) override;

    // Vendor-specific eligibility query; exposed only as an awaitable so the
    // HTTP layer can inject a provider-neutral Eligible callback.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<bool>>
    eligibleAsync(identity::core::IdentityId identity,
                  identity::provider::ProviderId configuredLocalProvider);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres
