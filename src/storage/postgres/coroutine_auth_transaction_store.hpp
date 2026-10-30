#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

import openproof.foundation;
import openproof.identity.provider;

namespace openproof::storage::postgres {

// Opt-in native PostgreSQL transaction repository for trusted asynchronous
// authentication coordination. The legacy sync API fails closed; it MUST NOT
// be used by synchronous HTTP routes. Own this object until all pending
// coroutine frames complete and connect it only to a dedicated async stack.
class CoroutinePostgresAuthenticationTransactionStore final
    : public identity::provider::AuthenticationTransactionStore,
      public identity::provider::CoroutineAuthenticationTransactionStore {
public:
    CoroutinePostgresAuthenticationTransactionStore(
        boost::asio::any_io_executor executor,
        foundation::SecretString connectionString,
        std::size_t maxConnections,
        foundation::Duration acquireTimeout,
        foundation::Duration connectTimeout,
        foundation::Duration queryTimeout);
    CoroutinePostgresAuthenticationTransactionStore(
        const CoroutinePostgresAuthenticationTransactionStore&) = delete;
    CoroutinePostgresAuthenticationTransactionStore& operator=(
        const CoroutinePostgresAuthenticationTransactionStore&) = delete;
    ~CoroutinePostgresAuthenticationTransactionStore() override;

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    beginAsync(identity::provider::AuthenticationTransaction transaction) override;

    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<identity::provider::AuthenticationTransaction>>
    consumeAsync(identity::provider::TransactionId id,
                 foundation::SecretString nonce,
                 identity::provider::BindingDigest binding,
                 foundation::Instant now) override;

    // Never wait for libpq on the reactor through the old synchronous SPI.
    [[nodiscard]] foundation::Status
    begin(identity::provider::AuthenticationTransaction transaction) override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationTransaction>
    consume(const identity::provider::TransactionId& id,
            const foundation::SecretString& nonce,
            const identity::provider::BindingDigest& binding,
            foundation::Instant now) override;
    [[nodiscard]] foundation::Result<
        std::optional<identity::provider::AuthenticationTransaction>>
    find(const identity::provider::TransactionId& id) const override;
    [[nodiscard]] std::size_t purgeExpired(foundation::Instant now) override;
    [[nodiscard]] std::size_t size() const override;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres
