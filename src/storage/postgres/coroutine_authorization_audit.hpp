#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>

import openproof.audit;
import openproof.foundation;
import openproof.identity.core;
import openproof.policy;
import openproof.session;

namespace openproof::storage::postgres {

/** Native counterpart to PostgresAuthorizationDecisionSink. It appends the
 * existing global HMAC chain and security outbox in a single transaction
 * under the same advisory lock as every legacy audit writer.
 * Own all request data across suspension; keep this sink and clock alive
 * until outstanding operations finish.
 */
class CoroutineAuthorizationDecisionSink final {
public:
    CoroutineAuthorizationDecisionSink(boost::asio::any_io_executor executor,
        foundation::SecretString connectionString, audit::AuditKey key,
        const foundation::ClockSource& clock, std::size_t maxConnections,
        foundation::Duration acquireTimeout, foundation::Duration connectTimeout,
        foundation::Duration queryTimeout);
    CoroutineAuthorizationDecisionSink(const CoroutineAuthorizationDecisionSink&) = delete;
    CoroutineAuthorizationDecisionSink& operator=(const CoroutineAuthorizationDecisionSink&) = delete;
    ~CoroutineAuthorizationDecisionSink();

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    recordAsync(session::AuthenticatedSession authenticated,
        identity::core::OrganizationId tenant, policy::Action action,
        policy::Resource resource, policy::AuthorizationDecision decision,
        foundation::CorrelationId correlation);
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres
