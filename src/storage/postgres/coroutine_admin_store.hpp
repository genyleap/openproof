#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <variant>

import openproof.administration;
import openproof.audit;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;

namespace openproof::credentials { class BoundedPasswordExecutor; }

namespace openproof::storage::postgres {
// Owns the same tenant, credential encryption policy and audit key as the
// existing administration SPI. Commands are owned by the awaiting caller.
class CoroutineAdminStore final {
public:
    using Command = std::variant<administration::LocalMemberEnrollment,
        administration::MemberRoleReplacement, administration::MemberLifecycleChange,
        administration::LocalCredentialReset>;
    CoroutineAdminStore(boost::asio::any_io_executor executor, foundation::SecretString dsn,
        identity::core::OrganizationId organization, identity::provider::ProviderId provider,
        credentials::BoundedPasswordExecutor& passwords, security::AeadKey totpKey,
        std::uint32_t keyVersion, audit::AuditKey auditKey, std::size_t capacity,
        foundation::Duration acquireTimeout, foundation::Duration connectTimeout,
        foundation::Duration queryTimeout);
    ~CoroutineAdminStore();
    CoroutineAdminStore(const CoroutineAdminStore&) = delete;
    CoroutineAdminStore& operator=(const CoroutineAdminStore&) = delete;
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    mutateAsync(identity::core::IdentityId actor, const Command& command);
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};
}
