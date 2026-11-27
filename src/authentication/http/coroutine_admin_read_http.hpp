#pragma once

#include <boost/asio/awaitable.hpp>
#include <functional>
#include <optional>
#include <variant>

import openproof.administration;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.session;

namespace openproof::administration::http {

// The SQL adapter must check owner membership and return the same actor in
// one tenant-scoped snapshot. No synchronous storage SPI is accepted here.
class CoroutineAdministrationReadAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate = std::function<boost::asio::awaitable<
        foundation::Result<session::Session>>(foundation::SecretString)>;
    using Read = std::function<boost::asio::awaitable<
        foundation::Result<MemberListing>>(identity::core::IdentityId)>;

    using Command = std::variant<LocalMemberEnrollment, MemberRoleReplacement,
        MemberLifecycleChange, LocalCredentialReset>;
    // The HTTP coroutine owns the validated command until mutation completes.
    // Persistence must authorize and commit before returning success.
    using Mutate = std::function<boost::asio::awaitable<foundation::Status>(
        identity::core::IdentityId, const Command&)>;
    struct MutationContext final {
        identity::core::OrganizationId organization;
        identity::provider::ProviderId provider;
        const foundation::ClockSource* clock;
        Mutate mutate;
    };
    CoroutineAdministrationReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter, Authenticate authenticate, Read read,
        std::optional<MutationContext> mutation = std::nullopt);
    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;

private:
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    list(gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    mutate(gateway::HttpRequest request, identity::core::IdentityId actor);
    [[nodiscard]] static gateway::HttpResponse fail(
        const foundation::Error& failure, const gateway::HttpRequest& request);
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    Authenticate m_authenticate;
    Read m_read;
    std::optional<MutationContext> m_mutation;
};

} // namespace openproof::administration::http
