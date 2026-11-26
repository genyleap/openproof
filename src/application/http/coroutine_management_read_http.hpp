#pragma once
#include <functional>
#include <optional>
#include <string>
#include <boost/asio/detail/call_stack.hpp>
#include "../../gateway/asio_thread_context_extern.hpp"
#include <boost/asio/awaitable.hpp>

import openproof.application;
import openproof.client;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.session;
import openproof.resource;

namespace openproof::application::http {
class CoroutineManagementReadAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate=std::function<boost::asio::awaitable<foundation::Result<session::Session>>(foundation::SecretString)>;
    using Read=std::function<boost::asio::awaitable<foundation::Result<std::string>>(
        ManagementRead,identity::core::IdentityId,session::SessionId,std::optional<std::string>)>;
    using Mutate=std::function<boost::asio::awaitable<foundation::Result<Application>>(
        ApplicationMutationCommand,identity::core::IdentityId,session::SessionId)>;
    using MutateClient=std::function<boost::asio::awaitable<foundation::Result<client::Client>>(
        client::ManagementMutationCommand,identity::core::IdentityId,session::SessionId)>;
    using MutateJarKey=std::function<boost::asio::awaitable<foundation::Status>(
        client::ClientId,std::optional<std::string>,std::optional<std::string>,
        identity::core::IdentityId,session::SessionId)>;
    struct ClientContext final {
        foundation::SecretString key;
        MutateClient mutate;
        MutateJarKey mutateJarKey{};
    };
    using MutateResource=std::function<boost::asio::awaitable<foundation::Result<resource::ResourceServer>>(
        resource::ResourceMutationCommand,identity::core::IdentityId,session::SessionId)>;
    CoroutineManagementReadAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter,Authenticate authenticate,Read read,Mutate mutate={},
        std::optional<ClientContext> clients=std::nullopt,MutateResource resources={});
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest&) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(gateway::HttpRequest) override;
private:
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    Authenticate m_authenticate;
    Read m_read;
    Mutate m_mutate;
    std::optional<ClientContext> m_clients;
    MutateResource m_resources;
};
}
