module;

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

module openproof.account.delivery:implementation;

import openproof.account;
import openproof.foundation;
import openproof.gateway;
import openproof.security;

namespace openproof::account::delivery {
namespace detail {

class WebhookConfig final {
public:
    [[nodiscard]] static foundation::Result<WebhookConfig> create(
        std::string host,
        std::uint16_t port,
        bool tls,
        std::string path,
        foundation::SecretString authorization)
    {
        if (host.empty() || port == 0U || path.empty() || !path.starts_with('/')
            || path.starts_with("//") || path.contains('?') || path.contains('#')
            || authorization.size() < 16U) {
            return foundation::fail(
                foundation::ErrorCode::InvalidArgument,
                "The verification webhook configuration is invalid.");
        }

        auto endpoint = gateway::Endpoint::create(
            gateway::EndpointId{"account-verification-delivery"},
            std::move(host), port, tls, 1U);
        if (!endpoint) {
            return foundation::fail(endpoint.error());
        }

        return WebhookConfig{
            std::move(endpoint).value(), std::move(path), std::move(authorization)};
    }

    [[nodiscard]] const std::string& path() const noexcept
    {
        return m_path;
    }

    [[nodiscard]] const foundation::SecretString& authorization() const noexcept
    {
        return m_authorization;
    }

    [[nodiscard]] const gateway::Endpoint& endpoint() const noexcept
    {
        return m_endpoint;
    }

private:
    WebhookConfig(
        gateway::Endpoint endpoint,
        std::string path,
        foundation::SecretString authorization)
        : m_endpoint(std::move(endpoint)),
          m_path(std::move(path)),
          m_authorization(std::move(authorization))
    {
    }

    gateway::Endpoint m_endpoint;
    std::string m_path;
    foundation::SecretString m_authorization;
};

class WebhookVerificationDelivery final : public VerificationDelivery {
public:
    WebhookVerificationDelivery(
        gateway::ProxyTransport& transport,
        WebhookConfig config,
        foundation::Duration timeout)
        : m_transport(&transport),
          m_config(std::move(config)),
          m_timeout(timeout)
    {
    }

    [[nodiscard]] foundation::Status deliver(
        const VerificationDispatch& dispatch) override
    {
        if (m_timeout <= foundation::Duration::zero()) {
            return foundation::fail(
                foundation::ErrorCode::FailedPrecondition,
                "The verification delivery timeout is invalid.");
        }

        auto correlation = security::randomTokenBase64Url(18U);
        if (!correlation) {
            return foundation::fail(correlation.error());
        }

        foundation::JsonObjectWriter payload;
        payload.add("verification_id", dispatch.id().value())
            .add("identity_id", dispatch.identity().value())
            .add("purpose", verificationPurposeName(dispatch.purpose()))
            .add("channel", verificationChannelName(dispatch.channel()))
            .add("destination", dispatch.destination())
            .add("secret", dispatch.secret().expose())
            .add("expires_at_ms", static_cast<std::int64_t>(
                dispatch.expiresAt().time_since_epoch().count()));

        std::vector<std::pair<std::string, std::string>> headers;
        headers.emplace_back("content-type", "application/json");
        headers.emplace_back("accept", "application/json");
        headers.emplace_back(
            "authorization",
            std::string{"Bearer "} + m_config.authorization().expose());

        auto request = gateway::HttpRequest::create(
            gateway::HttpMethod::Post,
            m_config.path(),
            std::move(headers),
            payload.build(),
            "127.0.0.1",
            foundation::CorrelationId{"delivery-" + correlation.value()});
        if (!request) {
            return foundation::fail(request.error());
        }

        auto response = m_transport->send(
            m_config.endpoint(), request.value(), m_timeout);
        if (!response) {
            return foundation::fail(response.error());
        }
        if (response->status() < 200 || response->status() >= 300) {
            return foundation::fail(
                foundation::ErrorCode::Unavailable,
                "Verification delivery is temporarily unavailable.",
                "The configured verification webhook returned a non-success status.");
        }

        return foundation::ok();
    }

private:
    gateway::ProxyTransport* m_transport;
    WebhookConfig m_config;
    foundation::Duration m_timeout{};
};

} // namespace detail

foundation::Result<std::unique_ptr<VerificationDelivery>>
createWebhookVerificationDelivery(
    gateway::ProxyTransport& transport,
    std::string host,
    std::uint16_t port,
    bool tls,
    std::string path,
    foundation::SecretString authorization,
    foundation::Duration timeout)
{
    if (timeout <= foundation::Duration::zero()) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The verification delivery timeout is invalid.");
    }

    auto config = detail::WebhookConfig::create(
        std::move(host), port, tls, std::move(path), std::move(authorization));
    if (!config) {
        return foundation::fail(config.error());
    }

    return std::unique_ptr<VerificationDelivery>{
        new detail::WebhookVerificationDelivery{
            transport, std::move(config).value(), timeout}};
}

} // namespace openproof::account::delivery
