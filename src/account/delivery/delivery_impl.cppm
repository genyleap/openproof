module;

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

module openproof.account.delivery:implementation;

import :coroutine;

import openproof.account;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
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

[[nodiscard]] foundation::Result<gateway::HttpRequest>
prepareDeliveryRequest(const WebhookConfig& config, const VerificationDispatch& dispatch)
{
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
        std::string{"Bearer "} + config.authorization().expose());

    return gateway::HttpRequest::create(
        gateway::HttpMethod::Post,
        config.path(),
        std::move(headers),
        payload.build(),
        "127.0.0.1",
        foundation::CorrelationId{"delivery-" + correlation.value()});
}

[[nodiscard]] foundation::Status deliveryStatus(
    const foundation::Result<gateway::HttpResponse>& response)
{
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

struct ScrubDeliveryRequest final {
    gateway::HttpRequest& request;
    ~ScrubDeliveryRequest()
    {
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        request.wipeBody();
        request.wipeTargetQuery();
    }
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

        auto request = prepareDeliveryRequest(m_config, dispatch);
        if (!request) return foundation::fail(request.error());
        const ScrubDeliveryRequest scrub{request.value()};
        return deliveryStatus(m_transport->send(
            m_config.endpoint(), request.value(), m_timeout));
    }

private:
    gateway::ProxyTransport* m_transport;
    WebhookConfig m_config;
    foundation::Duration m_timeout{};
};

class CoroutineWebhookVerificationDelivery final : public CoroutineVerificationDelivery {
public:
    CoroutineWebhookVerificationDelivery(gateway::http::BeastProxyTransport& transport,
        WebhookConfig config, foundation::Duration timeout)
        : m_transport(&transport), m_config(std::move(config)), m_timeout(timeout) {}

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    deliverAsync(const VerificationDispatch& dispatch) override
    {
        // Not a coroutine: no borrowed VerificationDispatch survives into
        // a suspended frame, even if execution starts later.
        return sendPrepared(prepareDeliveryRequest(m_config, dispatch));
    }

private:
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    sendPrepared(foundation::Result<gateway::HttpRequest> prepared)
    {
        if (!prepared) co_return foundation::fail(prepared.error());
        const ScrubDeliveryRequest scrub{prepared.value()};
        try {
            // Transport takes the request by value and owns it across I/O.
            co_return deliveryStatus(co_await m_transport->sendAsync(
                m_config.endpoint(), std::move(prepared).value(), m_timeout));
        } catch (...) {
            co_return foundation::fail(foundation::ErrorCode::Unavailable,
                "Verification delivery is temporarily unavailable.");
        }
    }

    gateway::http::BeastProxyTransport* m_transport;
    WebhookConfig m_config;
    foundation::Duration m_timeout;
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

foundation::Result<std::unique_ptr<CoroutineVerificationDelivery>>
createCoroutineWebhookVerificationDelivery(
    gateway::http::BeastProxyTransport& transport,
    std::string host, std::uint16_t port, bool tls, std::string path,
    foundation::SecretString authorization, foundation::Duration timeout)
{
    if (timeout <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
            "The verification delivery timeout is invalid.");
    }
    auto config = detail::WebhookConfig::create(
        std::move(host), port, tls, std::move(path), std::move(authorization));
    if (!config) return foundation::fail(config.error());
    return std::unique_ptr<CoroutineVerificationDelivery>{
        new detail::CoroutineWebhookVerificationDelivery{
            transport, std::move(config).value(), timeout}};
}

CoroutineContactVerificationIssuer::CoroutineContactVerificationIssuer(
    VerificationKey key, AccountPolicy policy, identity::provider::ProviderId localProvider,
    identity::provider::ProviderId phoneProvider, const foundation::ClockSource& clock,
    CoroutineVerificationDelivery& delivery, Reserve reserve, Discard discard)
    : m_key(std::move(key)), m_policy(policy), m_localProvider(std::move(localProvider)),
      m_phoneProvider(std::move(phoneProvider)), m_clock(&clock), m_delivery(&delivery),
      m_reserve(std::move(reserve)), m_discard(std::move(discard))
{
}

boost::asio::awaitable<foundation::Status> CoroutineContactVerificationIssuer::issueAsync(
    identity::core::IdentityId owner, VerificationPurpose purpose, std::string destination)
{
    if (!m_reserve || !m_discard || m_localProvider.empty() || m_phoneProvider.empty())
        co_return foundation::fail(foundation::ErrorCode::FailedPrecondition);
    auto prepared = VerificationPreparation::prepareContact(
        m_key, m_policy, owner, purpose, std::move(destination), m_clock->now());
    if (!prepared) co_return foundation::fail(prepared.error());
    auto id = prepared->first.id();
    std::optional<VerificationDispatch> dispatch{std::move(prepared->second)};
    foundation::Status stored = foundation::fail(foundation::ErrorCode::Unavailable);
    try {
        stored = co_await m_reserve(std::move(prepared->first),
            purpose == VerificationPurpose::ChangeEmail ? m_localProvider : m_phoneProvider);
    } catch (...) {
        // The commit may have been ambiguous. Never send a secret in this case.
    }
    if (!stored) {
        dispatch.reset();
        co_return foundation::fail(stored.error());
    }
    foundation::Status delivered = foundation::fail(foundation::ErrorCode::Unavailable);
    try {
        auto pending = m_delivery->deliverAsync(*dispatch);
        // The delivery ABI owns its request before suspension.
        dispatch.reset();
        delivered = co_await std::move(pending);
    } catch (...) {
        dispatch.reset();
    }
    if (delivered) co_return foundation::ok();

    // Never implicitly retry a possibly delivered proof. Remove only the
    // specific challenge. The alias reservation remains bounded by its
    // expiry: legacy release has no generation token and cannot safely
    // distinguish a newer reservation for the same owner/subject.
    foundation::Status compensated = foundation::fail(foundation::ErrorCode::Unavailable);
    try {
        compensated = co_await m_discard(std::move(id), std::move(owner), purpose);
    } catch (...) {
    }
    if (!compensated)
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Verification delivery failed.",
            "Exact challenge compensation could not be confirmed.");
    co_return foundation::fail(delivered.error());
}

} // namespace openproof::account::delivery
