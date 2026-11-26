module;

#include <boost/asio/awaitable.hpp>

#include <cstdint>
#include <memory>
#include <string>

export module openproof.account.delivery;

import openproof.account;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;

export namespace openproof::account::delivery {

/**
 * @brief Creates an authenticated webhook-backed verification delivery adapter.
 *
 * The returned adapter owns its validated endpoint configuration and borrows the
 * supplied proxy transport. Verification secrets are emitted only in the
 * outbound request body and are never persisted by this adapter.
 *
 * @param transport Outbound HTTP transport whose lifetime must exceed the adapter.
 * @param host Verification webhook host.
 * @param port Verification webhook TCP port.
 * @param tls Whether TLS is required for the webhook connection.
 * @param path Absolute webhook request path without query or fragment components.
 * @param authorization Bearer credential used to authenticate webhook requests.
 * @param timeout Maximum duration of each outbound delivery request.
 * @return A delivery adapter, or a validation error for an invalid configuration.
 */
[[nodiscard]] foundation::Result<std::unique_ptr<VerificationDelivery>>
createWebhookVerificationDelivery(
    gateway::ProxyTransport& transport,
    std::string host,
    std::uint16_t port,
    bool tls,
    std::string path,
    foundation::SecretString authorization,
    foundation::Duration timeout);


/** Native delivery boundary for future coroutine account workflows.
 * The adapter synchronously consumes the borrowed dispatch into an owned
 * HTTP request before returning an awaitable. The dispatch may be destroyed
 * immediately. The adapter and transport must outlive pending operations.
 * A webhook failure is returned to the account workflow; never retry a
 * verification delivery implicitly.
 */
class CoroutineVerificationDelivery {
public:
    CoroutineVerificationDelivery(const CoroutineVerificationDelivery&) = delete;
    CoroutineVerificationDelivery& operator=(const CoroutineVerificationDelivery&) = delete;
    virtual ~CoroutineVerificationDelivery() = default;
    [[nodiscard]] virtual boost::asio::awaitable<foundation::Status>
    deliverAsync(const VerificationDispatch& dispatch) = 0;
protected:
    CoroutineVerificationDelivery() = default;
};

[[nodiscard]] foundation::Result<std::unique_ptr<CoroutineVerificationDelivery>>
createCoroutineWebhookVerificationDelivery(
    gateway::http::BeastProxyTransport& transport,
    std::string host, std::uint16_t port, bool tls, std::string path,
    foundation::SecretString authorization, foundation::Duration timeout);

}
