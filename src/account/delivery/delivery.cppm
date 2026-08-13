module;

#include <cstdint>
#include <memory>
#include <string>

export module openproof.account.delivery;

import openproof.account;
import openproof.foundation;
import openproof.gateway;

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

}
