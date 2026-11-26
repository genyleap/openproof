module;

#include <boost/asio/awaitable.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

export module openproof.account.delivery:coroutine;

import openproof.account;
import openproof.foundation;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;

export namespace openproof::account::delivery {

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
