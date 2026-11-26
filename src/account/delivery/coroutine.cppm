module;

#include <boost/asio/awaitable.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
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


/** Native contact issuance orchestration. Callers MUST have already verified
 * first-party session ownership, assurance, and rate limits. The storage
 * callback must atomically reserve the configured provider's subject and
 * replace the challenge under the tenant/lifecycle lock.
 * All borrowed dependencies must outlive in-flight operations.
 */
class CoroutineContactVerificationIssuer final {
public:
    using Reserve = std::function<boost::asio::awaitable<foundation::Status>(
        VerificationChallenge, identity::provider::ProviderId)>;
    using Discard = std::function<boost::asio::awaitable<foundation::Status>(
        VerificationId, identity::core::IdentityId, VerificationPurpose)>;

    CoroutineContactVerificationIssuer(VerificationKey key, AccountPolicy policy,
        identity::provider::ProviderId localProvider,
        identity::provider::ProviderId phoneProvider, const foundation::ClockSource& clock,
        CoroutineVerificationDelivery& delivery, Reserve reserve, Discard discard);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    issueAsync(identity::core::IdentityId owner, VerificationPurpose purpose,
               std::string destination);
    using FindPublicOwner=std::function<boost::asio::awaitable<
        foundation::Result<std::optional<identity::core::IdentityId>>>(
        identity::provider::ProviderId,VerificationPurpose,std::string,foundation::Instant)>;
    void configurePublicEmail(FindPublicOwner find,Reserve replace);
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    issuePublicEmailAsync(VerificationPurpose purpose,std::string destination);
private:
    VerificationKey m_key;
    AccountPolicy m_policy;
    identity::provider::ProviderId m_localProvider;
    identity::provider::ProviderId m_phoneProvider;
    const foundation::ClockSource* m_clock;
    CoroutineVerificationDelivery* m_delivery;
    Reserve m_reserve;
    Discard m_discard;
    FindPublicOwner m_findPublicOwner;
    Reserve m_replacePublic;
    [[nodiscard]] boost::asio::awaitable<foundation::Status> deliverPrepared(
        VerificationPreparation::Prepared prepared,identity::core::IdentityId owner,
        VerificationPurpose purpose,Reserve& persist,identity::provider::ProviderId provider);
};


}
