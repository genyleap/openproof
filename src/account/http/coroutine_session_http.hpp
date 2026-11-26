#pragma once

// Provider-neutral, opt-in coroutine HTTP entry for account session and
// read-only profile management. Keep the existing AccountHttpApi and all
// mutation routes intact.
// Native callbacks can be bound to any real asynchronous session repository:
// this contract never imports PostgreSQL, a vendor, or an operator product.
#include <boost/asio/awaitable.hpp>

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

import openproof.account;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.session;

namespace openproof::account::http {

class CoroutineAccountSessionAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate = std::function<boost::asio::awaitable<
        foundation::Result<session::Session>>(foundation::SecretString)>;
    using List = std::function<boost::asio::awaitable<
        foundation::Result<std::vector<session::Session>>>(
            identity::core::IdentityId)>;
    using RevokeOwned = std::function<boost::asio::awaitable<foundation::Status>(
        identity::core::IdentityId, session::SessionId)>;
    using ReadProfile = std::function<boost::asio::awaitable<
        foundation::Result<identity::profile::IdentityProfile>>(
            identity::core::IdentityId)>;
    // Explicit owner echo makes accidental cross-identity callback results
    // fail closed before any external account metadata is serialized.
    using ConnectionList = std::pair<identity::core::IdentityId,
        std::vector<identity::core::ExternalIdentityRef>>;
    using ReadConnections = std::function<boost::asio::awaitable<
        foundation::Result<ConnectionList>>(identity::core::IdentityId)>;

    using TotpStatus = std::pair<identity::core::IdentityId, std::optional<bool>>;
    using ReadTotpStatus = std::function<boost::asio::awaitable<
        foundation::Result<TotpStatus>>(identity::core::IdentityId)>;

    using PasswordUpgradeStatus = std::pair<identity::core::IdentityId, std::optional<bool>>;
    using ReadPasswordUpgradeStatus = std::function<boost::asio::awaitable<
        foundation::Result<PasswordUpgradeStatus>>(identity::core::IdentityId)>;

    using ConfirmPasswordUpgrade = std::function<boost::asio::awaitable<
        foundation::Result<std::pair<identity::core::IdentityId, bool>>>(
            identity::core::IdentityId, foundation::SecretString)>;

    struct ProfileUpdate final {
        std::optional<std::string> displayName, username, locale, picture, avatarSource;
    };
    using UpdateProfile = std::function<boost::asio::awaitable<
        foundation::Result<identity::profile::IdentityProfile>>(
            identity::core::IdentityId, ProfileUpdate)>;

    CoroutineAccountSessionAdapter(
        gateway::HttpHandler& legacyAccount,
        gateway::http::CoroutineHttpHandler& asyncFallback,
        gateway::TokenBucketRateLimiter& limiter,
        Authenticate authenticate, List list, RevokeOwned revokeOwned,
        ReadProfile readProfile = {}, ReadConnections readConnections = {},
        ReadTotpStatus readTotpStatus = {}, ReadPasswordUpgradeStatus readPasswordUpgradeStatus = {},
        ConfirmPasswordUpgrade confirmPasswordUpgrade = {}, UpdateProfile updateProfile = {});

    [[nodiscard]] bool nativeEnabled() const noexcept override { return false; }
    [[nodiscard]] bool nativeEnabledFor(
        const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(
        gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> handleAsync(
        gateway::HttpRequest request) override;

private:
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> sessionList(
        gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> sessionRevoke(
        gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> profileRead(
        gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> connectionsRead(
        gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> totpStatusRead(
        gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> passwordUpgradeStatusRead(
        gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> passwordUpgradeConfirm(
        gateway::HttpRequest request);
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse> profileUpdate(
        gateway::HttpRequest request);
    [[nodiscard]] static gateway::HttpResponse fail(
        const foundation::Error& failure, const gateway::HttpRequest& request);
    gateway::HttpHandler* m_legacyAccount;
    gateway::http::CoroutineHttpHandler* m_asyncFallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    Authenticate m_authenticate;
    List m_list;
    RevokeOwned m_revokeOwned;
    ReadProfile m_readProfile;
    ReadConnections m_readConnections;
    ReadTotpStatus m_readTotpStatus;
    ReadPasswordUpgradeStatus m_readPasswordUpgradeStatus;
    ConfirmPasswordUpgrade m_confirmPasswordUpgrade;
    UpdateProfile m_updateProfile;
};

/** Native contact challenge issuance, independent of session-list opt-ins.
 * The issuer owns durable reservation and delivery compensation.
 */
class CoroutineContactVerificationAdapter final : public gateway::http::CoroutineHttpHandler {
public:
    using Authenticate=CoroutineAccountSessionAdapter::Authenticate;
    using Issue=std::function<boost::asio::awaitable<foundation::Status>(
        identity::core::IdentityId, VerificationPurpose, std::string)>;

    CoroutineContactVerificationAdapter(gateway::http::CoroutineHttpHandler& fallback,
        gateway::TokenBucketRateLimiter& limiter, Authenticate authenticate, Issue issue);
    [[nodiscard]] bool nativeEnabledFor(const gateway::HttpRequest& request) const noexcept override;
    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;
    [[nodiscard]] boost::asio::awaitable<gateway::HttpResponse>
    handleAsync(gateway::HttpRequest request) override;
private:
    [[nodiscard]] static gateway::HttpResponse fail(const foundation::Error& failure,
        const gateway::HttpRequest& request);
    gateway::http::CoroutineHttpHandler* m_fallback;
    gateway::TokenBucketRateLimiter* m_limiter;
    Authenticate m_authenticate;
    Issue m_issue;
};

} // namespace openproof::account::http
