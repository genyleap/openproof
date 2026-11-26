#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

import openproof.account;
import openproof.account.delivery;
import openproof.credentials;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;
import openproof.provider.local;
import openproof.session;

namespace {
namespace asio = boost::asio;
namespace account = openproof::account;
namespace delivery = openproof::account::delivery;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace gh = openproof::gateway::http;
namespace core = openproof::identity::core;
namespace profile = openproof::identity::profile;
namespace idp = openproof::identity::provider;
namespace local = openproof::provider::local;
namespace sess = openproof::session;
using namespace std::chrono_literals;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'790'000'000'000}};

class WebhookReceiver final : public gw::HttpHandler {
public:
    void expect(std::string body)
    {
        const std::lock_guard lock{m_mutex};
        m_expected = fnd::SecretString{std::move(body)};
    }

    gw::HttpResponse handle(gw::HttpRequest request) override
    {
        const std::lock_guard lock{m_mutex};
        ++calls;
        const bool valid = request.method() == gw::HttpMethod::Post
            && request.path() == "/verification"
            && request.header("authorization") == "Bearer fixture-delivery-key"
            && request.header("content-type") == "application/json"
            && request.body() == m_expected.expose();
        request.wipeAuthorizationHeader();
        request.wipeBody();
        accepted.store(valid);
        return gw::HttpResponse{valid ? status.load() : 400, {}, ""};
    }
    std::atomic<int> calls{0};
    std::atomic<int> status{204};
    std::atomic<bool> accepted{false};
private:
    std::mutex m_mutex;
    fnd::SecretString m_expected{""};
};

class DeferredDispatch final : public account::VerificationDelivery {
public:
    DeferredDispatch(delivery::CoroutineVerificationDelivery& adapter, WebhookReceiver& receiver)
        : m_adapter(&adapter), m_receiver(&receiver) {}
    fnd::Status deliver(const account::VerificationDispatch& dispatch) override
    {
        EXPECT_EQ(dispatch.identity().value(), "owner");
        EXPECT_EQ(dispatch.purpose(), account::VerificationPurpose::ChangeEmail);
        EXPECT_EQ(dispatch.channel(), account::VerificationChannel::Email);
        EXPECT_EQ(dispatch.destination(), "new@example.com");
        EXPECT_FALSE(dispatch.secret().empty());
        fnd::JsonObjectWriter expected;
        expected.add("verification_id", dispatch.id().value())
            .add("identity_id", "owner")
            .add("purpose", account::verificationPurposeName(account::VerificationPurpose::ChangeEmail))
            .add("channel", account::verificationChannelName(account::VerificationChannel::Email))
            .add("destination", "new@example.com")
            .add("secret", dispatch.secret().expose())
            .add("expires_at_ms", static_cast<std::int64_t>(dispatch.expiresAt().time_since_epoch().count()));
        m_receiver->expect(expected.build());
        pending.emplace(m_adapter->deliverAsync(dispatch));
        // Test-only capture seam. Production native workflows must await
        // delivery before reporting success or applying compensation.
        return fnd::ok();
    }
    std::optional<asio::awaitable<fnd::Status>> pending;
private:
    delivery::CoroutineVerificationDelivery* m_adapter;
    WebhookReceiver* m_receiver;
};

TEST(NativeVerificationDeliveryTest, DispatchLifetimeAndWebhookStatusOverRealTcp)
{
    WebhookReceiver receiver;
    auto config = gh::ServerConfig::create("127.0.0.1", 0, 8192U, 8192U,
        2s, 2s, 16U, 2U);
    ASSERT_TRUE(config);
    gh::BeastHttpServer server{receiver, std::move(config).value()};
    ASSERT_TRUE(server.start());
    auto transport = gh::BeastProxyTransport::create(gh::ProxyConfig::create(8192U, 8192U).value());
    ASSERT_TRUE(transport);
    const auto create = [&](std::string path, fnd::Duration timeout) {
        return delivery::createCoroutineWebhookVerificationDelivery(*transport.value(),
            "127.0.0.1", server.boundPort(), false, std::move(path),
            fnd::SecretString{"fixture-delivery-key"}, timeout);
    };
    EXPECT_FALSE(create("/verification?secret=1", 2s));
    EXPECT_FALSE(create("/verification", 0ms));
    auto adapter = create("/verification", 2s);
    ASSERT_TRUE(adapter);
    DeferredDispatch deferred{*adapter.value(), receiver};
    fnd::ManualClockSource clock{kNow};
    core::InMemoryIdentityRepository identities;
    core::InMemoryExternalIdentityDirectory external;
    profile::InMemoryIdentityProfileRepository profiles;
    account::InMemoryAccountRepository repository;
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions{sessionRepository, clock,
        sess::SessionKey::create(fnd::SecretString{std::string(32U, 's')}).value(),
        sess::SessionPolicy::create(8h, 30min).value()};
    cred::InMemoryRecoveryCodeRepository recoveryRepository;
    auto recovery = cred::RecoveryCodeService::create(recoveryRepository,
        fnd::SecretString{std::string(32U, 'r')});
    ASSERT_TRUE(recovery);
    auto passwordPolicy = cred::PasswordPolicy::create(1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U);
    ASSERT_TRUE(passwordPolicy);
    auto hasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, passwordPolicy.value());
    ASSERT_TRUE(hasher);
    auto localAccounts = local::InMemoryLocalAccountDirectory::create(
        std::move(hasher).value(), cred::TotpPolicy::recommended());
    ASSERT_TRUE(localAccounts);
    const core::OrganizationId tenant{"tenant"};
    const core::IdentityId owner{"owner"};
    ASSERT_TRUE(identities.add(tenant, core::Identity::create(owner,
        core::SubjectKind::Human, kNow).value()));
    auto ownerProfile = profile::IdentityProfile::create(owner, kNow);
    ASSERT_TRUE(ownerProfile);
    ASSERT_TRUE(ownerProfile->setEmail("old@example.com", true, kNow));
    ASSERT_TRUE(profiles.save(ownerProfile.value()));
    account::AccountService service{tenant, idp::ProviderId{"local"}, idp::ProviderId{"phone"},
        identities, external, profiles, *localAccounts.value(), recovery.value(),
        repository, sessions, clock,
        account::VerificationKey::create(fnd::SecretString{std::string(32U, 'v')}).value(),
        account::AccountPolicy::create(24h, 10min, 30min, 8U).value(), deferred};

    // The dispatch is destroyed by AccountService before execution starts.
    for (const int status : {204, 503}) {
        receiver.status.store(status);
        ASSERT_TRUE(service.beginEmailChange(owner, "new@example.com"));
        ASSERT_TRUE(deferred.pending);
        asio::io_context io;
        std::optional<fnd::Status> result;
        auto run = [&]() -> asio::awaitable<void> {
            result.emplace(co_await std::move(*deferred.pending));
        };
        auto completed = asio::co_spawn(io, run(), asio::use_future);
        io.run();
        ASSERT_NO_THROW(completed.get());
        ASSERT_TRUE(result);
        EXPECT_EQ(result->has_value(), status == 204);
        if (status != 204 && !*result) {
            EXPECT_EQ(result->error().code(), fnd::ErrorCode::Unavailable);
        }
        EXPECT_TRUE(receiver.accepted.load());
        deferred.pending.reset();
    }
    EXPECT_EQ(receiver.calls.load(), 2);
    server.stop();
}
} // namespace
