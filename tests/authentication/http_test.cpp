#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/json.hpp>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include "../../src/authentication/http/web3_presentation.hpp"

import openproof.authentication;
import openproof.authentication.federated.http;
import openproof.authentication.http;
import openproof.authentication.web3.http;
import openproof.credentials;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.provider.local;
import openproof.session;

namespace {

namespace auth = openproof::authentication;
namespace authHttp = openproof::authentication::http;
namespace cred = openproof::credentials;
namespace core = openproof::identity::core;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace idp = openproof::identity::provider;
namespace local = openproof::provider::local;
namespace sess = openproof::session;
namespace json = boost::json;

constexpr fnd::Instant kNow{std::chrono::seconds{1'770'000'000}};

class Fallback final : public gw::HttpHandler {
public:
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        return gw::HttpResponse{418, {}, "fallback"};
    }
};

class HandoffOnlyRedirectProvider final : public idp::AuthenticationProvider,
    public idp::CoroutineAuthenticationProvider {
public:
    idp::ProviderId id() const override {return idp::ProviderId{"handoff-test"};}
    idp::InteractionModel interactionModel() const noexcept override {return idp::InteractionModel::Redirect;}
    idp::AssuranceLevel maximumClaimableAssurance() const noexcept override {return idp::AssuranceLevel::Ial1;}
    fnd::Result<idp::AuthenticationChallenge> beginAuthentication(const idp::AuthenticationRequest&) override
    {++syncCalls;return fnd::fail(fnd::ErrorCode::Unavailable);}
    fnd::Result<idp::AuthenticationOutcome> completeAuthentication(const idp::AuthenticationResponse&) override
    {++syncCalls;return fnd::fail(fnd::ErrorCode::Unavailable);}
    boost::asio::awaitable<fnd::Result<idp::AuthenticationChallenge>>
    beginAuthenticationAsync(idp::AuthenticationRequest) override
    {co_return fnd::fail(fnd::ErrorCode::Unavailable);}
    boost::asio::awaitable<fnd::Result<idp::AuthenticationOutcome>>
    completeAuthenticationAsync(idp::AuthenticationResponse) override
    {co_return fnd::fail(fnd::ErrorCode::Unavailable);}
    int syncCalls{};
};
class HandoffDelegatedAccess final : public sess::DelegatedAccessAuthenticator {
public:
    fnd::Result<sess::DelegatedAccess> authenticateDelegated(const fnd::SecretString& token) override {
        if (token.expose()!="fixture-delegated") return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        auto actor=sess::AuthenticatedSession::fromDelegatedAccess(core::IdentityId{"identity-current"},
            idp::ProviderId{"local"},idp::AssuranceLevel::Ial1,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge,false},
            kNow,kNow,kNow+std::chrono::hours{1});
        if (!actor) return fnd::fail(actor.error());
        return sess::DelegatedAccess{std::move(actor).value(),"fixture-client",{"account"}};
    }
};

class RedirectProvider final : public idp::AuthenticationProvider {
public:
    explicit RedirectProvider(std::string providerId = "redirect")
        : m_providerId(std::move(providerId)) {}

    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{m_providerId};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return idp::InteractionModel::Redirect;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return idp::AssuranceLevel::Ial1;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        idp::AuthenticationChallenge challenge{
            idp::ChallengeId{"redirect-challenge"}, kNow + std::chrono::minutes{5}};
        challenge.setParameter("authorization_url", "https://provider.example/authorize");
        return challenge;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse& response) override
    {
        const auto code = response.parameters().find("code");
        const auto state = response.parameters().find("state");
        if (code == response.parameters().end() || code->second.expose() != "accepted"
            || state == response.parameters().end() || state->second.expose() != "provider-state") {
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        return idp::AuthenticationOutcome::create(
            idp::ProviderId{m_providerId}, idp::ExternalSubject{"redirect-subject"},
            idp::VerifiedClaims{}, idp::AssuranceLevel::Ial1,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, true},
            idp::ProviderEvidence{}, kNow);
    }

private:
    std::string m_providerId;
};

class OAuth1RelayProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{"oauth1-relay"};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return idp::InteractionModel::Redirect;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return idp::AssuranceLevel::Ial1;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        idp::AuthenticationChallenge challenge{
            idp::ChallengeId{"oauth1-relay-challenge"},
            kNow + std::chrono::minutes{5}};
        challenge.setParameter(
            "authorization_url", "https://provider.example/oauth1-authorize");
        return challenge;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse& response) override
    {
        const auto token = response.parameters().find("oauth_token");
        const auto verifier = response.parameters().find("oauth_verifier");
        if (token == response.parameters().end()
            || token->second.expose() != "request-token"
            || verifier == response.parameters().end()
            || verifier->second.expose() != "accepted-verifier") {
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        return idp::AuthenticationOutcome::create(
            idp::ProviderId{"oauth1-relay"},
            idp::ExternalSubject{"oauth1-subject"},
            idp::VerifiedClaims{}, idp::AssuranceLevel::Ial1,
            idp::AuthenticationStrength{
                idp::AuthenticationFactor::Possession, true},
            idp::ProviderEvidence{}, kNow);
    }
};

class AppleFormPostRelayProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{"apple-relay"};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return idp::InteractionModel::Redirect;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return idp::AssuranceLevel::Ial1;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        idp::AuthenticationChallenge challenge{
            idp::ChallengeId{"apple-relay-challenge"}, kNow + std::chrono::minutes{5}};
        challenge.setParameter("authorization_url", "https://provider.example/apple-authorize");
        return challenge;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse& response) override
    {
        const auto code = response.parameters().find("code");
        const auto state = response.parameters().find("state");
        const auto user = response.parameters().find("user");
        constexpr std::string_view expectedUser{
            R"({"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"ignored@example.test"})"};
        if (code == response.parameters().end() || code->second.expose() != "accepted"
            || state == response.parameters().end() || state->second.expose() != "provider-state"
            || user == response.parameters().end() || user->second.expose() != expectedUser) {
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        idp::VerifiedClaims claims;
        claims.set(idp::ClaimName::DisplayName, "Ada Lovelace");
        return idp::AuthenticationOutcome::create(
            idp::ProviderId{"apple-relay"}, idp::ExternalSubject{"apple-subject"},
            std::move(claims), idp::AssuranceLevel::Ial1,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, true},
            idp::ProviderEvidence{}, kNow);
    }
};

class SessionRedirectProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{"session-redirect"};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return idp::InteractionModel::Redirect;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return idp::AssuranceLevel::Ial1;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        idp::AuthenticationChallenge challenge{
            idp::ChallengeId{"session-redirect-challenge"},
            kNow + std::chrono::minutes{5}};
        challenge.setParameter(
            "authorization_url", "https://provider.example/session-authorize");
        return challenge;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse& response) override
    {
        const auto code = response.parameters().find("code");
        const auto state = response.parameters().find("state");
        if (code == response.parameters().end()
            || code->second.expose() != "accepted"
            || state == response.parameters().end()
            || state->second.expose() != "provider-state") {
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        return idp::AuthenticationOutcome::create(
            idp::ProviderId{"session-redirect"},
            idp::ExternalSubject{"session-subject"}, idp::VerifiedClaims{},
            idp::AssuranceLevel::Ial1,
            idp::AuthenticationStrength{
                idp::AuthenticationFactor::Possession, true},
            idp::ProviderEvidence{}, kNow);
    }
};

class ChallengeProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{"challenge"};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return idp::InteractionModel::ChallengeResponse;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return idp::AssuranceLevel::Ial1;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        return idp::AuthenticationChallenge{
            idp::ChallengeId{"challenge-id"}, kNow + std::chrono::minutes{5}};
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse&) override
    {
        return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
    }
};

class WalletChallengeProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override
    {
        return idp::ProviderId{"ethereum-wallet"};
    }

    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    {
        return idp::InteractionModel::ChallengeResponse;
    }

    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    {
        return idp::AssuranceLevel::Ial1;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    {
        idp::AuthenticationChallenge challenge{
            idp::ChallengeId{"wallet-challenge"}, kNow + std::chrono::minutes{5}};
        challenge.setParameter("message", "test");
        return challenge;
    }

    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse&) override
    {
        return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
    }
};

[[nodiscard]] gw::HttpRequest request(
    std::string path, std::string body = {}, std::string cookie = {})
{
    std::vector<std::pair<std::string, std::string>> headers;
    if (!body.empty()) headers.emplace_back("content-type", "application/json");
    if (!cookie.empty()) headers.emplace_back("cookie", std::move(cookie));
    return gw::HttpRequest::create(
        gw::HttpMethod::Post, std::move(path), std::move(headers), std::move(body),
        "127.0.0.1", fnd::CorrelationId{"request"}).value();
}

[[nodiscard]] gw::HttpRequest formPostRequest(
    std::string path, std::string body, std::string cookie = {})
{
    std::vector<std::pair<std::string, std::string>> headers{
        {"content-type", "application/x-www-form-urlencoded"}};
    if (!cookie.empty()) headers.emplace_back("cookie", std::move(cookie));
    return gw::HttpRequest::create(
        gw::HttpMethod::Post, std::move(path), std::move(headers), std::move(body),
        "127.0.0.1", fnd::CorrelationId{"request"}).value();
}

[[nodiscard]] gw::HttpRequest getRequest(std::string target, std::string cookie = {})
{
    std::vector<std::pair<std::string, std::string>> headers;
    if (!cookie.empty()) headers.emplace_back("cookie", std::move(cookie));
    return gw::HttpRequest::create(
        gw::HttpMethod::Get, std::move(target), std::move(headers), {},
        "127.0.0.1", fnd::CorrelationId{"request"}).value();
}

[[nodiscard]] std::vector<std::string> setCookies(const gw::HttpResponse& response)
{
    std::vector<std::string> output;
    if (const auto found = response.headers().find("set-cookie");
        found != response.headers().end()) output.push_back(found->second);
    for (const auto& [name, value] : response.repeatedHeaders()) {
        if (name == "set-cookie") output.push_back(value);
    }
    return output;
}

[[nodiscard]] std::string cookieValue(const gw::HttpResponse& response,
                                      std::string_view name)
{
    const std::string prefix = std::string{name} + "=";
    for (const auto& header : setCookies(response)) {
        if (header.starts_with(prefix)) {
            return header.substr(prefix.size(), header.find(';') - prefix.size());
        }
    }
    return {};
}

[[nodiscard]] std::string preauthCookieHeader(
    const gw::HttpResponse& response, std::string subjectOverride = {})
{
    const std::string subject = subjectOverride.empty()
        ? cookieValue(response, "__Host-openproof-preauth-subject")
        : std::move(subjectOverride);
    return "__Host-openproof-preauth="
        + cookieValue(response, "__Host-openproof-preauth")
        + "; __Host-openproof-preauth-binding="
        + cookieValue(response, "__Host-openproof-preauth-binding")
        + "; __Host-openproof-preauth-subject=" + subject;
}

[[nodiscard]] std::string setCookieHeader(const gw::HttpResponse& response,
                                          std::string_view name)
{
    const std::string prefix = std::string{name} + "=";
    for (const auto& header : setCookies(response)) {
        if (header.starts_with(prefix)) return header;
    }
    return {};
}

void expectHostCookie(const gw::HttpResponse& response, std::string_view name)
{
    const auto header = setCookieHeader(response, name);
    ASSERT_FALSE(header.empty());
    EXPECT_TRUE(name.starts_with("__Host-"));
    EXPECT_NE(header.find("; Path=/"), std::string::npos);
    EXPECT_NE(header.find("; Secure"), std::string::npos);
    EXPECT_NE(header.find("; HttpOnly"), std::string::npos);
    EXPECT_EQ(header.find("; Domain="), std::string::npos);
}

// Test-only in-memory adapter. Never wrap a blocking provider or repository
// in this fashion in the executable. Production uses the native PostgreSQL
// credential verifier and atomic session service.
class MemoryLocalProvider final : public idp::AuthenticationProvider,
    public idp::CoroutineAuthenticationProvider {
public:
    MemoryLocalProvider(local::LocalAccountDirectory& accounts, const fnd::ClockSource& clock,
        core::ExternalIdentityDirectory& identities, cred::RecoveryCodeService& recovery)
        : m_provider(idp::ProviderId{"local"}, accounts, clock, std::chrono::minutes{5},
            &identities,&recovery) {}
    idp::ProviderId id() const override { return m_provider.id(); }
    idp::InteractionModel interactionModel() const noexcept override { return m_provider.interactionModel(); }
    idp::AssuranceLevel maximumClaimableAssurance() const noexcept override { return m_provider.maximumClaimableAssurance(); }
    fnd::Result<idp::AuthenticationChallenge> beginAuthentication(const idp::AuthenticationRequest&) override
    { return fnd::fail(fnd::ErrorCode::Unavailable); }
    fnd::Result<idp::AuthenticationOutcome> completeAuthentication(const idp::AuthenticationResponse&) override
    { return fnd::fail(fnd::ErrorCode::Unavailable); }
    boost::asio::awaitable<fnd::Result<idp::AuthenticationChallenge>>
    beginAuthenticationAsync(idp::AuthenticationRequest request) override
    { co_return m_provider.beginAuthentication(request); }
    boost::asio::awaitable<fnd::Result<idp::AuthenticationOutcome>>
    completeAuthenticationAsync(idp::AuthenticationResponse proof) override
    { co_return m_provider.completeAuthentication(proof); }
private:
    local::LocalAuthenticationProvider m_provider;
};

class MemoryLoginFinalizer final : public auth::CoroutineCanonicalIdentityFinalizer {
public:
    explicit MemoryLoginFinalizer(core::InMemoryExternalIdentityDirectory& directory) : m_directory(directory) {}
    boost::asio::awaitable<fnd::Result<core::IdentityId>>
    finishLoginAsync(const idp::AuthenticationOutcome& outcome,fnd::Instant) override {
        auto owner=m_directory.ownerOf(core::ExternalIdentityRef{outcome.provider(),outcome.subject()});
        if (!owner) co_return fnd::fail(owner.error());
        if (!owner->has_value()) co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        co_return owner->value();
    }
    boost::asio::awaitable<fnd::Status> authorizeConnectionTargetAsync(core::IdentityId) override
    { co_return fnd::fail(fnd::ErrorCode::Unavailable); }
    boost::asio::awaitable<fnd::Result<core::ExternalIdentityRef>>
    finishConnectionAsync(const idp::AuthenticationOutcome&,core::IdentityId,fnd::Instant) override
    { co_return fnd::fail(fnd::ErrorCode::Unavailable); }
private:
    core::InMemoryExternalIdentityDirectory& m_directory;
};

class MemorySessionIssuer final : public sess::CoroutineReplacingSessionIssuer {
public:
    explicit MemorySessionIssuer(sess::SessionService& service):m_service(service){}
    boost::asio::awaitable<fnd::Result<sess::CoroutineIssuedSession>>
    issueAsync(const auth::VerifiedAuthentication& verified,idp::ClientContext client) override {
        co_return co_await issueReplacingAsync(verified,std::move(client),std::nullopt);
    }
    boost::asio::awaitable<fnd::Result<sess::CoroutineIssuedSession>>
    issueReplacingAsync(const auth::VerifiedAuthentication& verified,idp::ClientContext client,
        std::optional<fnd::SecretString> previous) override {
        auto grant=m_service.issueReplacing(verified,client,previous?&*previous:nullptr);
        if (!grant) co_return fnd::fail(grant.error());
        co_return sess::CoroutineIssuedSession{grant->id(),grant->token().clone()};
    }
private:
    sess::SessionService& m_service;
};

struct Fixture {
    explicit Fixture(std::string subject = "alice")
        : clock(kNow),
          sessionService(sessionRepository, clock,
              sess::SessionKey::create(fnd::SecretString{
                  "0123456789abcdef0123456789abcdef"}).value(),
              sess::SessionPolicy::create(std::chrono::hours{8},
                                          std::chrono::minutes{30}).value()),
          recoveryService(cred::RecoveryCodeService::create(
              recoveryRepository, fnd::SecretString{
                  "abcdef0123456789abcdef0123456789"}).value()),
          limiter(gw::TokenBucketRateLimiter::create(
              clock, 1000.0, 1000.0, 1000U).value())
    {
        auto passwordPolicy = cred::PasswordPolicy::create(
            1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U).value();
        auto passwordHasher = cred::PasswordHasher::create(
            fnd::SecretString{std::string(32U, 'p')}, passwordPolicy).value();
        accounts = local::InMemoryLocalAccountDirectory::create(
            std::move(passwordHasher), cred::TotpPolicy::recommended()).value();
        auto totp = cred::TotpSecret::create(
            fnd::SecretString{"12345678901234567890"}).value();
        totpCode = cred::totpAt(totp, cred::TotpPolicy::recommended(), kNow).value();
        EXPECT_TRUE(accounts->enroll(
            idp::ExternalSubject{subject}, fnd::SecretString{"correct-password"},
            std::optional<cred::TotpSecret>{std::move(totp)}));
        auto provider = std::make_unique<MemoryLocalProvider>(
            *accounts,clock,externalIdentities,recoveryService);
        EXPECT_TRUE(registry.registerProvider(std::move(provider)));

        auto link = core::IdentityLink::request(
            core::IdentityId{"identity-1"},
            core::ExternalIdentityRef{idp::ProviderId{"local"},
                                      idp::ExternalSubject{subject}},
            kNow, std::chrono::minutes{5}).value();
        EXPECT_TRUE(link.requireVerification(kNow));
        EXPECT_TRUE(link.markVerified(kNow));
        EXPECT_TRUE(link.complete(kNow));
        EXPECT_TRUE(externalIdentities.attach(link));
        auth::ProviderTrustPolicy trust;
        EXPECT_TRUE(trust.trust(idp::ProviderId{"local"}, idp::AssuranceLevel::Ial2));
        authentication = std::make_unique<auth::AuthenticationService>(
            registry, transactions, externalIdentities, clock, std::move(trust),
            std::chrono::minutes{5}, nullptr, {}, nullptr, &finalizer);
        api = std::make_unique<authHttp::AuthenticationHttpApi>(
            *authentication, issuer, limiter,idp::ProviderId{"local"},fallback);
    }

    gw::HttpResponse invoke(gw::HttpRequest request) {
        boost::asio::io_context io;
        std::optional<gw::HttpResponse> result;
        auto capture=[](authHttp::AuthenticationHttpApi& api,gw::HttpRequest input,
                        std::optional<gw::HttpResponse>& output)->boost::asio::awaitable<void> {
            output.emplace(co_await api.handleAsync(std::move(input)));
        };
        auto done=boost::asio::co_spawn(io,capture(*api,std::move(request),result),boost::asio::use_future);
        io.run();
        done.get();
        return std::move(result.value());
    }

    fnd::ManualClockSource clock;
    idp::ProviderRegistry registry;
    idp::InMemoryAuthenticationTransactionStore transactions;
    core::InMemoryExternalIdentityDirectory externalIdentities;
    MemoryLoginFinalizer finalizer{externalIdentities};
    std::unique_ptr<local::InMemoryLocalAccountDirectory> accounts;
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessionService;
    MemorySessionIssuer issuer{sessionService};
    cred::InMemoryRecoveryCodeRepository recoveryRepository;
    cred::RecoveryCodeService recoveryService;
    gw::TokenBucketRateLimiter limiter;
    Fallback fallback;
    std::unique_ptr<auth::AuthenticationService> authentication;
    std::unique_ptr<authHttp::AuthenticationHttpApi> api;
    std::string totpCode;
};

class NeverIssueNativeSession final : public sess::CoroutineReplacingSessionIssuer {
public:
    boost::asio::awaitable<fnd::Result<sess::CoroutineIssuedSession>>
    issueAsync(const auth::VerifiedAuthentication&,idp::ClientContext) override {
        ++calls;
        co_return fnd::fail(fnd::ErrorCode::Unavailable);
    }
    boost::asio::awaitable<fnd::Result<sess::CoroutineIssuedSession>>
    issueReplacingAsync(const auth::VerifiedAuthentication&,idp::ClientContext,
                        std::optional<fnd::SecretString>) override {
        ++calls;
        co_return fnd::fail(fnd::ErrorCode::Unavailable);
    }
    int calls{};
};

TEST(AuthenticationHttpApiTest, NativeRuntimeConstructorCannotDispatchLegacyAuthentication)
{
    Fixture fixture;
    NeverIssueNativeSession issuer;
    authHttp::AuthenticationHttpApi api{
        *fixture.authentication,issuer,fixture.limiter,idp::ProviderId{"local"},fixture.fallback};
    for (const auto route:{"/auth/login","/auth/mfa/verify","/auth/session/rotate",
                           "/auth/logout","/auth/logout-all","/auth/recovery-codes"}) {
        EXPECT_EQ(api.handle(request(route,R"({"subject":"alice"})")).status(),503)
            << route;
    }
    EXPECT_EQ(fixture.transactions.size(),0U);
    EXPECT_EQ(fixture.sessionRepository.size(),0U);
    EXPECT_EQ(issuer.calls,0);
    EXPECT_EQ(api.handle(request("/non-auth",{})).status(),418);
}

TEST(AuthenticationHttpApiTest, NativeLoginMfaAndRecoveryWithInMemorySessionLifecycle)
{
    Fixture fixture;
    const auto started = fixture.invoke(request(
        "/auth/login", R"({"subject":"alice"})"));
    ASSERT_EQ(started.status(), 202);
    const std::string continuation = cookieValue(started, "__Host-openproof-preauth");
    const std::string binding = cookieValue(started, "__Host-openproof-preauth-binding");
    const std::string subjectCookie = cookieValue(started, "__Host-openproof-preauth-subject");
    ASSERT_FALSE(continuation.empty());
    ASSERT_FALSE(binding.empty());
    ASSERT_FALSE(subjectCookie.empty());
    expectHostCookie(started, "__Host-openproof-preauth");
    expectHostCookie(started, "__Host-openproof-preauth-binding");
    expectHostCookie(started, "__Host-openproof-preauth-subject");
    const json::object startBody = json::parse(started.body()).as_object();

    json::object completionBody;
    completionBody["transaction_id"] = startBody.at("transaction_id");
    completionBody["challenge_id"] = startBody.at("challenge_id");
    completionBody["password"] = "correct-password";
    completionBody["totp"] = fixture.totpCode;
    const std::string preauthCookies = preauthCookieHeader(started);
    const auto completed = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(completionBody), preauthCookies));
    ASSERT_EQ(completed.status(), 200) << completed.body();
    const std::string firstToken = cookieValue(completed, "__Host-openproof-session");
    ASSERT_FALSE(firstToken.empty());
    expectHostCookie(completed, "__Host-openproof-session");
    EXPECT_EQ(json::parse(completed.body()).as_object().at("assurance"), "ial2");

    auto recovery=fixture.recoveryService.issue(core::IdentityId{"identity-1"},10U);
    ASSERT_TRUE(recovery);
    ASSERT_EQ(recovery->codes().size(),10U);
    const std::string recoveryCode{recovery->codes().front().expose()};

    auto rotated=fixture.sessionService.rotate(fnd::SecretString{firstToken});
    ASSERT_TRUE(rotated);
    const std::string replacement{rotated->token().expose()};
    ASSERT_FALSE(replacement.empty());
    EXPECT_NE(firstToken, replacement);
    EXPECT_FALSE(fixture.sessionService.authenticate(fnd::SecretString{firstToken}));
    EXPECT_TRUE(fixture.sessionService.authenticate(fnd::SecretString{replacement}));

    ASSERT_TRUE(fixture.sessionService.revoke(rotated->id()));
    EXPECT_FALSE(fixture.sessionService.authenticate(fnd::SecretString{replacement}));

    const auto recoveryStarted = fixture.invoke(request(
        "/auth/login", R"({"subject":"alice"})"));
    ASSERT_EQ(recoveryStarted.status(), 202);
    const auto recoveryStartBody = json::parse(recoveryStarted.body()).as_object();
    json::object recoveryCompletion;
    recoveryCompletion["transaction_id"] = recoveryStartBody.at("transaction_id");
    recoveryCompletion["challenge_id"] = recoveryStartBody.at("challenge_id");
    recoveryCompletion["password"] = "correct-password";
    recoveryCompletion["recovery_code"] = recoveryCode;
    const std::string recoveryPreauth = preauthCookieHeader(recoveryStarted);
    const auto recovered = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(recoveryCompletion), recoveryPreauth));
    ASSERT_EQ(recovered.status(), 200) << recovered.body();
    EXPECT_EQ(json::parse(recovered.body()).as_object().at("assurance"), "ial2");

    const auto replayStarted = fixture.invoke(request(
        "/auth/login", R"({"subject":"alice"})"));
    ASSERT_EQ(replayStarted.status(), 202);
    const auto replayStartBody = json::parse(replayStarted.body()).as_object();
    json::object replayCompletion;
    replayCompletion["transaction_id"] = replayStartBody.at("transaction_id");
    replayCompletion["challenge_id"] = replayStartBody.at("challenge_id");
    replayCompletion["password"] = "correct-password";
    replayCompletion["recovery_code"] = recoveryCode;
    const std::string replayPreauth = preauthCookieHeader(replayStarted);
    const auto replayed = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(replayCompletion), replayPreauth));
    EXPECT_EQ(replayed.status(), 401);
}

TEST(AuthenticationHttpApiTest, NativeLoginLeafCannotIssueRecoveryCodesAfterTotpDisable)
{
    Fixture fixture;
    const auto started = fixture.invoke(request(
        "/auth/login", R"({"subject":"alice"})"));
    ASSERT_EQ(started.status(), 202);
    const auto startBody = json::parse(started.body()).as_object();
    json::object completion;
    completion["transaction_id"] = startBody.at("transaction_id");
    completion["challenge_id"] = startBody.at("challenge_id");
    completion["password"] = std::string{"correct-"} + "pass" + "word";
    completion["totp"] = fixture.totpCode;
    const std::string preauthCookies = preauthCookieHeader(started);
    const auto completed = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(completion), preauthCookies));
    ASSERT_EQ(completed.status(), 200) << completed.body();
    const std::string token = cookieValue(completed, "__Host-openproof-session");
    ASSERT_FALSE(token.empty());

    ASSERT_TRUE(fixture.accounts->removeTotp(idp::ExternalSubject{"alice"}));
    const auto recovery = fixture.api->handle(request(
        "/auth/recovery-codes", {}, "__Host-openproof-session=" + token));
    EXPECT_EQ(recovery.status(), 503); // This leaf cannot issue recovery codes.
    auto enabled=fixture.accounts->hasTotp(idp::ExternalSubject{"alice"});
    ASSERT_TRUE(enabled);
    EXPECT_FALSE(enabled.value());
    auto remaining = fixture.recoveryRepository.remaining(core::IdentityId{"identity-1"});
    ASSERT_TRUE(remaining);
    EXPECT_EQ(remaining.value(), 0U);
}

TEST(AuthenticationHttpApiTest, LongValidSubjectCookieSurvivesLoginVerification)
{
    // The 320-byte allowed subject can have a base64url cookie above 128
    // characters. Rejected cookies previously made valid logins impossible.
    const std::string subject(180U, 'x');
    Fixture fixture{subject};
    json::object input;
    input["subject"] = subject;
    const auto started = fixture.invoke(
        request("/auth/login", json::serialize(input)));
    ASSERT_EQ(started.status(), 202) << started.body();
    const std::string subjectCookie =
        cookieValue(started, "__Host-openproof-preauth-subject");
    ASSERT_GT(subjectCookie.size(), 128U);
    ASSERT_LE(subjectCookie.size(), 512U);

    const auto body = json::parse(started.body()).as_object();
    json::object proof;
    proof["transaction_id"] = body.at("transaction_id");
    proof["challenge_id"] = body.at("challenge_id");
    proof["password"] = "correct-password";
    proof["totp"] = fixture.totpCode;
    const auto completed = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(proof), preauthCookieHeader(started)));
    ASSERT_EQ(completed.status(), 200) << completed.body();
    EXPECT_FALSE(cookieValue(completed, "__Host-openproof-session").empty());
}

TEST(AuthenticationHttpApiTest, RepeatedLoginFromSameCookieRetiresEarlierSession)
{
    Fixture fixture;
    const auto started = fixture.invoke(request(
        "/auth/login", R"({"subject":"alice"})"));
    ASSERT_EQ(started.status(), 202);
    const auto beginBody = json::parse(started.body()).as_object();
    json::object firstProof;
    firstProof["transaction_id"] = beginBody.at("transaction_id");
    firstProof["challenge_id"] = beginBody.at("challenge_id");
    firstProof["password"] = "correct-password";
    firstProof["totp"] = fixture.totpCode;
    const auto completed = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(firstProof), preauthCookieHeader(started)));
    ASSERT_EQ(completed.status(), 200);
    const std::string oldToken = cookieValue(completed, "__Host-openproof-session");
    ASSERT_FALSE(oldToken.empty());

    // A failed login from the same browser must not create or revoke a session.
    const std::string sameBrowserCookie = "__Host-openproof-session=" + oldToken;
    const auto rejectedStart = fixture.invoke(request(
        "/auth/login", R"({"subject":"alice"})", sameBrowserCookie));
    ASSERT_EQ(rejectedStart.status(), 202);
    const auto rejectedBody = json::parse(rejectedStart.body()).as_object();
    json::object invalidProof;
    invalidProof["transaction_id"] = rejectedBody.at("transaction_id");
    invalidProof["challenge_id"] = rejectedBody.at("challenge_id");
    invalidProof["password"] = "wrong-password";
    invalidProof["totp"] = fixture.totpCode;
    const auto failed = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(invalidProof),
        preauthCookieHeader(rejectedStart) + "; " + sameBrowserCookie));
    EXPECT_EQ(failed.status(), 401);
    ASSERT_TRUE(fixture.sessionService.authenticate(fnd::SecretString{oldToken}));
    auto stillOne = fixture.sessionService.list(core::IdentityId{"identity-1"});
    ASSERT_TRUE(stillOne);
    EXPECT_EQ(stillOne->size(), 1U);

    // Advance the authenticator clock: replay of an already used TOTP is refused.
    fixture.clock.advance(std::chrono::seconds{31});
    const auto secondStarted = fixture.invoke(request(
        "/auth/login", R"({"subject":"alice"})", sameBrowserCookie));
    ASSERT_EQ(secondStarted.status(), 202);
    const auto secondStartBody = json::parse(secondStarted.body()).as_object();
    auto secondTotpSecret = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"}).value();
    const std::string newCode = cred::totpAt(
        secondTotpSecret, cred::TotpPolicy::recommended(), fixture.clock.now()).value();
    json::object secondProof;
    secondProof["transaction_id"] = secondStartBody.at("transaction_id");
    secondProof["challenge_id"] = secondStartBody.at("challenge_id");
    secondProof["password"] = "correct-password";
    secondProof["totp"] = newCode;
    const auto relogged = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(secondProof),
        preauthCookieHeader(secondStarted) + "; " + sameBrowserCookie));
    ASSERT_EQ(relogged.status(), 200) << relogged.body();
    const std::string newToken = cookieValue(relogged, "__Host-openproof-session");
    ASSERT_FALSE(newToken.empty());
    EXPECT_NE(newToken, oldToken);
    EXPECT_FALSE(fixture.sessionService.authenticate(fnd::SecretString{oldToken}));
    EXPECT_TRUE(fixture.sessionService.authenticate(fnd::SecretString{newToken}));
    const auto listed = fixture.sessionService.list(core::IdentityId{"identity-1"});
    ASSERT_TRUE(listed);
    EXPECT_EQ(listed->size(), 1U);
}

TEST(AuthenticationHttpApiTest, WrongPasswordBurnsExchangeAndClearsPreauthCookies)
{
    Fixture fixture;
    const auto started = fixture.invoke(request(
        "/auth/login", R"({"subject":"alice"})"));
    const auto body = json::parse(started.body()).as_object();
    json::object completion;
    completion["transaction_id"] = body.at("transaction_id");
    completion["challenge_id"] = body.at("challenge_id");
    completion["password"] = "wrong-password";
    completion["totp"] = fixture.totpCode;
    const std::string cookies = preauthCookieHeader(started);
    const auto rejected = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(completion), cookies));
    EXPECT_EQ(rejected.status(), 401);
    EXPECT_EQ(cookieValue(rejected, "__Host-openproof-preauth"), "");
    EXPECT_EQ(cookieValue(rejected, "__Host-openproof-preauth-binding"), "");
    EXPECT_EQ(cookieValue(rejected, "__Host-openproof-preauth-subject"), "");
    EXPECT_EQ(fixture.sessionRepository.size(), 0U);
}

TEST(AuthenticationHttpApiTest, TamperedSubjectCookieCannotSwitchAccounts)
{
    Fixture fixture;
    const auto started = fixture.invoke(request(
        "/auth/login", R"({"subject":"alice"})"));
    ASSERT_EQ(started.status(), 202);
    const auto body = json::parse(started.body()).as_object();
    json::object completion;
    completion["transaction_id"] = body.at("transaction_id");
    completion["challenge_id"] = body.at("challenge_id");
    completion["password"] = "correct-password";
    completion["totp"] = fixture.totpCode;

    const auto rejected = fixture.invoke(request(
        "/auth/mfa/verify", json::serialize(completion),
        preauthCookieHeader(started, "Ym9i")));

    EXPECT_EQ(rejected.status(), 401);
    EXPECT_EQ(cookieValue(rejected, "__Host-openproof-preauth"), "");
    EXPECT_EQ(cookieValue(rejected, "__Host-openproof-preauth-binding"), "");
    EXPECT_EQ(cookieValue(rejected, "__Host-openproof-preauth-subject"), "");
}

TEST(AuthenticationHttpApiTest, SharedSessionCredentialParserRejectsAmbiguity)
{
    auto ambiguous = gw::HttpRequest::create(
        gw::HttpMethod::Post, "/auth/logout",
        {{"authorization", "Bearer bearer-token"},
         {"cookie", "__Host-openproof-session=cookie-token"}},
        {}, "127.0.0.1", fnd::CorrelationId{"request"});
    ASSERT_TRUE(ambiguous);

    auto rejected=gw::takeSessionCredential(ambiguous.value());
    EXPECT_FALSE(rejected);
    EXPECT_EQ(rejected.error().code(),fnd::ErrorCode::AuthenticationFailed);
}

TEST(Web3PresentationMetadataTest, DiscardsUnsafeTextWithoutBlockingAuthentication)
{
    using openproof::authentication::http::detail::presentationText;

    EXPECT_EQ(presentationText(std::optional<std::string>{"Ada Lovelace"}, 256U),
              std::optional<std::string>{"Ada Lovelace"});
    EXPECT_FALSE(presentationText(std::optional<std::string>{"Ada\nLovelace"}, 256U));
    EXPECT_FALSE(presentationText(std::optional<std::string>{"Ada\x7fLovelace"}, 256U));
    EXPECT_FALSE(presentationText(std::optional<std::string>{}, 256U));
}

TEST(Web3PresentationMetadataTest, KeepsOnlyStructurallyValidHttpsPictureUrls)
{
    using openproof::authentication::http::detail::presentationPictureUrl;

    const auto valid = presentationPictureUrl(std::optional<std::string>{
        "https://imagedelivery.example.test:443/avatar/42?variant=large"});
    ASSERT_TRUE(valid);
    EXPECT_EQ(*valid,
              "https://imagedelivery.example.test:443/avatar/42?variant=large");

    for (const std::string value : {
             "http://images.example.test/avatar.png",
             "https:///avatar.png",
             "https://user@images.example.test/avatar.png",
             "https://images.example.test:0/avatar.png",
             "https://images.example.test:70000/avatar.png",
             "https://images.example.test:/avatar.png",
             "https://images.example.test/avatar.png#fragment",
             "https://images.example.test\\avatar.png",
             "https://images.example.test/avatar image.png"}) {
        EXPECT_FALSE(presentationPictureUrl(std::optional<std::string>{value})) << value;
    }
}

TEST(Web3AuthenticationHttpApiTest, MobileWalletHandoffSeparatesBrowserRedeemCredential)
{
    fnd::ManualClockSource clock{kNow};
    idp::ProviderRegistry registry;
    ASSERT_TRUE(registry.registerProvider(std::make_unique<WalletChallengeProvider>()));

    core::InMemoryExternalIdentityDirectory externalIdentities;
    idp::InMemoryAuthenticationTransactionStore transactions;
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(
        idp::ProviderId{"ethereum-wallet"}, idp::AssuranceLevel::Ial1));
    auth::AuthenticationService authentication{
        registry, transactions, externalIdentities, clock, std::move(trust),
        std::chrono::minutes{5}};
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions{
        sessionRepository, clock,
        sess::SessionKey::create(fnd::SecretString{
            "0123456789abcdef0123456789abcdef"}).value(),
        sess::SessionPolicy::create(std::chrono::hours{8},
                                    std::chrono::minutes{30}).value()};
    gw::TokenBucketRateLimiter limiter = gw::TokenBucketRateLimiter::create(
        clock, 1000.0, 1000.0, 1000U).value();
    Fallback fallback;
    authHttp::Web3AuthenticationHttpApi api{
        authentication, registry, sessions, limiter, fallback};

    const auto issued = api.handle(request(
        "/auth/web3/handoff", R"({"provider":"ethereum-wallet"})"));
    ASSERT_EQ(issued.status(), 201) << issued.body();
    const auto body = json::parse(issued.body()).as_object();
    const std::string publisher{body.at("publisher_ticket").as_string()};
    const std::string redeemer{body.at("redeem_ticket").as_string()};
    EXPECT_FALSE(publisher.empty());
    EXPECT_FALSE(redeemer.empty());
    EXPECT_NE(publisher, redeemer);
    EXPECT_TRUE(setCookies(issued).empty());

    json::object redemption;
    redemption["redeem_ticket"] = redeemer;
    const auto pending = api.handle(request(
        "/auth/web3/handoff/redeem", json::serialize(redemption)));
    ASSERT_EQ(pending.status(), 202) << pending.body();
    EXPECT_TRUE(json::parse(pending.body()).as_object().at("pending").as_bool());
    EXPECT_TRUE(cookieValue(pending, "__Host-openproof-session").empty());
}

TEST(FederatedAuthenticationHttpApiTest, RuntimeDelegatedStartUsesOneTimeHandoffWithoutProviderIo)
{
    fnd::ManualClockSource clock{kNow};
    idp::ProviderRegistry registry;
    auto implementation=std::make_unique<HandoffOnlyRedirectProvider>();
    auto* observed=implementation.get();
    ASSERT_TRUE(registry.registerProvider(std::move(implementation)));
    idp::InMemoryAuthenticationTransactionStore transactions;
    core::InMemoryExternalIdentityDirectory identities;
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(idp::ProviderId{"handoff-test"},idp::AssuranceLevel::Ial1));
    auth::AuthenticationService authentication{registry,transactions,identities,clock,
        std::move(trust),std::chrono::minutes{5}};
    sess::InMemorySessionRepository repository;
    sess::SessionService sessions{repository,clock,
        sess::SessionKey::create(fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value(),
        sess::SessionPolicy::create(std::chrono::hours{8},std::chrono::minutes{30}).value()};
    auto limiter=gw::TokenBucketRateLimiter::create(clock,100.0,100.0,100U).value();
    Fallback fallback;
    HandoffDelegatedAccess delegated;
    authHttp::FederatedAuthenticationHttpApi api{
        authentication,registry,sessions,limiter,fallback,&delegated,true};
    const auto request=[](std::string target,std::string bearer){
        return gw::HttpRequest::create(gw::HttpMethod::Get,std::move(target),
            {{"authorization","Bearer "+std::move(bearer)}},"","127.0.0.1",
            fnd::CorrelationId{"handoff-test"}).value();
    };
    const std::string route="/account/connections/start?provider=handoff-test&return_to=%2Faccount";
    EXPECT_EQ(api.handle(request(route,"wrong-token")).status(),401);
    const auto response=api.handle(request(route,"fixture-delegated"));
    ASSERT_EQ(response.status(),302) << response.body();
    const auto location=response.headers().at("location");
    const std::string prefix="/account/connections/handoff?ticket=";
    ASSERT_TRUE(location.starts_with(prefix));
    EXPECT_EQ(response.headers().at("cache-control"),"no-store");
    EXPECT_EQ(api.handle(request(location,"fixture-delegated")).status(),503);
    auto consumed=authentication.consumeBrowserConnectionHandoff(
        fnd::SecretString{location.substr(prefix.size())});
    ASSERT_TRUE(consumed);
    EXPECT_EQ(consumed->identity.value(),"identity-current");
    EXPECT_EQ(consumed->providerId.value(),"handoff-test");
    EXPECT_EQ(consumed->returnTarget,"/account");
    EXPECT_FALSE(authentication.consumeBrowserConnectionHandoff(
        fnd::SecretString{location.substr(prefix.size())}));
    EXPECT_EQ(observed->syncCalls,0);
    EXPECT_EQ(api.handle(getRequest("/auth/federated/callback?code=never")).status(),503);
}

TEST(FederatedAuthenticationHttpApiTest, ProviderDiscoverySeparatesRedirectAndChallengeProviders)
{
    fnd::ManualClockSource clock{kNow};
    idp::ProviderRegistry registry;
    ASSERT_TRUE(registry.registerProvider(std::make_unique<RedirectProvider>()));
    ASSERT_TRUE(registry.registerProvider(std::make_unique<ChallengeProvider>()));

    core::InMemoryExternalIdentityDirectory externalIdentities;
    idp::InMemoryAuthenticationTransactionStore transactions;
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(idp::ProviderId{"redirect"}, idp::AssuranceLevel::Ial1));
    ASSERT_TRUE(trust.trust(idp::ProviderId{"challenge"}, idp::AssuranceLevel::Ial1));
    auth::AuthenticationService authentication{
        registry, transactions, externalIdentities, clock, std::move(trust),
        std::chrono::minutes{5}};
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions{
        sessionRepository, clock,
        sess::SessionKey::create(fnd::SecretString{
            "0123456789abcdef0123456789abcdef"}).value(),
        sess::SessionPolicy::create(std::chrono::hours{8},
                                    std::chrono::minutes{30}).value()};
    gw::TokenBucketRateLimiter limiter = gw::TokenBucketRateLimiter::create(
        clock, 1000.0, 1000.0, 1000U).value();
    Fallback fallback;
    authHttp::FederatedAuthenticationHttpApi api{
        authentication, registry, sessions, limiter, fallback};

    const auto discovered = api.handle(getRequest("/auth/providers"));
    ASSERT_EQ(discovered.status(), 200);
    const auto body = json::parse(discovered.body()).as_object();
    const auto& redirects = body.at("providers").as_array();
    const auto& challenges = body.at("challenge_providers").as_array();
    ASSERT_EQ(redirects.size(), 1U);
    ASSERT_EQ(challenges.size(), 1U);
    EXPECT_EQ(redirects.front().as_string(), "redirect");
    EXPECT_EQ(challenges.front().as_string(), "challenge");
}

TEST(FederatedAuthenticationHttpApiTest, OAuth1CallbackForwardsTokenAndVerifier)
{
    fnd::ManualClockSource clock{kNow};
    idp::ProviderRegistry registry;
    ASSERT_TRUE(registry.registerProvider(
        std::make_unique<OAuth1RelayProvider>()));

    core::InMemoryExternalIdentityDirectory externalIdentities;
    auto link = core::IdentityLink::request(
        core::IdentityId{"identity-oauth1"},
        core::ExternalIdentityRef{idp::ProviderId{"oauth1-relay"},
                                  idp::ExternalSubject{"oauth1-subject"}},
        kNow, std::chrono::minutes{5}).value();
    ASSERT_TRUE(link.requireVerification(kNow));
    ASSERT_TRUE(link.markVerified(kNow));
    ASSERT_TRUE(link.complete(kNow));
    ASSERT_TRUE(externalIdentities.attach(link));

    idp::InMemoryAuthenticationTransactionStore transactions;
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(
        idp::ProviderId{"oauth1-relay"}, idp::AssuranceLevel::Ial1));
    auth::AuthenticationService authentication{
        registry, transactions, externalIdentities, clock, std::move(trust),
        std::chrono::minutes{5}};
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions{
        sessionRepository, clock,
        sess::SessionKey::create(fnd::SecretString{
            "0123456789abcdef0123456789abcdef"}).value(),
        sess::SessionPolicy::create(std::chrono::hours{8},
                                    std::chrono::minutes{30}).value()};
    gw::TokenBucketRateLimiter limiter = gw::TokenBucketRateLimiter::create(
        clock, 1000.0, 1000.0, 1000U).value();
    Fallback fallback;
    authHttp::FederatedAuthenticationHttpApi api{
        authentication, registry, sessions, limiter, fallback};

    const auto started = api.handle(getRequest(
        "/auth/federated/start?provider=oauth1-relay&return_to=%2Faccount"));
    ASSERT_EQ(started.status(), 302) << started.body();
    ASSERT_EQ(started.headers().at("location"),
              "https://provider.example/oauth1-authorize");

    std::string callbackCookies;
    for (const auto& header : setCookies(started)) {
        if (!callbackCookies.empty()) callbackCookies.append("; ");
        callbackCookies.append(header.substr(0U, header.find(';')));
    }
    const auto completed = api.handle(getRequest(
        "/auth/federated/callback?oauth_token=request-token&"
        "oauth_verifier=accepted-verifier",
        std::move(callbackCookies)));

    ASSERT_EQ(completed.status(), 302) << completed.body();
    EXPECT_EQ(completed.headers().at("location"), "/account");
    EXPECT_FALSE(cookieValue(
        completed, "__Host-openproof-session").empty());
}

TEST(FederatedAuthenticationHttpApiTest, FormPostForwardsAppleUserPayloadToProvider)
{
    fnd::ManualClockSource clock{kNow};
    idp::ProviderRegistry registry;
    ASSERT_TRUE(registry.registerProvider(
        std::make_unique<AppleFormPostRelayProvider>()));

    core::InMemoryExternalIdentityDirectory externalIdentities;
    auto link = core::IdentityLink::request(
        core::IdentityId{"identity-apple"},
        core::ExternalIdentityRef{idp::ProviderId{"apple-relay"},
                                  idp::ExternalSubject{"apple-subject"}},
        kNow, std::chrono::minutes{5}).value();
    ASSERT_TRUE(link.requireVerification(kNow));
    ASSERT_TRUE(link.markVerified(kNow));
    ASSERT_TRUE(link.complete(kNow));
    ASSERT_TRUE(externalIdentities.attach(link));

    idp::InMemoryAuthenticationTransactionStore transactions;
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(
        idp::ProviderId{"apple-relay"}, idp::AssuranceLevel::Ial1));
    auth::AuthenticationService authentication{
        registry, transactions, externalIdentities, clock, std::move(trust),
        std::chrono::minutes{5}};
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions{
        sessionRepository, clock,
        sess::SessionKey::create(fnd::SecretString{
            "0123456789abcdef0123456789abcdef"}).value(),
        sess::SessionPolicy::create(std::chrono::hours{8},
                                    std::chrono::minutes{30}).value()};
    gw::TokenBucketRateLimiter limiter = gw::TokenBucketRateLimiter::create(
        clock, 1000.0, 1000.0, 1000U).value();
    Fallback fallback;
    authHttp::FederatedAuthenticationHttpApi api{
        authentication, registry, sessions, limiter, fallback};

    const auto started = api.handle(getRequest(
        "/auth/federated/start?provider=apple-relay&return_to=%2Faccount"));
    ASSERT_EQ(started.status(), 302) << started.body();

    std::string callbackCookies;
    for (const auto& header : setCookies(started)) {
        if (!callbackCookies.empty()) callbackCookies.append("; ");
        callbackCookies.append(header.substr(0U, header.find(';')));
    }
    const std::string form =
        "code=accepted&state=provider-state&user="
        "%7B%22name%22%3A%7B%22firstName%22%3A%22Ada%22%2C"
        "%22lastName%22%3A%22Lovelace%22%7D%2C"
        "%22email%22%3A%22ignored%40example.test%22%7D";
    const auto completed = api.handle(formPostRequest(
        "/auth/federated/callback", form, std::move(callbackCookies)));

    ASSERT_EQ(completed.status(), 302) << completed.body();
    EXPECT_EQ(completed.headers().at("location"), "/account");
    EXPECT_FALSE(cookieValue(completed, "__Host-openproof-session").empty());
}

TEST(FederatedAuthenticationHttpApiTest, ConnectionConflictRedirectsBackToUiInsteadOfRenderingJson)
{
    fnd::ManualClockSource clock{kNow};
    idp::ProviderRegistry registry;
    ASSERT_TRUE(registry.registerProvider(std::make_unique<RedirectProvider>()));
    ASSERT_TRUE(registry.registerProvider(std::make_unique<SessionRedirectProvider>()));

    core::InMemoryExternalIdentityDirectory externalIdentities;
    const auto attach = [&](std::string identity, std::string provider,
                            std::string subject) {
        auto link = core::IdentityLink::request(
            core::IdentityId{std::move(identity)},
            core::ExternalIdentityRef{
                idp::ProviderId{std::move(provider)},
                idp::ExternalSubject{std::move(subject)}},
            kNow, std::chrono::minutes{5}).value();
        EXPECT_TRUE(link.requireVerification(kNow));
        EXPECT_TRUE(link.markVerified(kNow));
        EXPECT_TRUE(link.complete(kNow));
        EXPECT_TRUE(externalIdentities.attach(link));
    };
    attach("identity-current", "session-redirect", "session-subject");
    attach("identity-existing", "redirect", "redirect-subject");

    idp::InMemoryAuthenticationTransactionStore transactions;
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(
        idp::ProviderId{"redirect"}, idp::AssuranceLevel::Ial1));
    ASSERT_TRUE(trust.trust(
        idp::ProviderId{"session-redirect"}, idp::AssuranceLevel::Ial1));
    auth::AuthenticationService authentication{
        registry, transactions, externalIdentities, clock, std::move(trust),
        std::chrono::minutes{5}};
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions{
        sessionRepository, clock,
        sess::SessionKey::create(fnd::SecretString{
            "0123456789abcdef0123456789abcdef"}).value(),
        sess::SessionPolicy::create(
            std::chrono::hours{8}, std::chrono::minutes{30}).value()};
    gw::TokenBucketRateLimiter limiter = gw::TokenBucketRateLimiter::create(
        clock, 1000.0, 1000.0, 1000U).value();
    Fallback fallback;
    authHttp::FederatedAuthenticationHttpApi api{
        authentication, registry, sessions, limiter, fallback};

    const auto loginStarted = api.handle(getRequest(
        "/auth/federated/start?provider=session-redirect&return_to=%2Faccount"));
    ASSERT_EQ(loginStarted.status(), 302) << loginStarted.body();
    std::string loginCookies;
    for (const auto& header : setCookies(loginStarted)) {
        if (!loginCookies.empty()) loginCookies.append("; ");
        loginCookies.append(header.substr(0U, header.find(';')));
    }
    const auto loginCompleted = api.handle(getRequest(
        "/auth/federated/callback?code=accepted&state=provider-state",
        std::move(loginCookies)));
    ASSERT_EQ(loginCompleted.status(), 302) << loginCompleted.body();
    const std::string sessionToken =
        cookieValue(loginCompleted, "__Host-openproof-session");
    ASSERT_FALSE(sessionToken.empty());

    const auto cancelledStarted = api.handle(getRequest(
        "/account/connections/start?provider=redirect&return_to="
        "%2Faccount%3Fop_connection%3Dcomplete%26op_provider%3Dgithub",
        "__Host-openproof-session=" + sessionToken));
    ASSERT_EQ(cancelledStarted.status(), 302) << cancelledStarted.body();
    std::string cancelledCookies =
        "__Host-openproof-session=" + sessionToken;
    for (const auto& header : setCookies(cancelledStarted)) {
        cancelledCookies.append("; ");
        cancelledCookies.append(header.substr(0U, header.find(';')));
    }
    const auto cancelled = api.handle(getRequest(
        "/auth/federated/callback?error=access_denied&state=provider-state",
        std::move(cancelledCookies)));
    ASSERT_EQ(cancelled.status(), 302) << cancelled.body();
    EXPECT_NE(cancelled.headers().at("location").find(
                  "op_error=AUTHENTICATION_FAILED"),
              std::string::npos);
    EXPECT_TRUE(cancelled.body().empty());

    const auto connectionStarted = api.handle(getRequest(
        "/account/connections/start?provider=redirect&return_to="
        "%2Faccount%3Fop_connection%3Dcomplete%26op_provider%3Dgithub",
        "__Host-openproof-session=" + sessionToken));
    ASSERT_EQ(connectionStarted.status(), 302) << connectionStarted.body();

    std::string callbackCookies =
        "__Host-openproof-session=" + sessionToken;
    for (const auto& header : setCookies(connectionStarted)) {
        callbackCookies.append("; ");
        callbackCookies.append(header.substr(0U, header.find(';')));
    }
    const auto conflicted = api.handle(getRequest(
        "/auth/federated/callback?code=accepted&state=provider-state",
        std::move(callbackCookies)));

    ASSERT_EQ(conflicted.status(), 302) << conflicted.body();
    const auto location = conflicted.headers().at("location");
    EXPECT_NE(location.find("op_connection=complete"), std::string::npos);
    EXPECT_NE(location.find("op_provider=github"), std::string::npos);
    EXPECT_NE(location.find("op_error=CONFLICT"), std::string::npos);
    EXPECT_NE(location.find("op_request=request"), std::string::npos);
    EXPECT_TRUE(conflicted.body().empty());
    EXPECT_TRUE(setCookieHeader(
        conflicted, "__Host-openproof-federation-continuation").contains("Max-Age=0"));
}

TEST(FederatedAuthenticationHttpApiTest, GitHubStateCookiesUseLaxWithoutChangingOtherProviders)
{
    fnd::ManualClockSource clock{kNow};
    idp::ProviderRegistry registry;
    ASSERT_TRUE(registry.registerProvider(std::make_unique<RedirectProvider>("github")));
    ASSERT_TRUE(registry.registerProvider(std::make_unique<RedirectProvider>()));

    core::InMemoryExternalIdentityDirectory externalIdentities;
    idp::InMemoryAuthenticationTransactionStore transactions;
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(idp::ProviderId{"github"}, idp::AssuranceLevel::Ial1));
    ASSERT_TRUE(trust.trust(idp::ProviderId{"redirect"}, idp::AssuranceLevel::Ial1));
    auth::AuthenticationService authentication{
        registry, transactions, externalIdentities, clock, std::move(trust),
        std::chrono::minutes{5}};
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions{
        sessionRepository, clock,
        sess::SessionKey::create(fnd::SecretString{
            "0123456789abcdef0123456789abcdef"}).value(),
        sess::SessionPolicy::create(std::chrono::hours{8},
                                    std::chrono::minutes{30}).value()};
    gw::TokenBucketRateLimiter limiter = gw::TokenBucketRateLimiter::create(
        clock, 1000.0, 1000.0, 1000U).value();
    Fallback fallback;
    authHttp::FederatedAuthenticationHttpApi api{
        authentication, registry, sessions, limiter, fallback};

    const auto githubStart = api.handle(getRequest(
        "/auth/federated/start?provider=github&return_to=%2Faccount"));
    ASSERT_EQ(githubStart.status(), 302) << githubStart.body();
    ASSERT_EQ(setCookies(githubStart).size(), 5U);
    for (const auto& header : setCookies(githubStart)) {
        EXPECT_NE(header.find("; SameSite=Lax"), std::string::npos);
        EXPECT_NE(header.find("; Secure"), std::string::npos);
        EXPECT_NE(header.find("; HttpOnly"), std::string::npos);
    }

    const auto otherStart = api.handle(getRequest(
        "/auth/federated/start?provider=redirect&return_to=%2Faccount"));
    ASSERT_EQ(otherStart.status(), 302) << otherStart.body();
    ASSERT_EQ(setCookies(otherStart).size(), 5U);
    for (const auto& header : setCookies(otherStart)) {
        EXPECT_NE(header.find("; SameSite=None"), std::string::npos);
    }
}

TEST(FederatedAuthenticationHttpApiTest, CallbackSessionSurvivesCrossSiteOAuthRedirect)
{
    fnd::ManualClockSource clock{kNow};
    idp::ProviderRegistry registry;
    ASSERT_TRUE(registry.registerProvider(std::make_unique<RedirectProvider>()));

    core::InMemoryExternalIdentityDirectory externalIdentities;
    auto link = core::IdentityLink::request(
        core::IdentityId{"identity-redirect"},
        core::ExternalIdentityRef{idp::ProviderId{"redirect"},
                                  idp::ExternalSubject{"redirect-subject"}},
        kNow, std::chrono::minutes{5}).value();
    ASSERT_TRUE(link.requireVerification(kNow));
    ASSERT_TRUE(link.markVerified(kNow));
    ASSERT_TRUE(link.complete(kNow));
    ASSERT_TRUE(externalIdentities.attach(link));

    idp::InMemoryAuthenticationTransactionStore transactions;
    auth::ProviderTrustPolicy trust;
    ASSERT_TRUE(trust.trust(idp::ProviderId{"redirect"}, idp::AssuranceLevel::Ial1));
    auth::AuthenticationService authentication{
        registry, transactions, externalIdentities, clock, std::move(trust),
        std::chrono::minutes{5}};
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions{
        sessionRepository, clock,
        sess::SessionKey::create(fnd::SecretString{
            "0123456789abcdef0123456789abcdef"}).value(),
        sess::SessionPolicy::create(std::chrono::hours{8},
                                    std::chrono::minutes{30}).value()};
    gw::TokenBucketRateLimiter limiter = gw::TokenBucketRateLimiter::create(
        clock, 1000.0, 1000.0, 1000U).value();
    Fallback fallback;
    authHttp::FederatedAuthenticationHttpApi api{
        authentication, registry, sessions, limiter, fallback};

    const auto started = api.handle(getRequest(
        "/auth/federated/start?provider=redirect&return_to="
        "%2Foauth%2Fauthorize%3Fclient_id%3Dqml-demo"));
    ASSERT_EQ(started.status(), 302) << started.body();
    ASSERT_EQ(started.headers().at("location"), "https://provider.example/authorize");

    std::string callbackCookies;
    for (const auto& header : setCookies(started)) {
        if (!callbackCookies.empty()) callbackCookies.append("; ");
        callbackCookies.append(header.substr(0U, header.find(';')));
    }
    const auto completed = api.handle(getRequest(
        "/auth/federated/callback?code=accepted&state=provider-state",
        std::move(callbackCookies)));
    ASSERT_EQ(completed.status(), 302) << completed.body();
    EXPECT_EQ(completed.headers().at("location"),
              "/oauth/authorize?client_id=qml-demo");
    const auto sessionHeader = setCookieHeader(completed, "__Host-openproof-session");
    ASSERT_FALSE(sessionHeader.empty());
    EXPECT_NE(sessionHeader.find("; SameSite=Lax"), std::string::npos);
    EXPECT_EQ(sessionHeader.find("; SameSite=Strict"), std::string::npos);
}

}
