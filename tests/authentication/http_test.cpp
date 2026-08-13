#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/json.hpp>

import openproof.authentication;
import openproof.authentication.http;
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

struct Fixture {
    Fixture()
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
            idp::ExternalSubject{"alice"}, fnd::SecretString{"correct-password"},
            std::optional<cred::TotpSecret>{std::move(totp)}));
        auto provider = std::make_unique<local::LocalAuthenticationProvider>(
            idp::ProviderId{"local"}, *accounts, clock, std::chrono::minutes{5});
        EXPECT_TRUE(registry.registerProvider(std::move(provider)));

        auto link = core::IdentityLink::request(
            core::IdentityId{"identity-1"},
            core::ExternalIdentityRef{idp::ProviderId{"local"},
                                      idp::ExternalSubject{"alice"}},
            kNow, std::chrono::minutes{5}).value();
        EXPECT_TRUE(link.requireVerification(kNow));
        EXPECT_TRUE(link.markVerified(kNow));
        EXPECT_TRUE(link.complete(kNow));
        EXPECT_TRUE(externalIdentities.attach(link));
        auth::ProviderTrustPolicy trust;
        EXPECT_TRUE(trust.trust(idp::ProviderId{"local"}, idp::AssuranceLevel::Ial2));
        authentication = std::make_unique<auth::AuthenticationService>(
            registry, transactions, externalIdentities, clock, std::move(trust),
            std::chrono::minutes{5});
        api = std::make_unique<authHttp::AuthenticationHttpApi>(
            *authentication, sessionService, recoveryService, limiter,
            idp::ProviderId{"local"}, fallback);
    }

    fnd::ManualClockSource clock;
    idp::ProviderRegistry registry;
    idp::InMemoryAuthenticationTransactionStore transactions;
    core::InMemoryExternalIdentityDirectory externalIdentities;
    std::unique_ptr<local::InMemoryLocalAccountDirectory> accounts;
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessionService;
    cred::InMemoryRecoveryCodeRepository recoveryRepository;
    cred::RecoveryCodeService recoveryService;
    gw::TokenBucketRateLimiter limiter;
    Fallback fallback;
    std::unique_ptr<auth::AuthenticationService> authentication;
    std::unique_ptr<authHttp::AuthenticationHttpApi> api;
    std::string totpCode;
};

TEST(AuthenticationHttpApiTest, LoginMfaRecoveryRotationAndLogoutAreEndToEnd)
{
    Fixture fixture;
    const auto started = fixture.api->handle(request(
        "/auth/login", R"({"subject":"alice"})"));
    ASSERT_EQ(started.status(), 202);
    const std::string continuation = cookieValue(started, "__Host-openproof-preauth");
    const std::string binding = cookieValue(started, "__Host-openproof-preauth-binding");
    ASSERT_FALSE(continuation.empty());
    ASSERT_FALSE(binding.empty());
    expectHostCookie(started, "__Host-openproof-preauth");
    expectHostCookie(started, "__Host-openproof-preauth-binding");
    const json::object startBody = json::parse(started.body()).as_object();

    json::object completionBody;
    completionBody["transaction_id"] = startBody.at("transaction_id");
    completionBody["challenge_id"] = startBody.at("challenge_id");
    completionBody["password"] = "correct-password";
    completionBody["totp"] = fixture.totpCode;
    const std::string preauthCookies = "__Host-openproof-preauth=" + continuation
        + "; __Host-openproof-preauth-binding=" + binding;
    const auto completed = fixture.api->handle(request(
        "/auth/mfa/verify", json::serialize(completionBody), preauthCookies));
    ASSERT_EQ(completed.status(), 200) << completed.body();
    const std::string firstToken = cookieValue(completed, "__Host-openproof-session");
    ASSERT_FALSE(firstToken.empty());
    expectHostCookie(completed, "__Host-openproof-session");
    EXPECT_EQ(json::parse(completed.body()).as_object().at("assurance"), "ial2");

    const auto recovery = fixture.api->handle(request(
        "/auth/recovery-codes", {}, "__Host-openproof-session=" + firstToken));
    ASSERT_EQ(recovery.status(), 201);
    EXPECT_EQ(json::parse(recovery.body()).as_object().at("codes").as_array().size(), 10U);

    const auto rotated = fixture.api->handle(request(
        "/auth/session/rotate", {}, "__Host-openproof-session=" + firstToken));
    ASSERT_EQ(rotated.status(), 200);
    const std::string replacement = cookieValue(rotated, "__Host-openproof-session");
    ASSERT_FALSE(replacement.empty());
    EXPECT_NE(firstToken, replacement);
    EXPECT_FALSE(fixture.sessionService.authenticate(fnd::SecretString{firstToken}));
    EXPECT_TRUE(fixture.sessionService.authenticate(fnd::SecretString{replacement}));

    const auto loggedOut = fixture.api->handle(request(
        "/auth/logout", {}, "__Host-openproof-session=" + replacement));
    EXPECT_EQ(loggedOut.status(), 204);
    EXPECT_FALSE(fixture.sessionService.authenticate(fnd::SecretString{replacement}));
}

TEST(AuthenticationHttpApiTest, WrongPasswordBurnsExchangeAndClearsPreauthCookies)
{
    Fixture fixture;
    const auto started = fixture.api->handle(request(
        "/auth/login", R"({"subject":"alice"})"));
    const auto body = json::parse(started.body()).as_object();
    json::object completion;
    completion["transaction_id"] = body.at("transaction_id");
    completion["challenge_id"] = body.at("challenge_id");
    completion["password"] = "wrong-password";
    completion["totp"] = fixture.totpCode;
    const std::string cookies = "__Host-openproof-preauth="
        + cookieValue(started, "__Host-openproof-preauth")
        + "; __Host-openproof-preauth-binding="
        + cookieValue(started, "__Host-openproof-preauth-binding");
    const auto rejected = fixture.api->handle(request(
        "/auth/mfa/verify", json::serialize(completion), cookies));
    EXPECT_EQ(rejected.status(), 401);
    EXPECT_EQ(cookieValue(rejected, "__Host-openproof-preauth"), "");
    EXPECT_EQ(cookieValue(rejected, "__Host-openproof-preauth-binding"), "");
}

TEST(AuthenticationHttpApiTest, LogoutRejectsAmbiguousCredentials)
{
    Fixture fixture;
    auto ambiguous = gw::HttpRequest::create(
        gw::HttpMethod::Post, "/auth/logout",
        {{"authorization", "Bearer bearer-token"},
         {"cookie", "__Host-openproof-session=cookie-token"}},
        {}, "127.0.0.1", fnd::CorrelationId{"request"});
    ASSERT_TRUE(ambiguous);

    const auto rejected = fixture.api->handle(std::move(ambiguous).value());
    EXPECT_EQ(rejected.status(), 401);
    EXPECT_TRUE(setCookies(rejected).empty());
}

}
