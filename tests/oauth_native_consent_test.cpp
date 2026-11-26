#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "../src/oauth/http/coroutine_consent_http.hpp"
#include "../src/oauth/http/coroutine_token_read_http.hpp"

import openproof.client;
import openproof.consent;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;
import openproof.oauth;
import openproof.oauth.http.sender;
import openproof.session;

namespace {
namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace http = openproof::oauth::http;
namespace core = openproof::identity::core;
namespace idp = openproof::identity::provider;
namespace sess = openproof::session;
namespace cons = openproof::consent;
namespace client = openproof::client;
using namespace std::chrono_literals;
constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class Fallback final : public gw::http::CoroutineHttpHandler {
public:
    bool nativeEnabledFor(const gw::HttpRequest& request) const noexcept override {
        return request.path() == "/other";
    }
    gw::HttpResponse handle(gw::HttpRequest) override {
        ++syncCalls;
        return {500, {}, "sync"};
    }
    asio::awaitable<gw::HttpResponse> handleAsync(gw::HttpRequest request) override {
        ++asyncCalls;
        EXPECT_EQ(request.body(), "preserved");
        EXPECT_EQ(request.header("authorization"), "Bearer other-token");
        co_return gw::HttpResponse{202, {}, "native"};
    }
    int syncCalls{}, asyncCalls{};
};

gw::HttpRequest request(gw::HttpMethod method, std::string path,
                        std::string cookie = {}, std::string body = {},
                        std::string type = "application/x-www-form-urlencoded",
                        std::string bearer = {})
{
    std::vector<std::pair<std::string, std::string>> headers;
    if (!cookie.empty()) headers.emplace_back("cookie", std::move(cookie));
    if (!body.empty()) headers.emplace_back("content-type", std::move(type));
    if (!bearer.empty()) headers.emplace_back("authorization", "Bearer " + bearer);
    return gw::HttpRequest::create(method, std::move(path), std::move(headers),
        std::move(body), "127.0.0.1", fnd::CorrelationId{"native-consent-test"}).value();
}

struct Fixture {
    fnd::ManualClockSource clock{kNow};
    Fallback fallback;
    gw::TokenBucketRateLimiter limiter;
    http::CoroutineConsentAdapter api;
    int authenticationCalls{}, listCalls{}, revokeCalls{};
    bool foreign{}, unavailable{};
    std::string revokedId;
    explicit Fixture(double burst = 1000.0)
        : limiter(gw::TokenBucketRateLimiter::create(clock, burst, 1000.0, 1000U).value()),
          api(fallback, limiter, clock,
            [this](fnd::SecretString token) -> asio::awaitable<fnd::Result<sess::Session>> {
                ++authenticationCalls;
                if (token.expose() != "valid-token")
                    co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
                co_return sess::Session::create(sess::SessionId{"current"}, core::IdentityId{"owner"},
                    idp::ProviderId{"local"}, idp::AssuranceLevel::Ial1,
                    idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge, false},
                    kNow, sess::TokenDigest{openproof::security::sha256("fixture").value()},
                    kNow, 8h, 30min);
            },
            [this](core::IdentityId owner) -> asio::awaitable<fnd::Result<std::vector<cons::ConsentGrant>>> {
                ++listCalls;
                if (unavailable) co_return fnd::fail(fnd::ErrorCode::Unavailable);
                std::vector<cons::ConsentGrant> values;
                values.push_back(cons::ConsentGrant::create(cons::ConsentId{"grant-1"},
                    foreign ? core::IdentityId{"foreign-owner"} : owner, client::ClientId{"client"},
                    "urn:fixture", {"write", "read"}, kNow, kNow + 1h).value());
                co_return values;
            },
            [this](cons::ConsentId id, core::IdentityId owner, fnd::Instant now)
                -> asio::awaitable<fnd::Status> {
                ++revokeCalls;
                EXPECT_EQ(owner.value(), "owner");
                EXPECT_EQ(now, kNow);
                revokedId = std::string{id.value()};
                if (unavailable) co_return fnd::fail(fnd::ErrorCode::Unavailable);
                co_return fnd::ok();
            }) {}
    gw::HttpResponse run(gw::HttpRequest input) {
        asio::io_context io;
        std::optional<gw::HttpResponse> result;
        auto collect = [&]() -> asio::awaitable<void> {
            result.emplace(co_await api.handleAsync(std::move(input)));
        };
        auto completion = asio::co_spawn(io, collect(), asio::use_future);
        io.run();
        completion.get();
        return std::move(result).value();
    }
};

TEST(NativeOAuthTokenReadTest, ScopedUserInfoAndAuthenticatedIntrospectionNeverUseLegacy)
{
    namespace sec=openproof::security;
    namespace profile=openproof::identity::profile;
    fnd::ManualClockSource clock{kNow};
    Fallback fallback;
    auto limiter=gw::TokenBucketRateLimiter::create(clock,1000.0,1000.0,1000U).value();
    fnd::SecretString tokenKey{std::string(32U,'t')},clientKey{std::string(32U,'c')};
    const auto fingerprint=[&](std::string_view raw){return fnd::toHex(sec::hmacSha256(tokenKey,raw).value());};
    const auto valid=fingerprint("fixture-access"),restricted=fingerprint("fixture-restricted"),
        bound=fingerprint("fixture-bound"),unavailable=fingerprint("fixture-unavailable");
    const auto clientDigest=fnd::toHex(sec::hmacSha256(clientKey,"fixture-client-proof").value());
    int accessCalls=0,clientCalls=0,profileCalls=0,senderCalls=0,revokeCalls=0,rotateCalls=0;
    bool foreign=false;
    http::CoroutineTokenReadAdapter api{fallback,limiter,tokenKey.clone(),clientKey.clone(),
        [&](std::string digest,fnd::Instant* issued)->asio::awaitable<fnd::Result<sess::DelegatedAccess>> {
            ++accessCalls;
            if (digest==unavailable) co_return fnd::fail(fnd::ErrorCode::Unavailable);
            if (digest!=valid && digest!=restricted && digest!=bound)
                co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
            if (issued) *issued=kNow-10s;
            auto authenticated=sess::AuthenticatedSession::fromDelegatedAccess(
                core::IdentityId{"owner"},idp::ProviderId{"local"},idp::AssuranceLevel::Ial1,
                idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge,false},kNow-20s,kNow,kNow+60s);
            std::vector<std::string> scopes{"openid"};
            if (digest!=restricted) scopes.emplace_back("profile");
            std::optional<sess::DelegatedSenderConstraint> sender;
            if (digest==bound) sender.emplace(sess::DelegatedSenderConstraintKind::Dpop,"fixture-thumbprint");
            co_return sess::DelegatedAccess{std::move(authenticated).value(),"fixture-client",
                std::move(scopes),{"urn:fixture"},std::move(sender)};
        },
        [&](std::string id,std::string digest)->asio::awaitable<fnd::Status> {
            ++clientCalls;
            if (id!="fixture-client" || digest!=clientDigest)
                co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
            co_return fnd::ok();
        },
        [&](core::IdentityId owner)->asio::awaitable<fnd::Result<profile::IdentityProfile>> {
            ++profileCalls;
            if (foreign) owner=core::IdentityId{"foreign"};
            co_return profile::IdentityProfile::restore(std::move(owner),
                std::optional<std::string>{"Visible"},std::nullopt,
                std::optional<std::string>{"private@example.invalid"},true,
                std::nullopt,false,std::nullopt,std::nullopt,kNow,kNow,"auto");
        },
        [&](gw::HttpRequest&,sess::DelegatedSenderConstraint constraint,
            fnd::SecretString token,bool dpop)->asio::awaitable<fnd::Status> {
            ++senderCalls;
            if (!dpop || constraint.value()!="fixture-thumbprint" || token.expose()!="fixture-bound")
                co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
            co_return fnd::ok();
        },
        [&](std::string id,std::optional<std::string> proof,std::string digest)->asio::awaitable<fnd::Status> {
            ++revokeCalls;
            if ((id=="fixture-client" && proof!=clientDigest)
                || (id=="fixture-public" && proof)
                || (id!="fixture-client" && id!="fixture-public"))
                co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
            if (digest==unavailable) co_return fnd::fail(fnd::ErrorCode::Unavailable);
            EXPECT_EQ(digest.size(),64U);
            co_return fnd::ok();
        },
        [&](std::string id,std::optional<std::string> proof,std::string presented,
            std::string accessDigest,std::string refreshDigest,
            std::optional<sess::DelegatedSenderConstraint> sender)->asio::awaitable<fnd::Result<std::vector<std::string>>> {
            ++rotateCalls;
            if (id!="fixture-client" || proof!=clientDigest)
                co_return fnd::fail(fnd::ErrorCode::AuthenticationRequired);
            if (presented!=valid || sender) co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
            EXPECT_EQ(accessDigest.size(),64U);
            EXPECT_EQ(refreshDigest.size(),64U);
            EXPECT_NE(accessDigest,refreshDigest);
            co_return std::vector<std::string>{"openid","profile"};
        },
        [](gw::HttpRequest&)->asio::awaitable<fnd::Result<std::optional<openproof::token::SenderConstraint>>> {
            co_return std::optional<openproof::token::SenderConstraint>{};
        }};
    auto run=[&](gw::HttpRequest input) {
        asio::io_context io;
        std::optional<gw::HttpResponse> response;
        auto collect=[&]()->asio::awaitable<void>{response.emplace(co_await api.handleAsync(std::move(input)));};
        auto done=asio::co_spawn(io,collect(),asio::use_future);
        io.run(); done.get(); return std::move(response).value();
    };
    EXPECT_EQ(run(request(gw::HttpMethod::Get,"/oauth/userinfo")).status(),401);
    EXPECT_EQ(accessCalls,0);
    auto visible=run(request(gw::HttpMethod::Get,"/oauth/userinfo",{}, {},{},"fixture-access"));
    ASSERT_EQ(visible.status(),200);
    EXPECT_NE(visible.body().find("\"name\":\"Visible\""),std::string::npos);
    EXPECT_EQ(visible.body().find("private@example.invalid"),std::string::npos);
    EXPECT_EQ(visible.headers().at("cache-control"),"no-store");
    auto minimal=run(request(gw::HttpMethod::Get,"/oauth/userinfo",{}, {},{},"fixture-restricted"));
    EXPECT_EQ(minimal.body(),R"({"sub":"owner"})");
    EXPECT_EQ(profileCalls,1);
    foreign=true;
    EXPECT_EQ(run(request(gw::HttpMethod::Get,"/oauth/userinfo",{}, {},{},"fixture-access")).status(),503);
    foreign=false;
    EXPECT_EQ(run(request(gw::HttpMethod::Get,"/oauth/userinfo",{}, {},{},"fixture-bound")).status(),401);
    auto proof=gw::HttpRequest::create(gw::HttpMethod::Get,"/oauth/userinfo",
        {{"authorization","DPoP fixture-bound"}},{},"127.0.0.1",fnd::CorrelationId{"fixture"}).value();
    EXPECT_EQ(run(std::move(proof)).status(),200);
    EXPECT_EQ(senderCalls,2);
    auto inspect=[&](std::string proof,std::string token){
        return run(request(gw::HttpMethod::Post,"/oauth/introspect",{},
            "client_id=fixture-client&client_secret="+proof+"&token="+token));
    };
    const auto before=accessCalls;
    EXPECT_EQ(inspect("wrong","fixture-access").status(),401);
    EXPECT_EQ(accessCalls,before);
    auto active=inspect("fixture-client-proof","fixture-access");
    ASSERT_EQ(active.status(),200);
    EXPECT_NE(active.body().find("\"active\":true"),std::string::npos);
    EXPECT_NE(active.body().find("\"iat\":1769999990"),std::string::npos);
    EXPECT_NE(active.body().find("\"exp\":1770000060"),std::string::npos);
    EXPECT_EQ(inspect("fixture-client-proof","unknown").body(),R"({"active":false})");
    EXPECT_EQ(inspect("fixture-client-proof","fixture-unavailable").status(),503);
    EXPECT_EQ(run(request(gw::HttpMethod::Post,"/oauth/introspect",{},
        "client_id=fixture-client&client_secret=fixture-client-proof&token=a&token=b")).status(),400);
    EXPECT_EQ(clientCalls,4);
    auto revoke=[&](std::string form){
        return run(request(gw::HttpMethod::Post,"/oauth/revoke",{},std::move(form)));
    };
    auto publicRevocation=revoke("client_id=fixture-public&token=fixture-access");
    ASSERT_EQ(publicRevocation.status(),200);
    EXPECT_TRUE(publicRevocation.body().empty());
    EXPECT_EQ(publicRevocation.headers().at("cache-control"),"no-store");
    EXPECT_EQ(revoke("client_id=fixture-client&client_secret=fixture-client-proof&token=unknown").status(),200);
    EXPECT_EQ(revoke("client_id=fixture-client&client_secret=wrong&token=fixture-access").status(),401);
    EXPECT_EQ(revoke("client_id=fixture-public&client_secret=wrong&token=fixture-access").status(),401);
    EXPECT_EQ(revoke("client_id=fixture-public&token=fixture-unavailable").status(),503);
    EXPECT_EQ(revoke("client_id=fixture-public&token=a&token=b").status(),400);
    EXPECT_EQ(revokeCalls,5);
    auto rotate=[&](std::string form){
        auto input=request(gw::HttpMethod::Post,"/oauth/token",{},std::move(form));
        EXPECT_TRUE(api.nativeEnabledFor(input));
        return run(std::move(input));
    };
    auto rotated=rotate("grant_type=refresh%5Ftoken&client_id=fixture-client&client_secret=fixture-client-proof&refresh_token=fixture-access");
    ASSERT_EQ(rotated.status(),200);
    EXPECT_NE(rotated.body().find("\"access_token\":\"opa_"),std::string::npos);
    EXPECT_NE(rotated.body().find("\"refresh_token\":\"opr_"),std::string::npos);
    EXPECT_NE(rotated.body().find("\"expires_in\":900"),std::string::npos);
    EXPECT_EQ(rotate("grant_type=refresh_token&client_id=fixture-client&client_secret=wrong&refresh_token=fixture-access").status(),401);
    EXPECT_EQ(rotate("grant_type=refresh_token&client_id=fixture-client&client_secret=fixture-client-proof&refresh_token=unknown").status(),400);
    EXPECT_EQ(rotate("grant_type=refresh_token&grant_type=authorization_code&client_id=fixture-client&refresh_token=fixture-access").status(),400);
    EXPECT_EQ(rotateCalls,3);
    EXPECT_EQ(api.handle(request(gw::HttpMethod::Post,"/oauth/revoke",{},"client_id=fixture-public&token=fixture-access")).status(),503);
    EXPECT_EQ(api.handle(request(gw::HttpMethod::Get,"/oauth/userinfo")).status(),503);
    EXPECT_EQ(fallback.syncCalls,0);
    EXPECT_EQ(fallback.asyncCalls,0);
}

TEST(NativeOAuthTokenReadTest, DevicePollingReturnsProtocolStatesWithoutLeakingCredentials)
{
    namespace sec=openproof::security;
    namespace oauth=openproof::oauth;
    using State=oauth::NativeDevicePollState;
    fnd::ManualClockSource clock{kNow};
    Fallback fallback;
    auto limiter=gw::TokenBucketRateLimiter::create(clock,1000.0,1000.0,1000U).value();
    fnd::SecretString deviceKey{std::string(32U,'d')};
    const auto expected=fnd::toHex(sec::hmacSha256(deviceKey,"fixture-device").value());
    auto state=State::Pending;
    int calls=0;
    http::CoroutineTokenReadAdapter api{fallback,limiter,
        fnd::SecretString{std::string(32U,'t')},fnd::SecretString{std::string(32U,'c')},
        {},{},{},{},{},{},
        [](gw::HttpRequest&)->asio::awaitable<fnd::Result<std::optional<openproof::token::SenderConstraint>>> {
            co_return std::optional<openproof::token::SenderConstraint>{};
        },15min,std::nullopt,{},
        http::CoroutineTokenReadAdapter::DevicePollContext{deviceKey.clone(),
            [&](std::string clientId,std::optional<std::string> proof,std::string digest,
                std::string family,std::string access,std::string refresh,
                std::optional<sess::DelegatedSenderConstraint> sender)->asio::awaitable<fnd::Result<oauth::NativeDevicePollResult>> {
                ++calls;
                if (clientId!="fixture-client" || proof) co_return fnd::fail(fnd::ErrorCode::AuthenticationRequired);
                if (digest!=expected) co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
                EXPECT_FALSE(family.empty());
                EXPECT_EQ(access.size(),64U);
                EXPECT_EQ(refresh.size(),64U);
                EXPECT_NE(access,refresh);
                EXPECT_FALSE(sender);
                co_return oauth::NativeDevicePollResult{state,state==State::Issued
                    ?std::vector<std::string>{"account"}:std::vector<std::string>{}};
            }}};
    auto run=[&](std::string body){
        auto input=request(gw::HttpMethod::Post,"/oauth/token",{},std::move(body));
        EXPECT_TRUE(api.nativeEnabledFor(input));
        asio::io_context io;
        std::optional<gw::HttpResponse> response;
        auto collect=[&]()->asio::awaitable<void>{response.emplace(co_await api.handleAsync(std::move(input)));};
        auto done=asio::co_spawn(io,collect(),asio::use_future);
        io.run(); done.get(); return std::move(response).value();
    };
    const std::string form="grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=fixture-client&device_code=fixture-device";
    for (const auto& [next,code]:std::vector<std::pair<State,std::string_view>>{
        {State::Pending,"authorization_pending"},{State::SlowDown,"slow_down"},
        {State::Denied,"access_denied"},{State::Expired,"expired_token"}}) {
        state=next;
        const auto response=run(form);
        EXPECT_EQ(response.status(),400);
        EXPECT_NE(response.body().find(code),std::string::npos);
        EXPECT_EQ(response.body().find("access_token"),std::string::npos);
        EXPECT_EQ(response.body().find("fixture-device"),std::string::npos);
    }
    state=State::Issued;
    const auto accepted=run(form);
    EXPECT_EQ(accepted.status(),200);
    EXPECT_NE(accepted.body().find("opa_"),std::string::npos);
    EXPECT_NE(accepted.body().find("opr_"),std::string::npos);
    EXPECT_EQ(accepted.body().find("id_token"),std::string::npos);
    EXPECT_EQ(run(form+"&device_code=duplicate").status(),400);
    EXPECT_EQ(calls,5);
    EXPECT_EQ(fallback.syncCalls,0);
    EXPECT_EQ(fallback.asyncCalls,0);
}

TEST(NativeOAuthTokenReadTest, DeviceInitiationRetriesCollisionAndReturnsOnlyCommittedCodes)
{
    namespace sec=openproof::security;
    fnd::ManualClockSource clock{kNow};
    Fallback fallback;
    auto limiter=gw::TokenBucketRateLimiter::create(clock,1000.0,1000.0,1000U).value();
    fnd::SecretString deviceKey{std::string(32U,'d')};
    int calls=0;
    std::string acceptedDevice,acceptedUser;
    http::CoroutineTokenReadAdapter api{fallback,limiter,
        fnd::SecretString{std::string(32U,'t')},fnd::SecretString{std::string(32U,'c')},
        {},{},{},{},{},{},{},15min,std::nullopt,{},
        http::CoroutineTokenReadAdapter::DevicePollContext{deviceKey.clone(),{},
            [&](std::string client,std::optional<std::string> proof,std::string device,
                std::string user,std::vector<std::string> scopes,std::optional<std::string> resource)
                ->asio::awaitable<fnd::Status> {
                ++calls;
                if (client!="fixture-client" || proof) co_return fnd::fail(fnd::ErrorCode::AuthenticationRequired);
                if (scopes!=std::vector<std::string>{"account"}) co_return fnd::fail(fnd::ErrorCode::PermissionDenied);
                if (resource) co_return fnd::fail(fnd::ErrorCode::NotFound);
                EXPECT_EQ(device.size(),64U); EXPECT_EQ(user.size(),64U);
                EXPECT_NE(device,user);
                if (calls==1) co_return fnd::fail(fnd::ErrorCode::Conflict);
                acceptedDevice=std::move(device); acceptedUser=std::move(user);
                co_return fnd::ok();
            },"https://issuer.example.invalid/oauth/device"}};
    auto run=[&](std::string form){
        auto input=request(gw::HttpMethod::Post,"/oauth/device_authorization",{},std::move(form));
        EXPECT_TRUE(api.nativeEnabledFor(input));
        asio::io_context io;
        std::optional<gw::HttpResponse> response;
        auto collect=[&]()->asio::awaitable<void>{response.emplace(co_await api.handleAsync(std::move(input)));};
        auto done=asio::co_spawn(io,collect(),asio::use_future);
        io.run(); done.get(); return std::move(response).value();
    };
    const auto result=run("client_id=fixture-client&scope=account");
    ASSERT_EQ(result.status(),200);
    EXPECT_EQ(calls,2);
    const auto field=[&](std::string_view name){
        const std::string marker="\""+std::string{name}+"\":\"";
        const auto start=result.body().find(marker);
        if (start==std::string::npos) return std::string{};
        const auto pos=start+marker.size();
        return result.body().substr(pos,result.body().find('"',pos)-pos);
    };
    const auto device=field("device_code"),user=field("user_code");
    EXPECT_TRUE(device.starts_with("opd_"));
    ASSERT_EQ(user.size(),9U);
    EXPECT_EQ(user[4],'-');
    EXPECT_EQ(fnd::toHex(sec::hmacSha256(deviceKey,device).value()),acceptedDevice);
    EXPECT_EQ(fnd::toHex(sec::hmacSha256(deviceKey,user).value()),acceptedUser);
    EXPECT_EQ(field("verification_uri_complete"),"https://issuer.example.invalid/oauth/device?user_code="+user);
    EXPECT_EQ(result.headers().at("cache-control"),"no-store");
    EXPECT_EQ(run("client_id=wrong&scope=account").status(),401);
    EXPECT_EQ(run("client_id=fixture-client&scope=write").status(),400);
    EXPECT_EQ(run("client_id=fixture-client&scope=account&resource=unknown").status(),400);
    EXPECT_EQ(run("client_id=fixture-client&scope=account&scope=account").status(),400);
    EXPECT_EQ(calls,5);
    EXPECT_EQ(fallback.syncCalls,0);
    EXPECT_EQ(fallback.asyncCalls,0);
}

constexpr std::string_view sessionCookie = "__Host-openproof-session=valid-token";
constexpr std::string_view csrfCookies =
    "__Host-openproof-session=valid-token; __Host-openproof-consent-csrf=proof";

TEST(NativeConsentHttpTest, CookieOnlyListingAndCsrfResponse)
{
    Fixture f;
    auto missing = f.run(request(gw::HttpMethod::Get, "/oauth/consents", {}, {}, {}, "valid-token"));
    EXPECT_EQ(missing.status(), 401);
    EXPECT_EQ(f.authenticationCalls, 0);
    auto duplicate = f.run(request(gw::HttpMethod::Get, "/oauth/consents",
        std::string{sessionCookie} + "; __Host-openproof-session=valid-token"));
    EXPECT_EQ(duplicate.status(), 401);
    auto result = f.run(request(gw::HttpMethod::Get, "/oauth/consents?ignored=secret",
        std::string{sessionCookie}, "ignored", "text/plain"));
    ASSERT_EQ(result.status(), 200);
    EXPECT_EQ(result.headers().at("cache-control"), "no-store");
    EXPECT_FALSE(result.headers().contains("access-control-allow-origin"));
    const auto cookie = result.headers().at("set-cookie");
    EXPECT_TRUE(cookie.starts_with("__Host-openproof-consent-csrf="));
    EXPECT_TRUE(cookie.ends_with("; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Lax"));
    const auto begin = cookie.find('=') + 1U;
    const auto end = cookie.find(';', begin);
    const auto csrf = cookie.substr(begin, end - begin);
    EXPECT_FALSE(csrf.empty());
    EXPECT_TRUE(result.body().find("\"csrf\":\"" + csrf + "\"") != std::string_view::npos);
    EXPECT_TRUE(result.body().find("\"scope\":\"read write\"") != std::string_view::npos);
    EXPECT_TRUE(result.body().find("\"active\":true") != std::string_view::npos);
    EXPECT_EQ(f.listCalls, 1);
    f.foreign = true;
    auto denied = f.run(request(gw::HttpMethod::Get, "/oauth/consents", std::string{sessionCookie}));
    EXPECT_EQ(denied.status(), 503);
    EXPECT_EQ(denied.body().find("foreign-owner"), std::string_view::npos);
    EXPECT_FALSE(denied.headers().contains("set-cookie"));
}

TEST(NativeConsentHttpTest, MutationRequiresUniqueMatchingCsrfAndExactRoute)
{
    Fixture f;
    for (const auto& body : {"consent_id=grant-1&csrf=wrong",
            "consent_id=grant-1&csrf=proof&csrf=proof",
            "consent_id=grant-1&csrf=%00", "consent_id=grant-1"}) {
        EXPECT_NE(f.run(request(gw::HttpMethod::Post, "/oauth/consents/revoke",
            std::string{csrfCookies}, body)).status(), 204);
    }
    EXPECT_EQ(f.revokeCalls, 0);
    EXPECT_NE(f.run(request(gw::HttpMethod::Post, "/oauth/consents/revoke",
        std::string{csrfCookies}, "consent_id=grant-1&csrf=proof",
        "application/x-www-form-urlencoded-invalid")).status(), 204);
    EXPECT_EQ(f.revokeCalls, 0);
    auto valid = f.run(request(gw::HttpMethod::Post, "/oauth/consents/revoke",
        std::string{csrfCookies}, "consent_id=grant%2D1&csrf=proof"));
    EXPECT_EQ(valid.status(), 204);
    EXPECT_TRUE(valid.body().empty());
    EXPECT_EQ(valid.headers().at("set-cookie"),
        "__Host-openproof-consent-csrf=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax");
    EXPECT_EQ(f.revokedId, "grant-1");
    EXPECT_EQ(f.revokeCalls, 1);
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/oauth/consents/revoke",
        std::string{csrfCookies})).status(), 503);
    EXPECT_EQ(f.api.handle(request(gw::HttpMethod::Get, "/oauth/consents",
        std::string{sessionCookie})).status(), 503);
    EXPECT_EQ(f.run(request(gw::HttpMethod::Post, "/other", {}, "preserved",
        "text/plain", "other-token")).status(), 202);
    EXPECT_EQ(f.fallback.syncCalls, 0);
    EXPECT_EQ(f.fallback.asyncCalls, 1);
    EXPECT_EQ(f.revokeCalls, 1);
}

TEST(NativeConsentHttpTest, RateLimitAndStorageFailureNeverReportSuccess)
{
    Fixture f{1.0};
    f.unavailable = true;
    auto unavailable = f.run(request(gw::HttpMethod::Post, "/oauth/consents/revoke",
        std::string{csrfCookies}, "consent_id=grant-1&csrf=proof"));
    EXPECT_EQ(unavailable.status(), 503);
    EXPECT_FALSE(unavailable.headers().contains("set-cookie"));
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/oauth/consents",
        std::string{sessionCookie})).status(), 429);
    EXPECT_EQ(f.authenticationCalls, 1);
    EXPECT_EQ(f.revokeCalls, 1);
    EXPECT_EQ(f.listCalls, 0);

    // Both consent routes share the legacy OAuth IP bucket. Once it refills,
    // storage failure must still fail closed rather than report success.
    f.clock.advance(1ms);
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/oauth/consents",
        std::string{sessionCookie})).status(), 503);
    EXPECT_EQ(f.authenticationCalls, 2);
    EXPECT_EQ(f.revokeCalls, 1);
    EXPECT_EQ(f.listCalls, 1);
}
class LegacyReplayProbe final : public openproof::oauth::DpopReplayStore,
    public openproof::oauth::MtlsForwardingReplayStore {
public:
    fnd::Status consumeDpopReplay(std::string_view,std::string_view,fnd::Instant,fnd::Instant) override {
        ++calls; return fnd::fail(fnd::ErrorCode::Unavailable);
    }
    fnd::Status consumeMtlsForwardingReplay(std::string_view,std::string_view,fnd::Instant,fnd::Instant) override {
        ++calls; return fnd::fail(fnd::ErrorCode::Unavailable);
    }
    int calls{};
};

TEST(NativeSenderProofTest, MtlsProofBindsRequestAndUsesOnlyNativeReplay)
{
    LegacyReplayProbe legacy;
    fnd::ManualClockSource clock{kNow};
    openproof::oauth::DpopService dpop{legacy,clock,5min};
    const std::string key(32U,'k'),thumbprint(43U,'A');
    http::SenderProofVerifier verifier{dpop,legacy,clock,"https://issuer.example.test",
        fnd::SecretString{key}};
    const sess::DelegatedSenderConstraint binding{sess::DelegatedSenderConstraintKind::Mtls,thumbprint};
    const fnd::SecretString token{"fixture-access-token"};
    int writes=0;
    bool rejectReplay=false;
    http::SenderProofVerifier::ConsumeReplay consume=[&](sess::DelegatedSenderConstraintKind kind,
        std::string thumb,std::string nonce,fnd::Instant expires,fnd::Instant now)->asio::awaitable<fnd::Status>{
        ++writes;
        EXPECT_EQ(kind,sess::DelegatedSenderConstraintKind::Mtls);
        EXPECT_EQ(thumb,thumbprint);
        EXPECT_EQ(nonce,"fixture-nonce");
        EXPECT_EQ(expires,kNow+60s);
        EXPECT_EQ(now,kNow);
        if (rejectReplay) co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        co_return fnd::ok();
    };
    auto make=[&](std::string path,std::int64_t timestamp){
        const std::string stamp=std::to_string(timestamp);
        const std::string payload="GET\n/proxy?item=1\n"+thumbprint+"\n"+stamp+"\nfixture-nonce";
        const auto mac=openproof::security::hmacSha256(fnd::SecretString{key},payload).value();
        return gw::HttpRequest::create(gw::HttpMethod::Get,std::move(path),
            {{"x-forwarded-client-cert-sha256",thumbprint},{"x-forwarded-client-cert-timestamp",stamp},
             {"x-forwarded-client-cert-nonce","fixture-nonce"},
             {"x-forwarded-client-cert-signature",fnd::toBase64Url(mac)}},
             {},"127.0.0.1",fnd::CorrelationId{"native-mtls"}).value();
    };
    auto run=[&](gw::HttpRequest& input,const sess::DelegatedSenderConstraint& constraint,bool scheme=false){
        asio::io_context io;
        auto pending=verifier.verifyAsync(input,constraint,token,scheme,consume);
        auto done=asio::co_spawn(io,std::move(pending),asio::use_future);
        io.run();
        return done.get();
    };
    auto valid=make("/proxy?item=1",kNow.time_since_epoch().count());
    EXPECT_TRUE(run(valid,binding));
    EXPECT_FALSE(valid.header("x-forwarded-client-cert-signature"));
    EXPECT_EQ(writes,1);
    auto wrong=make("/proxy?item=2",kNow.time_since_epoch().count());
    EXPECT_FALSE(run(wrong,binding));
    auto wrongBinding=make("/proxy?item=1",kNow.time_since_epoch().count());
    EXPECT_FALSE(run(wrongBinding,sess::DelegatedSenderConstraint{sess::DelegatedSenderConstraintKind::Mtls,std::string(43U,'B')}));
    auto expired=make("/proxy?item=1",(kNow-60s).time_since_epoch().count());
    EXPECT_FALSE(run(expired,binding));
    auto wrongScheme=make("/proxy?item=1",kNow.time_since_epoch().count());
    EXPECT_FALSE(run(wrongScheme,binding,true));
    EXPECT_EQ(writes,1);
    rejectReplay=true;
    auto repeated=make("/proxy?item=1",kNow.time_since_epoch().count());
    EXPECT_FALSE(run(repeated,binding));
    EXPECT_EQ(writes,2);
    EXPECT_EQ(legacy.calls,0);
}

} // namespace
