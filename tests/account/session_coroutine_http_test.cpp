#include <gtest/gtest.h>

// GCC 16 module imports and Boost.Asio headers must share the same
// global-fragment declarations. The narrow header mix previously emitted
// duplicate internal-linkage execution CPOs (prefer/query/require).
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <boost/json.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_session_http.hpp"

import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.profile;
import openproof.identity.provider;
import openproof.session;
import openproof.security;

namespace {
namespace asio = boost::asio;
namespace json = boost::json;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace http = openproof::account::http;
namespace sess = openproof::session;
namespace idp = openproof::identity::provider;
namespace core = openproof::identity::core;
namespace profile = openproof::identity::profile;
namespace sec = openproof::security;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class LegacyHandler final : public gw::HttpHandler {
public:
    int invoked{};
    gw::HttpResponse handle(gw::HttpRequest) override
    {
        ++invoked;
        return gw::HttpResponse{299, {}, "legacy"};
    }
};

class NativeFallback final : public gw::http::CoroutineHttpHandler {
public:
    int invoked{};
    [[nodiscard]] bool nativeEnabled() const noexcept override { return true; }
    [[nodiscard]] bool nativeEnabledFor(
        const gw::HttpRequest& request) const noexcept override
    {
        return request.path() == "/other/api";
    }
    gw::HttpResponse handle(gw::HttpRequest) override
    {
        return gw::HttpResponse{299, {}, "fallback-legacy"};
    }
    asio::awaitable<gw::HttpResponse> handleAsync(gw::HttpRequest) override
    {
        ++invoked;
        co_return gw::HttpResponse{209, {}, "fallback-native"};
    }
};

[[nodiscard]] sess::Session validSession(
    std::string id, std::string identity = "identity-current")
{
    return sess::Session::create(
        sess::SessionId{std::move(id)},
        core::IdentityId{std::move(identity)}, idp::ProviderId{"local"},
        idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge, false},
        kNow, sess::TokenDigest{
            sec::sha256("test-not-a-real-token-digest").value()},
        kNow, std::chrono::hours{8}, std::chrono::minutes{30}).value();
}

asio::awaitable<std::optional<gw::HttpResponse>> dispatch(
    gw::http::CoroutineHttpHandler& api, gw::HttpRequest request)
{
    co_return std::optional<gw::HttpResponse>{
        co_await api.handleAsync(std::move(request))};
}

[[nodiscard]] gw::HttpRequest request(
    gw::HttpMethod method, std::string path, std::string token = {},
    std::string body = {}, std::string contentType = "application/json")
{
    std::vector<std::pair<std::string, std::string>> headers;
    if (!token.empty()) headers.emplace_back("authorization", "Bearer " + token);
    if (!body.empty()) headers.emplace_back("content-type", std::move(contentType));
    return gw::HttpRequest::create(method, std::move(path),
        std::move(headers), std::move(body), "127.0.0.1",
        fnd::CorrelationId{"account-coroutine-test"}).value();
}

[[nodiscard]] gw::HttpRequest profileCookieRequest(
    std::string token = "valid-token")
{
    return gw::HttpRequest::create(
        gw::HttpMethod::Get, "/account/profile",
        {{"cookie", "__Host-openproof-session=" + std::move(token)}}, {},
        "127.0.0.1", fnd::CorrelationId{"native-profile-cookie-test"}).value();
}

[[nodiscard]] gw::HttpRequest connectionsCookieRequest(
    std::string token = "valid-token")
{
    return gw::HttpRequest::create(
        gw::HttpMethod::Get, "/account/connections",
        {{"cookie", "__Host-openproof-session=" + std::move(token)}}, {},
        "127.0.0.1", fnd::CorrelationId{"native-connections-test"}).value();
}

struct Fixture final {
    explicit Fixture(bool profileEnabled = false,
                     bool connectionsEnabled = false,
                     bool totpStatusEnabled = false,
                     bool passwordStatusEnabled = false,
                     bool passwordConfirmEnabled = false)
        : limiter(gw::TokenBucketRateLimiter::create(
            clock, 1000.0, 1000.0, 1000U).value()),
          api(legacy, fallback, limiter,
              [this](fnd::SecretString token)
                  -> asio::awaitable<fnd::Result<sess::Session>> {
                  ++authenticationCalls;
                  if (token.expose() != "valid-token") {
                      co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
                  }
                  co_return validSession("current");
              },
              [this](core::IdentityId identity)
                  -> asio::awaitable<fnd::Result<std::vector<sess::Session>>> {
                  ++listCalls;
                  if (identity.value() != "identity-current") {
                      co_return fnd::fail(fnd::ErrorCode::PermissionDenied);
                  }
                  if (generatedSessionCount != 0U) {
                      std::vector<sess::Session> rows;
                      rows.reserve(generatedSessionCount);
                      for (std::size_t index = 0; index < generatedSessionCount; ++index) {
                          rows.emplace_back(validSession(
                              "oversize-session-" + std::to_string(index)));
                      }
                      co_return rows;
                  }
                  if (includeForeignSession) {
                      co_return std::vector<sess::Session>{
                          validSession("current"),
                          validSession("foreign-session-internal", "identity-foreign")};
                  }
                  co_return std::vector<sess::Session>{
                      validSession("current"), validSession("other")};
              },
              [this](core::IdentityId identity, sess::SessionId id)
                  -> asio::awaitable<fnd::Status> {
                  ++revokeCalls;
                  lastIdentity = std::string{identity.value()};
                  lastTarget = std::string{id.value()};
                  co_return fnd::ok();
              }, profileEnabled
                  ? http::CoroutineAccountSessionAdapter::ReadProfile{
                      [this](core::IdentityId owner)
                          -> asio::awaitable<fnd::Result<profile::IdentityProfile>> {
                          ++profileReadCalls;
                          if (owner.value() != "identity-current") {
                              co_return fnd::fail(fnd::ErrorCode::PermissionDenied);
                          }
                          if (profileMissing) {
                              co_return fnd::fail(fnd::ErrorCode::NotFound);
                          }
                          const auto resultOwner = profileForeign
                              ? core::IdentityId{"identity-foreign"} : owner;
                          co_return profile::IdentityProfile::restore(
                              resultOwner,
                              std::optional<std::string>{"Visible Account"},
                              std::optional<std::string>{"profile-user"},
                              std::optional<std::string>{"verified@example.invalid"},
                              true,
                              std::nullopt, false,
                              std::optional<std::string>{"en"},
                              std::nullopt, kNow, kNow, "auto");
                      }}
                  : http::CoroutineAccountSessionAdapter::ReadProfile{},
              connectionsEnabled
                  ? http::CoroutineAccountSessionAdapter::ReadConnections{
                      [this](core::IdentityId owner) -> asio::awaitable<
                          fnd::Result<http::CoroutineAccountSessionAdapter::ConnectionList>> {
                          ++connectionsReadCalls;
                          if (connectionsMissing)
                              co_return fnd::fail(fnd::ErrorCode::NotFound);
                          const auto resultOwner = connectionsForeign
                              ? core::IdentityId{"identity-foreign"} : owner;
                          std::vector<core::ExternalIdentityRef> values;
                          if (!connectionsEmpty) {
                              values.emplace_back(idp::ProviderId{"local"},
                                  idp::ExternalSubject{"verified@example.invalid"});
                              values.emplace_back(idp::ProviderId{"farcaster"},
                                  idp::ExternalSubject{"6841"},
                                  std::optional<std::string>{"Visible Farcaster"},
                                  std::nullopt, std::nullopt);
                          }
                          co_return http::CoroutineAccountSessionAdapter::ConnectionList{
                              resultOwner, std::move(values)};
                      }}
                  : http::CoroutineAccountSessionAdapter::ReadConnections{},
              totpStatusEnabled
                  ? http::CoroutineAccountSessionAdapter::ReadTotpStatus{
                      [this](core::IdentityId owner) -> asio::awaitable<
                          fnd::Result<http::CoroutineAccountSessionAdapter::TotpStatus>> {
                          ++totpStatusCalls;
                          if (totpMissing) co_return fnd::fail(fnd::ErrorCode::NotFound);
                          co_return http::CoroutineAccountSessionAdapter::TotpStatus{
                              totpForeign ? core::IdentityId{"identity-foreign"} : owner,
                              totpEnabled};
                      }}
                  : http::CoroutineAccountSessionAdapter::ReadTotpStatus{},
              passwordStatusEnabled
                  ? http::CoroutineAccountSessionAdapter::ReadPasswordUpgradeStatus{
                      [this](core::IdentityId owner) -> asio::awaitable<
                          fnd::Result<http::CoroutineAccountSessionAdapter::PasswordUpgradeStatus>> {
                          ++passwordStatusCalls;
                          if (passwordStatusMissing) co_return fnd::fail(fnd::ErrorCode::NotFound);
                          co_return http::CoroutineAccountSessionAdapter::PasswordUpgradeStatus{
                              passwordStatusForeign ? core::IdentityId{"identity-foreign"} : owner,
                              passwordStatus};
                      }}
                  : http::CoroutineAccountSessionAdapter::ReadPasswordUpgradeStatus{},
              passwordConfirmEnabled
                  ? http::CoroutineAccountSessionAdapter::ConfirmPasswordUpgrade{
                      [this](core::IdentityId owner, fnd::SecretString password) -> asio::awaitable<
                          fnd::Result<std::pair<core::IdentityId,bool>>> {
                          ++passwordConfirmCalls;
                          if (password.expose()!="fixture-password")
                              co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
                          co_return std::pair<core::IdentityId,bool>{
                              passwordStatusForeign ? core::IdentityId{"identity-foreign"} : owner,true};
                      }}
                  : http::CoroutineAccountSessionAdapter::ConfirmPasswordUpgrade{})
    {
    }

    gw::HttpResponse run(gw::HttpRequest input)
    {
        asio::io_context io;
        auto future = asio::co_spawn(io, dispatch(api, std::move(input)),
                                     asio::use_future);
        io.run();
        return std::move(future.get()).value();
    }

    fnd::ManualClockSource clock{kNow};
    LegacyHandler legacy;
    NativeFallback fallback;
    gw::TokenBucketRateLimiter limiter;
    int authenticationCalls{};
    int listCalls{};
    bool includeForeignSession{};
    std::size_t generatedSessionCount{};
    int revokeCalls{};
    int profileReadCalls{};
    int connectionsReadCalls{};
    int totpStatusCalls{};
    int passwordStatusCalls{};
    int passwordConfirmCalls{};
    bool passwordStatusForeign{};
    bool passwordStatusMissing{};
    std::optional<bool> passwordStatus{false};
    bool totpForeign{};
    bool totpMissing{};
    std::optional<bool> totpEnabled{false};
    bool connectionsForeign{};
    bool connectionsMissing{};
    bool connectionsEmpty{};
    bool profileForeign{};
    bool profileMissing{};
    std::string lastIdentity;
    std::string lastTarget;
    http::CoroutineAccountSessionAdapter api;
};

TEST(AccountCoroutineSessionHttpTest, ExplicitListenerOverlayRoutesSessionsWithoutLegacyIo)
{
    Fixture f;
    gw::http::CoroutineRouteOverlay overlay{
        f.legacy, f.api,
        {"/auth/ldap/start", "/auth/ldap/complete",
         "/account/sessions", "/account/sessions/revoke"}};
    EXPECT_TRUE(overlay.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/account/sessions")));
    EXPECT_TRUE(overlay.nativeEnabledFor(
        request(gw::HttpMethod::Post, "/account/sessions/revoke")));
    EXPECT_FALSE(overlay.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/account/sessions/other")));
    EXPECT_FALSE(overlay.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/account/profile")));
    // LDAP still needs its own native dependency graph, not this adapter.
    EXPECT_FALSE(overlay.nativeEnabledFor(
        request(gw::HttpMethod::Post, "/auth/ldap/start")));

    asio::io_context io;
    auto future = asio::co_spawn(io, dispatch(overlay,
        request(gw::HttpMethod::Get, "/account/sessions", "valid-token")),
        asio::use_future);
    io.run();
    auto response = std::move(future.get()).value();
    EXPECT_EQ(response.status(), 200);
    EXPECT_EQ(f.authenticationCalls, 1);
    EXPECT_EQ(f.listCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 0);

    // Native routes are fail-closed when entered through the sync facade;
    // unrelated compatibility routes preserve the legacy public contract.
    EXPECT_EQ(overlay.handle(request(
        gw::HttpMethod::Get, "/account/sessions", "valid-token")).status(), 503);
    EXPECT_EQ(f.legacy.invoked, 0);
    EXPECT_EQ(overlay.handle(request(
        gw::HttpMethod::Get, "/account/profile")).status(), 299);
    EXPECT_EQ(f.legacy.invoked, 1);
}

TEST(AccountCoroutineSessionHttpTest, RequestSpecificCapabilityAndNativeFallback)
{
    Fixture f;
    EXPECT_FALSE(f.api.nativeEnabled());
    EXPECT_TRUE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/account/sessions")));
    EXPECT_TRUE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Post, "/account/sessions/revoke")));
    EXPECT_FALSE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Post, "/account/sessions")));
    EXPECT_FALSE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/account/profile")));
    EXPECT_TRUE(f.api.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/other/api")));

    const auto response = f.run(request(gw::HttpMethod::Get, "/other/api"));
    EXPECT_EQ(response.status(), 209);
    EXPECT_EQ(f.fallback.invoked, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
    const auto unavailable = f.run(
        request(gw::HttpMethod::Get, "/account/profile"));
    EXPECT_EQ(unavailable.status(), 503);
    EXPECT_EQ(unavailable.headers().at("cache-control"), "no-store");
    EXPECT_EQ(f.legacy.invoked, 0);
}

TEST(AccountCoroutineSessionHttpTest, ListNativeSessionsPreservesExistingJson)
{
    Fixture f;
    const auto response = f.run(
        request(gw::HttpMethod::Get, "/account/sessions", "valid-token"));
    ASSERT_EQ(response.status(), 200) << response.body();
    const auto document = json::parse(response.body()).as_object();
    const auto& values = document.at("sessions").as_array();
    ASSERT_EQ(values.size(), 2U);
    EXPECT_TRUE(values[0].as_object().at("current").as_bool());
    EXPECT_FALSE(values[1].as_object().at("current").as_bool());
    EXPECT_EQ(values[0].as_object().at("provider").as_string(), "local");
    EXPECT_EQ(f.authenticationCalls, 1);
    EXPECT_EQ(f.listCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
    EXPECT_EQ(response.body().find("valid-token"), std::string::npos);
}

TEST(AccountCoroutineSessionHttpTest, ForeignIdentityRowsFailClosedBeforeSerialization)
{
    Fixture f;
    f.includeForeignSession = true;
    const auto response = f.run(request(
        gw::HttpMethod::Get, "/account/sessions", "valid-token"));
    EXPECT_EQ(response.status(), 503);
    EXPECT_EQ(response.body().find("foreign-session-internal"), std::string::npos);
    EXPECT_EQ(response.body().find("identity-foreign"), std::string::npos);
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
    EXPECT_EQ(f.listCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
}

TEST(AccountCoroutineSessionHttpTest, SessionListExactLimitAndOverflow)
{
    Fixture exact;
    exact.generatedSessionCount = 256U;
    const auto withinLimit = exact.run(request(
        gw::HttpMethod::Get, "/account/sessions", "valid-token"));
    ASSERT_EQ(withinLimit.status(), 200);
    EXPECT_EQ(json::parse(withinLimit.body()).as_object()
        .at("sessions").as_array().size(), 256U);
    EXPECT_EQ(exact.listCalls, 1);
    EXPECT_EQ(exact.legacy.invoked, 0);

    Fixture overflow;
    overflow.generatedSessionCount = 257U;
    const auto denied = overflow.run(request(
        gw::HttpMethod::Get, "/account/sessions", "valid-token"));
    EXPECT_EQ(denied.status(), 503);
    EXPECT_EQ(denied.body().find("oversize-session-"), std::string::npos);
    EXPECT_EQ(denied.headers().at("cache-control"), "no-store");
    EXPECT_EQ(overflow.listCalls, 1);
    EXPECT_EQ(overflow.legacy.invoked, 0);
}

TEST(AccountCoroutineSessionHttpTest, MissingAndInvalidBearerNeverEnumerate)
{
    Fixture f;
    const auto missing = f.run(request(
        gw::HttpMethod::Get, "/account/sessions"));
    EXPECT_EQ(missing.status(), 401);
    EXPECT_EQ(missing.headers().at("www-authenticate"), "Bearer");
    EXPECT_EQ(f.authenticationCalls, 0);
    const auto denied = f.run(request(
        gw::HttpMethod::Get, "/account/sessions", "invalid-token"));
    EXPECT_EQ(denied.status(), 401);
    EXPECT_EQ(denied.headers().at("www-authenticate"), "Bearer");
    EXPECT_EQ(f.listCalls, 0);
}

TEST(AccountCoroutineSessionHttpTest, RevokeRejectsLookalikeJsonMimeTypes)
{
    Fixture f;
    constexpr std::string_view body{R"({"session_id":"other"})"};
    for (const char* type : {
            "application/json-invalid", "application/jsonp",
            "application/json, application/json", "text/plain"}) {
        const auto response = f.run(request(
            gw::HttpMethod::Post, "/account/sessions/revoke", "valid-token",
            std::string{body}, type));
        EXPECT_EQ(response.status(), 400) << type;
        EXPECT_EQ(f.revokeCalls, 0) << type;
    }
    // MIME parameters are valid and remain compatible with JSON clients.
    const auto valid = f.run(request(
        gw::HttpMethod::Post, "/account/sessions/revoke", "valid-token",
        std::string{body}, "application/json; charset=utf-8"));
    EXPECT_EQ(valid.status(), 200);
    EXPECT_EQ(f.revokeCalls, 1);
}

TEST(AccountCoroutineSessionHttpTest, RevokeRejectsCurrentAndMalformedRequests)
{
    Fixture f;
    for (const char* body : {
        R"({"session_id":"current"})",
        R"({"session_id":"other","unrecognized":true})",
        R"({"session_id":""})"}) {
        const auto response = f.run(request(gw::HttpMethod::Post,
            "/account/sessions/revoke", "valid-token", body));
        EXPECT_TRUE(response.status() == 412 || response.status() == 400);
    }
    EXPECT_EQ(f.revokeCalls, 0);

    const auto response = f.run(request(gw::HttpMethod::Post,
        "/account/sessions/revoke", "valid-token",
        R"({"session_id":"other"})"));
    EXPECT_EQ(response.status(), 200);
    EXPECT_EQ(f.lastIdentity, "identity-current");
    EXPECT_EQ(f.lastTarget, "other");
    EXPECT_EQ(f.revokeCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
}


TEST(AccountCoroutineSessionHttpTest, ProfileReadRequiresExplicitNativeCapabilityAndSession)
{
    Fixture f{true};
    gw::http::CoroutineRouteOverlay overlay{
        f.legacy, f.api, {}, {{"/account/profile", gw::HttpMethod::Get}}};
    EXPECT_TRUE(overlay.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/account/profile")));
    EXPECT_FALSE(overlay.nativeEnabledFor(
        request(gw::HttpMethod::Patch, "/account/profile")));
    EXPECT_FALSE(overlay.nativeEnabledFor(
        request(gw::HttpMethod::Get, "/account/other")));
    const auto missing = f.run(request(
        gw::HttpMethod::Get, "/account/profile"));
    EXPECT_EQ(missing.status(), 401);
    EXPECT_EQ(missing.headers().at("www-authenticate"), "Bearer");
    EXPECT_EQ(f.profileReadCalls, 0);
    const auto invalid = f.run(profileCookieRequest("invalid-token"));
    EXPECT_EQ(invalid.status(), 401);
    EXPECT_EQ(invalid.headers().at("www-authenticate"), "Bearer");
    EXPECT_EQ(f.profileReadCalls, 0);
    EXPECT_EQ(f.legacy.invoked, 0);

    const auto response = f.run(profileCookieRequest());
    ASSERT_EQ(response.status(), 200) << response.body();
    const auto document = json::parse(response.body()).as_object();
    EXPECT_EQ(document.at("identity_id").as_string(), "identity-current");
    EXPECT_EQ(document.at("display_name").as_string(), "Visible Account");
    EXPECT_EQ(document.at("preferred_username").as_string(), "profile-user");
    EXPECT_EQ(document.at("email").as_string(), "verified@example.invalid");
    EXPECT_TRUE(document.at("email_verified").as_bool());
    EXPECT_FALSE(document.at("phone_number_verified").as_bool());
    EXPECT_EQ(document.at("locale").as_string(), "en");
    EXPECT_EQ(document.at("avatar_source").as_string(), "auto");
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
    EXPECT_EQ(response.body().find("valid-token"), std::string::npos);
    EXPECT_EQ(f.profileReadCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
    EXPECT_EQ(overlay.handle(profileCookieRequest()).status(), 503);
    // Delegated OAuth Bearer credentials are not native Session tokens.
    // They must retain the legacy authorization path, not be rejected by
    // the profile-only native cookie adapter.
    EXPECT_FALSE(overlay.nativeEnabledFor(request(
        gw::HttpMethod::Get, "/account/profile", "valid-token")));
    EXPECT_EQ(overlay.handle(request(
        gw::HttpMethod::Get, "/account/profile", "valid-token")).status(), 299);
    // The native GET overlay must preserve PATCH/PUT compatibility instead
    // of returning a 503 for profile mutations on the same URL.
    EXPECT_EQ(overlay.handle(request(
        gw::HttpMethod::Patch, "/account/profile", "valid-token")).status(), 299);
    EXPECT_EQ(overlay.handle(request(
        gw::HttpMethod::Put, "/account/profile", "valid-token")).status(), 299);
    EXPECT_EQ(f.legacy.invoked, 3);
}

TEST(AccountCoroutineSessionHttpTest, ProfileReadFailsClosedOnForeignOrMissingProfile)
{
    Fixture f{true};
    f.profileForeign = true;
    const auto foreign = f.run(profileCookieRequest());
    EXPECT_EQ(foreign.status(), 503);
    EXPECT_EQ(foreign.body().find("verified@example.invalid"), std::string::npos);
    EXPECT_EQ(foreign.body().find("identity-foreign"), std::string::npos);
    EXPECT_EQ(foreign.headers().at("cache-control"), "no-store");
    EXPECT_EQ(f.profileReadCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 0);
    f.profileForeign = false;
    f.profileMissing = true;
    const auto missing = f.run(profileCookieRequest());
    EXPECT_EQ(missing.status(), 404);
    EXPECT_EQ(missing.body().find("verified@example.invalid"), std::string::npos);
    EXPECT_EQ(f.profileReadCalls, 2);
}

TEST(AccountCoroutineSessionHttpTest, ConnectionsReadIsCookieOnlyAndPreservesLegacyBearer)
{
    Fixture f{false, true};
    gw::http::CoroutineRouteOverlay overlay{
        f.legacy, f.api, {}, {{"/account/connections", gw::HttpMethod::Get}}};
    EXPECT_TRUE(overlay.nativeEnabledFor(connectionsCookieRequest()));
    EXPECT_FALSE(overlay.nativeEnabledFor(request(
        gw::HttpMethod::Get, "/account/connections", "delegated-oauth")));
    EXPECT_FALSE(overlay.nativeEnabledFor(request(
        gw::HttpMethod::Post, "/account/connections")));
    EXPECT_EQ(overlay.handle(request(
        gw::HttpMethod::Get, "/account/connections", "delegated-oauth")).status(), 299);
    EXPECT_EQ(overlay.handle(request(
        gw::HttpMethod::Post, "/account/connections")).status(), 299);
    EXPECT_EQ(overlay.handle(connectionsCookieRequest()).status(), 503);
    EXPECT_EQ(f.legacy.invoked, 2);

    const auto noCredential = f.run(request(
        gw::HttpMethod::Get, "/account/connections"));
    EXPECT_EQ(noCredential.status(), 401);
    EXPECT_EQ(noCredential.headers().at("www-authenticate"), "Bearer");
    EXPECT_EQ(f.connectionsReadCalls, 0);
    const auto invalid = f.run(connectionsCookieRequest("invalid-token"));
    EXPECT_EQ(invalid.status(), 401);
    EXPECT_EQ(f.connectionsReadCalls, 0);

    const auto allowed = f.run(connectionsCookieRequest());
    ASSERT_EQ(allowed.status(), 200) << allowed.body();
    const auto document = json::parse(allowed.body());
    const auto& values = document.as_object().at("connections").as_array();
    ASSERT_EQ(values.size(), 2U);
    EXPECT_EQ(values[0].as_object().at("provider").as_string(), "local");
    EXPECT_EQ(values[1].as_object().at("fid").as_string(), "6841");
    EXPECT_EQ(values[1].as_object().at("profile_url").as_string(),
        "https://farcaster.xyz/~/profiles/6841");
    EXPECT_EQ(allowed.headers().at("cache-control"), "no-store");
    EXPECT_EQ(allowed.body().find("valid-token"), std::string::npos);
    EXPECT_EQ(f.connectionsReadCalls, 1);
    EXPECT_EQ(f.legacy.invoked, 2);
}

TEST(AccountCoroutineSessionHttpTest, ConnectionsReadRejectsForeignAndMissingWithoutDisclosure)
{
    Fixture f{false, true};
    f.connectionsForeign = true;
    const auto denied = f.run(connectionsCookieRequest());
    EXPECT_EQ(denied.status(), 503);
    EXPECT_EQ(denied.body().find("verified@example.invalid"), std::string::npos);
    EXPECT_EQ(denied.body().find("identity-foreign"), std::string::npos);
    f.connectionsForeign = false;
    f.connectionsEmpty = true;
    const auto empty = f.run(connectionsCookieRequest());
    ASSERT_EQ(empty.status(), 200);
    EXPECT_TRUE(json::parse(empty.body()).as_object().at("connections")
        .as_array().empty());
    f.connectionsMissing = true;
    EXPECT_EQ(f.run(connectionsCookieRequest()).status(), 404);
    EXPECT_EQ(f.legacy.invoked, 0);
}

[[nodiscard]] gw::HttpRequest totpCookieRequest(std::string token = "valid-token")
{
    return gw::HttpRequest::create(gw::HttpMethod::Get, "/account/totp",
        {{"cookie", "__Host-openproof-session=" + std::move(token)}}, {},
        "127.0.0.1", fnd::CorrelationId{"native-totp-status-test"}).value();
}

TEST(AccountCoroutineSessionHttpTest, TotpStatusIsOptInCookieOnlyAndOwnerBound)
{
    Fixture off;
    EXPECT_FALSE(off.api.nativeEnabledFor(totpCookieRequest()));
    Fixture f{false, false, true};
    gw::http::CoroutineRouteOverlay overlay{f.legacy, f.api, {},
        {{"/account/totp", gw::HttpMethod::Get}}};
    EXPECT_TRUE(overlay.nativeEnabledFor(totpCookieRequest()));
    EXPECT_FALSE(overlay.nativeEnabledFor(request(gw::HttpMethod::Get,
        "/account/totp", "delegated-oauth")));
    EXPECT_FALSE(overlay.nativeEnabledFor(request(gw::HttpMethod::Post, "/account/totp/start")));
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/account/totp")).status(), 401);
    EXPECT_EQ(f.run(totpCookieRequest("invalid-token")).status(), 401);
    EXPECT_EQ(f.totpStatusCalls, 0);
    for (const auto enrolled : {std::optional<bool>{}, std::optional<bool>{false},
                                std::optional<bool>{true}}) {
        f.totpEnabled = enrolled;
        const auto result = f.run(totpCookieRequest());
        ASSERT_EQ(result.status(), 200);
        const auto body = json::parse(result.body()).as_object();
        EXPECT_EQ(body.size(), 3U);
        EXPECT_EQ(body.at("available").as_bool(), enrolled.has_value());
        EXPECT_EQ(body.at("enabled").as_bool(), enrolled.value_or(false));
        EXPECT_EQ(body.at("assurance").as_string(), "ial1");
        EXPECT_EQ(result.headers().at("cache-control"), "no-store");
    }
    f.totpForeign = true;
    EXPECT_EQ(f.run(totpCookieRequest()).status(), 503);
    f.totpForeign = false;
    f.totpMissing = true;
    EXPECT_EQ(f.run(totpCookieRequest()).status(), 404);
    EXPECT_EQ(f.legacy.invoked, 0);
}

TEST(AccountCoroutineSessionHttpTest, PasswordUpgradeStatusIsCookieOnlyReadAndOwnerBound)
{
    auto cookieRequest = [](std::string token = "valid-token") {
        return gw::HttpRequest::create(
            gw::HttpMethod::Get, "/account/password/upgrade",
            {{"cookie", "__Host-openproof-session=" + std::move(token)}}, {},
            "127.0.0.1", fnd::CorrelationId{"native-password-status-test"}).value();
    };
    Fixture disabled;
    EXPECT_FALSE(disabled.api.nativeEnabledFor(cookieRequest()));
    Fixture f{false, false, false, true};
    gw::http::CoroutineRouteOverlay overlay{f.legacy, f.api, {},
        {{"/account/password/upgrade", gw::HttpMethod::Get}}};
    EXPECT_TRUE(overlay.nativeEnabledFor(cookieRequest()));
    EXPECT_FALSE(overlay.nativeEnabledFor(request(gw::HttpMethod::Get,
        "/account/password/upgrade", "delegated-oauth")));
    EXPECT_FALSE(overlay.nativeEnabledFor(request(gw::HttpMethod::Post,
        "/account/password/upgrade")));
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/account/password/upgrade")).status(), 401);
    EXPECT_EQ(f.run(cookieRequest("invalid-token")).status(), 401);
    EXPECT_EQ(f.passwordStatusCalls, 0);
    for (const auto status : {std::optional<bool>{}, std::optional<bool>{false},
                              std::optional<bool>{true}}) {
        f.passwordStatus = status;
        const auto result = f.run(cookieRequest());
        ASSERT_EQ(result.status(), 200);
        const auto body = json::parse(result.body()).as_object();
        EXPECT_EQ(body.size(), 3U);
        EXPECT_EQ(body.at("available").as_bool(), status.has_value());
        EXPECT_EQ(body.at("needs_upgrade").as_bool(), status.value_or(false));
        EXPECT_EQ(body.at("target_algorithm").as_string(), "argon2id");
        EXPECT_EQ(result.headers().at("cache-control"), "no-store");
    }
    f.passwordStatusForeign = true;
    EXPECT_EQ(f.run(cookieRequest()).status(), 503);
    f.passwordStatusForeign = false;
    f.passwordStatusMissing = true;
    EXPECT_EQ(f.run(cookieRequest()).status(), 404);
    EXPECT_EQ(f.legacy.invoked, 0);
}

TEST(AccountCoroutineSessionHttpTest, PasswordUpgradeConfirmRequiresOriginSessionAndStrictBody)
{
    auto post = [](std::string origin, std::string token, std::string body,
                   std::string site = "same-origin", std::string contentType = "application/json") {
        return gw::HttpRequest::create(gw::HttpMethod::Post, "/account/password/upgrade",
            {{"cookie", "__Host-openproof-session=" + std::move(token)},
             {"host", "example.invalid"}, {"origin", std::move(origin)},
             {"sec-fetch-site", std::move(site)}, {"content-type", std::move(contentType)}},
            std::move(body),"127.0.0.1",fnd::CorrelationId{"password-confirm-test"}).value();
    };
    constexpr auto origin="https://example.invalid";
    constexpr auto valid=R"({"password":"fixture-password"})";
    Fixture off;
    EXPECT_FALSE(off.api.nativeEnabledFor(post(origin,"valid-token",valid)));
    Fixture f{false,false,false,true,true};
    gw::http::CoroutineRouteOverlay overlay{f.legacy,f.api,{},
        {{"/account/password/upgrade",gw::HttpMethod::Post}}};
    EXPECT_TRUE(overlay.nativeEnabledFor(post(origin,"valid-token",valid)));
    EXPECT_FALSE(overlay.nativeEnabledFor(request(gw::HttpMethod::Post,
        "/account/password/upgrade","delegated-oauth",valid)));
    EXPECT_EQ(f.run(post("https://foreign.invalid","valid-token",valid)).status(),403);
    EXPECT_EQ(f.run(post(origin,"valid-token",valid,"cross-site")).status(),403);
    EXPECT_EQ(f.run(post(origin,"invalid-token",valid)).status(),401);
    EXPECT_EQ(f.run(post(origin,"valid-token",R"({"password":"fixture-password","owner":"foreign"})")).status(),400);
    EXPECT_EQ(f.run(post(origin,"valid-token",valid,"same-origin","application/jsonp")).status(),400);
    EXPECT_EQ(f.passwordConfirmCalls,0);
    EXPECT_EQ(f.run(post(origin,"valid-token",R"({"password":"wrong"})")).status(),401);
    const auto success=f.run(post(origin,"valid-token",valid));
    ASSERT_EQ(success.status(),200);
    const auto body=json::parse(success.body()).as_object();
    EXPECT_TRUE(body.at("upgraded").as_bool());
    EXPECT_FALSE(body.at("needs_upgrade").as_bool());
    EXPECT_EQ(success.headers().at("cache-control"),"no-store");
    f.passwordStatusForeign=true;
    EXPECT_EQ(f.run(post(origin,"valid-token",valid)).status(),503);
    EXPECT_EQ(f.legacy.invoked,0);
}

} // namespace
