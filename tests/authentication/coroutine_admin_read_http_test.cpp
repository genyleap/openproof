#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <chrono>
#include <future>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "coroutine_admin_read_http.hpp"

import openproof.administration;
import openproof.foundation;
import openproof.gateway;
import openproof.gateway.http;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;
import openproof.security;
import openproof.session;

namespace {
namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace core = openproof::identity::core;
namespace idp = openproof::identity::provider;
namespace org = openproof::organization;
namespace adm = openproof::administration;
namespace ses = openproof::session;
namespace sec = openproof::security;
constexpr fnd::Instant now{std::chrono::milliseconds{1770000000000}};

struct Fallback final : gw::http::CoroutineHttpHandler {
    bool nativeEnabled() const noexcept override { return false; }
    bool nativeEnabledFor(const gw::HttpRequest& r) const noexcept override {
        return r.path() == "/auth/logout";
    }
    gw::HttpResponse handle(gw::HttpRequest) override {
        ++sync; return gw::HttpResponse{500, {}, {}};
    }
    asio::awaitable<gw::HttpResponse> handleAsync(gw::HttpRequest) override {
        ++async; co_return gw::HttpResponse{204, {}, {}};
    }
    int sync{}, async{};
};
gw::HttpRequest request(gw::HttpMethod method, std::string path, std::string token = {}) {
    std::vector<std::pair<std::string, std::string>> headers;
    if (!token.empty()) headers.emplace_back("cookie", "__Host-openproof-session=" + token);
    return gw::HttpRequest::create(method, std::move(path), std::move(headers), {},
        "127.0.0.1", fnd::CorrelationId{"admin-read-test"}).value();
}
asio::awaitable<std::optional<gw::HttpResponse>> dispatch(
    adm::http::CoroutineAdministrationReadAdapter& api, gw::HttpRequest request) {
    co_return std::optional<gw::HttpResponse>{
        co_await api.handleAsync(std::move(request))};
}
struct Fixture final {
    fnd::ManualClockSource clock{now};
    gw::TokenBucketRateLimiter limiter{
        gw::TokenBucketRateLimiter::create(clock, 100.0, 100.0, 256U).value()};
    Fallback fallback;
    bool strong{true}, denied{}, foreign{}, missingOwner{};
    int reads{};
    adm::http::CoroutineAdministrationReadAdapter api{fallback, limiter,
        [this](fnd::SecretString bearer) -> asio::awaitable<fnd::Result<ses::Session>> {
            if (bearer.expose() != "valid")
                co_return fnd::fail(fnd::ErrorCode::AuthenticationRequired);
            co_return ses::Session::create(ses::SessionId{"admin-read"},
                core::IdentityId{"actor"}, idp::ProviderId{"local"},
                strong ? idp::AssuranceLevel::Ial2 : idp::AssuranceLevel::Ial1,
                idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge
                    | idp::AuthenticationFactor::Possession, false},
                now, ses::TokenDigest{sec::sha256("fixture-token").value()},
                now, std::chrono::hours{1}, std::chrono::minutes{10});
        },
        [this](core::IdentityId actor) -> asio::awaitable<fnd::Result<adm::MemberListing>> {
            ++reads;
            if (denied) co_return fnd::fail(fnd::ErrorCode::PermissionDenied);
            co_return adm::MemberListing{foreign ? core::IdentityId{"foreign"} : actor,
                {{actor, core::IdentityStatus::Active, org::MembershipState::Active,
                    {org::Role{missingOwner ? "member" : "owner"}}},
                 {core::IdentityId{"other"}, core::IdentityStatus::Locked,
                    org::MembershipState::Suspended, {org::Role{"viewer"}}}}};
        }};
    gw::HttpResponse run(gw::HttpRequest input) {
        asio::io_context io;
        auto done = asio::co_spawn(io, dispatch(api, std::move(input)), asio::use_future);
        io.run();
        return std::move(done.get()).value();
    }
};
TEST(NativeAdministrationReadTest, Ial2AndOwnerAreRequiredBeforeSerialization) {
    Fixture f;
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/admin/local-members")).status(), 401);
    f.strong = false;
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/admin/local-members", "valid")).status(), 403);
    EXPECT_EQ(f.reads, 0);
    f.strong = true; f.denied = true;
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/admin/local-members", "valid")).status(), 403);
    f.denied = false; f.foreign = true;
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/admin/local-members", "valid")).status(), 503);
    f.foreign = false; f.missingOwner = true;
    EXPECT_EQ(f.run(request(gw::HttpMethod::Get, "/admin/local-members", "valid")).status(), 503);
    f.missingOwner = false;
    const auto response = f.run(request(gw::HttpMethod::Get, "/admin/local-members", "valid"));
    ASSERT_EQ(response.status(), 200);
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
    const auto document = boost::json::parse(response.body());
    const auto& members = document.as_object().at("members").as_array();
    ASSERT_EQ(members.size(), 2U);
    EXPECT_EQ(members[0].as_object().at("roles").as_array()[0].as_string(), "owner");
    EXPECT_EQ(members[1].as_object().at("identity_status").as_string(), "locked");
    EXPECT_EQ(members[1].as_object().at("membership_state").as_string(), "suspended");
}
TEST(NativeAdministrationReadTest, OnlyGetIsNativeAndOtherCapabilityPreserved) {
    Fixture f;
    EXPECT_TRUE(f.api.nativeEnabledFor(request(gw::HttpMethod::Get, "/admin/local-members")));
    EXPECT_FALSE(f.api.nativeEnabledFor(request(gw::HttpMethod::Post, "/admin/local-members")));
    EXPECT_EQ(f.run(request(gw::HttpMethod::Post, "/admin/local-members", "valid")).status(), 503);
    EXPECT_EQ(f.run(request(gw::HttpMethod::Post, "/auth/logout", "valid")).status(), 204);
    EXPECT_EQ(f.api.handle(request(gw::HttpMethod::Get, "/admin/local-members", "valid")).status(), 503);
    EXPECT_EQ(f.fallback.sync, 0);
    EXPECT_EQ(f.fallback.async, 1);
    EXPECT_EQ(f.reads, 0);
}
} // namespace
