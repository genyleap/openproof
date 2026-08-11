#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <boost/json.hpp>

import openproof.administration;
import openproof.administration.http;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;
import openproof.security;
import openproof.session;

namespace {

namespace admin = openproof::administration;
namespace adminHttp = openproof::administration::http;
namespace core = openproof::identity::core;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace idp = openproof::identity::provider;
namespace org = openproof::organization;
namespace sec = openproof::security;
namespace sess = openproof::session;
namespace json = boost::json;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};
constexpr std::string_view kSessionKey =
    "0123456789abcdef0123456789abcdef";

class Fallback final : public gw::HttpHandler {
public:
    [[nodiscard]] gw::HttpResponse handle(gw::HttpRequest) override
    {
        return gw::HttpResponse{418, {}, "fallback"};
    }
};

class RecordingProvisioner final : public admin::LocalMemberAdministrator {
public:
    [[nodiscard]] fnd::Status provision(
        const core::IdentityId& actor,
        const admin::LocalMemberEnrollment& enrollment) override
    {
        called = true;
        actorId = std::string{actor.value()};
        identityId = std::string{enrollment.identity().id().value()};
        password = std::string{enrollment.generatedPassword().expose()};
        totpBase32 = std::string{
            enrollment.generatedTotp().enrollmentBase32().expose()};
        roles.clear();
        for (const org::Role& role : enrollment.membership().roles()) {
            roles.emplace_back(role.value());
        }
        if (failure.has_value()) {
            return fnd::fail(*failure, "provisioning refused");
        }
        return fnd::ok();
    }

    [[nodiscard]] fnd::Status replaceRoles(
        const core::IdentityId& actor,
        const admin::MemberRoleReplacement& replacement) override
    {
        called = true;
        operation = "roles";
        actorId = std::string{actor.value()};
        identityId = std::string{replacement.identityId().value()};
        roles.clear();
        for (const org::Role& role : replacement.roles()) {
            roles.emplace_back(role.value());
        }
        return result();
    }

    [[nodiscard]] fnd::Status changeLifecycle(
        const core::IdentityId& actor,
        const admin::MemberLifecycleChange& change) override
    {
        called = true;
        operation = std::string{admin::memberLifecycleActionName(change.action())};
        actorId = std::string{actor.value()};
        identityId = std::string{change.identityId().value()};
        return result();
    }

    [[nodiscard]] fnd::Status resetCredentials(
        const core::IdentityId& actor,
        const admin::LocalCredentialReset& reset) override
    {
        called = true;
        operation = "reset";
        actorId = std::string{actor.value()};
        identityId = std::string{reset.identityId().value()};
        password = std::string{reset.generatedPassword().expose()};
        totpBase32 = std::string{
            reset.generatedTotp().enrollmentBase32().expose()};
        return result();
    }

private:
    [[nodiscard]] fnd::Status result() const
    {
        return failure.has_value()
            ? fnd::Status{fnd::fail(*failure, "administration refused")}
            : fnd::ok();
    }

public:

    bool called{false};
    std::optional<fnd::ErrorCode> failure;
    std::string operation;
    std::string actorId;
    std::string identityId;
    std::string password;
    std::string totpBase32;
    std::vector<std::string> roles;
};

[[nodiscard]] gw::HttpRequest request(
    std::string path, std::string body = {}, std::string token = {},
    gw::HttpMethod method = gw::HttpMethod::Post)
{
    std::vector<std::pair<std::string, std::string>> headers;
    if (!body.empty()) headers.emplace_back("content-type", "application/json");
    if (!token.empty()) {
        headers.emplace_back("authorization", "Bearer " + std::move(token));
    }
    return gw::HttpRequest::create(
        method, std::move(path), std::move(headers),
        std::move(body), "127.0.0.1", fnd::CorrelationId{"request"}).value();
}

struct Fixture {
    Fixture()
        : clock(kNow),
          sessions(repository, clock,
              sess::SessionKey::create(
                  fnd::SecretString{std::string{kSessionKey}}).value(),
              sess::SessionPolicy::create(std::chrono::hours{8},
                                          std::chrono::minutes{30}).value()),
          limiter(gw::TokenBucketRateLimiter::create(
              clock, 1000.0, 1000.0, 1000U).value()),
          api(sessions, provisioner, limiter, core::OrganizationId{"org"},
              idp::ProviderId{"local"}, clock, fallback)
    {
    }

    void addSession(std::string_view token, idp::AssuranceLevel assurance,
                    std::string_view identity = "owner")
    {
        auto digest = sec::hmacSha256(
            fnd::SecretString{std::string{kSessionKey}}, token).value();
        auto session = sess::Session::create(
            sess::SessionId{"session-" + std::string{identity}},
            core::IdentityId{std::string{identity}}, idp::ProviderId{"local"},
            assurance,
            idp::AuthenticationStrength{
                assurance == idp::AssuranceLevel::Ial2
                    ? idp::AuthenticationFactor::Knowledge
                        | idp::AuthenticationFactor::Possession
                    : idp::AuthenticationFactor::Knowledge,
                false},
            kNow, sess::TokenDigest{digest}, kNow, std::chrono::hours{8},
            std::chrono::minutes{30}).value();
        ASSERT_TRUE(repository.add(std::move(session)));
    }

    fnd::ManualClockSource clock;
    sess::InMemorySessionRepository repository;
    sess::SessionService sessions;
    RecordingProvisioner provisioner;
    gw::TokenBucketRateLimiter limiter;
    Fallback fallback;
    adminHttp::AdministrationHttpApi api;
};

constexpr std::string_view kValidBody =
    R"({"identity_id":"identity-2","subject":"bob@example.test","roles":["viewer","member"]})";

TEST(AdministrationHttpApiTest, RequiresAnIal2SessionBeforeProvisioning)
{
    Fixture fixture;
    EXPECT_EQ(fixture.api.handle(request(
                  "/admin/local-members", std::string{kValidBody})).status(),
              401);
    EXPECT_FALSE(fixture.provisioner.called);

    fixture.addSession("ial1-token", idp::AssuranceLevel::Ial1);
    EXPECT_EQ(fixture.api.handle(request(
                  "/admin/local-members", std::string{kValidBody},
                  "ial1-token")).status(),
              403);
    EXPECT_FALSE(fixture.provisioner.called);
}

TEST(AdministrationHttpApiTest, GeneratesCredentialsAndReturnsThemOnlyAfterSuccess)
{
    Fixture fixture;
    fixture.addSession("owner-token", idp::AssuranceLevel::Ial2);
    const auto response = fixture.api.handle(request(
        "/admin/local-members", std::string{kValidBody}, "owner-token"));

    ASSERT_EQ(response.status(), 201) << response.body();
    ASSERT_TRUE(fixture.provisioner.called);
    EXPECT_EQ(fixture.provisioner.actorId, "owner");
    EXPECT_EQ(fixture.provisioner.identityId, "identity-2");
    EXPECT_EQ(fixture.provisioner.roles,
              (std::vector<std::string>{"member", "viewer"}));
    EXPECT_GE(fixture.provisioner.password.size(), 43U);
    EXPECT_EQ(fixture.provisioner.totpBase32.size(), 32U);
    const json::object body = json::parse(response.body()).as_object();
    EXPECT_EQ(std::string{body.at("initial_password").as_string()},
              fixture.provisioner.password);
    EXPECT_EQ(std::string{body.at("totp_secret_base32").as_string()},
              fixture.provisioner.totpBase32);
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
}

TEST(AdministrationHttpApiTest, DoesNotReturnGeneratedSecretsWhenOwnerCheckFails)
{
    Fixture fixture;
    fixture.addSession("member-token", idp::AssuranceLevel::Ial2, "member");
    fixture.provisioner.failure = fnd::ErrorCode::PermissionDenied;
    const auto response = fixture.api.handle(request(
        "/admin/local-members", std::string{kValidBody}, "member-token"));

    EXPECT_EQ(response.status(), 403);
    EXPECT_TRUE(fixture.provisioner.called);
    EXPECT_EQ(response.body().find("initial_password"), std::string::npos);
    EXPECT_EQ(response.body().find("totp_secret"), std::string::npos);
}

TEST(AdministrationHttpApiTest, RejectsUnknownFieldsAndReservesAdminNamespace)
{
    Fixture fixture;
    fixture.addSession("owner-token", idp::AssuranceLevel::Ial2);
    const auto malformed = fixture.api.handle(request(
        "/admin/local-members",
        R"({"identity_id":"identity-2","subject":"bob","roles":["member"],"password":"chosen"})",
        "owner-token"));
    EXPECT_EQ(malformed.status(), 400);
    EXPECT_FALSE(fixture.provisioner.called);
    EXPECT_EQ(fixture.api.handle(request(
                  "/admin/unknown", {}, "owner-token")).status(),
              404);
    EXPECT_EQ(fixture.api.handle(request("/outside")).status(), 418);
}

TEST(AdministrationHttpApiTest, ReplacesRolesThroughTheExplicitPutRoute)
{
    Fixture fixture;
    fixture.addSession("owner-token", idp::AssuranceLevel::Ial2);
    const auto response = fixture.api.handle(request(
        "/admin/local-members/roles",
        R"({"identity_id":"identity-2","roles":["viewer","member"]})",
        "owner-token", gw::HttpMethod::Put));

    EXPECT_EQ(response.status(), 204) << response.body();
    EXPECT_EQ(fixture.provisioner.operation, "roles");
    EXPECT_EQ(fixture.provisioner.identityId, "identity-2");
    EXPECT_EQ(fixture.provisioner.roles,
              (std::vector<std::string>{"member", "viewer"}));
}

TEST(AdministrationHttpApiTest, DispatchesEachExplicitLifecycleTransition)
{
    Fixture fixture;
    fixture.addSession("owner-token", idp::AssuranceLevel::Ial2);
    for (const auto& [path, operation] :
         std::vector<std::pair<std::string, std::string>>{
             {"/admin/local-members/suspend", "suspend"},
             {"/admin/local-members/reinstate", "reinstate"},
             {"/admin/local-members/remove", "remove"}}) {
        const auto response = fixture.api.handle(request(
            path, R"({"identity_id":"identity-2"})", "owner-token"));
        EXPECT_EQ(response.status(), 204) << response.body();
        EXPECT_EQ(fixture.provisioner.operation, operation);
    }
}

TEST(AdministrationHttpApiTest, CredentialResetReturnsSecretsOnlyAfterSuccess)
{
    Fixture fixture;
    fixture.addSession("owner-token", idp::AssuranceLevel::Ial2);
    const auto response = fixture.api.handle(request(
        "/admin/local-members/credentials/reset",
        R"({"identity_id":"identity-2"})", "owner-token"));
    ASSERT_EQ(response.status(), 200) << response.body();
    EXPECT_EQ(fixture.provisioner.operation, "reset");
    const json::object body = json::parse(response.body()).as_object();
    EXPECT_EQ(std::string{body.at("initial_password").as_string()},
              fixture.provisioner.password);
    EXPECT_EQ(std::string{body.at("totp_secret_base32").as_string()},
              fixture.provisioner.totpBase32);

    Fixture denied;
    denied.addSession("owner-token", idp::AssuranceLevel::Ial2);
    denied.provisioner.failure = fnd::ErrorCode::FailedPrecondition;
    const auto refused = denied.api.handle(request(
        "/admin/local-members/credentials/reset",
        R"({"identity_id":"identity-2"})", "owner-token"));
    EXPECT_EQ(refused.status(), 412);
    EXPECT_EQ(refused.body().find("initial_password"), std::string::npos);
    EXPECT_EQ(refused.body().find("totp_secret"), std::string::npos);
}

}
