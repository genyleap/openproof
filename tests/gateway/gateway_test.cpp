#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

import openproof.authentication;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;
import openproof.policy;
import openproof.security;
import openproof.session;

namespace {

namespace auth = openproof::authentication;
namespace core = openproof::identity::core;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace idp = openproof::identity::provider;
namespace pol = openproof::policy;
namespace org = openproof::organization;
namespace sec = openproof::security;
namespace sess = openproof::session;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};
constexpr std::string_view kSessionKey =
    "0123456789abcdef0123456789abcdef";

class TestProvider final : public idp::AuthenticationProvider {
public:
    [[nodiscard]] idp::ProviderId id() const override { return idp::ProviderId{"test"}; }
    [[nodiscard]] idp::InteractionModel interactionModel() const noexcept override
    { return idp::InteractionModel::ChallengeResponse; }
    [[nodiscard]] idp::AssuranceLevel maximumClaimableAssurance() const noexcept override
    { return idp::AssuranceLevel::Ial2; }
    [[nodiscard]] fnd::Result<idp::AuthenticationChallenge>
    beginAuthentication(const idp::AuthenticationRequest&) override
    { return idp::AuthenticationChallenge{idp::ChallengeId{"challenge"},
                                           kNow + std::chrono::minutes{5}}; }
    [[nodiscard]] fnd::Result<idp::AuthenticationOutcome>
    completeAuthentication(const idp::AuthenticationResponse&) override
    {
        return idp::AuthenticationOutcome::create(
            id(), idp::ExternalSubject{"external"}, idp::VerifiedClaims{},
            idp::AssuranceLevel::Ial2,
            idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge
                                            | idp::AuthenticationFactor::Possession,
                                        false},
            idp::ProviderEvidence{}, kNow);
    }
};

[[nodiscard]] auth::VerifiedAuthentication verifiedAuthentication()
{
    idp::ProviderRegistry providers;
    EXPECT_TRUE(providers.registerProvider(std::make_unique<TestProvider>()));
    idp::InMemoryAuthenticationTransactionStore transactions;
    core::InMemoryExternalIdentityDirectory identities;
    auto link = core::IdentityLink::request(
        core::IdentityId{"identity-1"},
        core::ExternalIdentityRef{idp::ProviderId{"test"}, idp::ExternalSubject{"external"}},
        kNow, std::chrono::minutes{5}).value();
    EXPECT_TRUE(link.requireVerification(kNow));
    EXPECT_TRUE(link.markVerified(kNow));
    EXPECT_TRUE(link.complete(kNow));
    EXPECT_TRUE(identities.attach(link));
    auth::ProviderTrustPolicy trust;
    EXPECT_TRUE(trust.trust(idp::ProviderId{"test"}, idp::AssuranceLevel::Ial2));
    fnd::ManualClockSource clock{kNow};
    auth::AuthenticationService service{providers, transactions, identities, clock,
                                        std::move(trust), std::chrono::minutes{5}};
    idp::AuthenticationRequest request{idp::ProviderId{"test"}, idp::ClientContext{}};
    auto started = service.begin(request, sec::sha256("binding").value(),
                                 fnd::CorrelationId{"correlation"}).value();
    idp::AuthenticationResponse response{started.challenge().id(), idp::ClientContext{}};
    return service.complete(started.transactionId(), started.continuationToken(),
                            sec::sha256("binding").value(), response).value();
}

class AllowAccess final : public gw::AccessController {
public:
    [[nodiscard]] pol::AuthorizationDecision authorize(
        const sess::AuthenticatedSession&, const gw::Route&,
        const fnd::CorrelationId&) override
    { return pol::AuthorizationDecision::allow("test permit"); }
};

class RecordingDecisionSink final : public pol::AuthorizationDecisionSink {
public:
    [[nodiscard]] fnd::Status record(
        const sess::AuthenticatedSession& authenticated,
        const core::OrganizationId&, const pol::Action&, const pol::Resource&,
        const pol::AuthorizationDecision& decision,
        const fnd::CorrelationId& correlation) override
    {
        ++calls;
        identity = std::string{authenticated.session().identity().value()};
        kind = decision.kind();
        requestId = std::string{correlation.value()};
        return fnd::ok();
    }
    std::size_t calls{};
    std::string identity;
    pol::DecisionKind kind{pol::DecisionKind::Allow};
    std::string requestId;
};

class RecordingProxy final : public gw::ProxyTransport {
public:
    [[nodiscard]] fnd::Result<gw::HttpResponse> send(
        const gw::Endpoint& endpoint, const gw::HttpRequest& request,
        fnd::Duration) override
    {
        endpoints.push_back(endpoint.id());
        identityHeader = request.header("x-openproof-identity");
        providerHeader = request.header("x-openproof-provider");
        authorizationHeader = request.header("authorization");
        connectionHeader = request.header("connection");
        cookieHeader = request.header("cookie");
        return gw::HttpResponse{200, gw::Headers{{"connection", "close"}}, "ok"};
    }
    std::vector<gw::EndpointId> endpoints;
    std::optional<std::string> identityHeader;
    std::optional<std::string> providerHeader;
    std::optional<std::string> authorizationHeader;
    std::optional<std::string> connectionHeader;
    std::optional<std::string> cookieHeader;
};

class FailingProxy final : public gw::ProxyTransport {
public:
    [[nodiscard]] fnd::Result<gw::HttpResponse> send(
        const gw::Endpoint& endpoint, const gw::HttpRequest&, fnd::Duration) override
    {
        attempted.push_back(endpoint.id());
        return fnd::fail(fnd::ErrorCode::Unavailable, "upstream failed");
    }
    std::vector<gw::EndpointId> attempted;
};

class ServerErrorProxy final : public gw::ProxyTransport {
public:
    [[nodiscard]] fnd::Result<gw::HttpResponse> send(
        const gw::Endpoint&, const gw::HttpRequest&, fnd::Duration) override
    { return gw::HttpResponse{503, {}, "unavailable"}; }
};

[[nodiscard]] gw::Route route(bool protectedRoute = false, gw::HttpMethod method = gw::HttpMethod::Get)
{
    return gw::Route::create(
        gw::RouteId{"route"}, method, "/api", gw::ServiceId{"service"},
        protectedRoute,
        protectedRoute ? core::OrganizationId{"org"} : core::OrganizationId{},
        protectedRoute ? pol::Action{"read"} : pol::Action{},
        protectedRoute ? pol::Resource{"thing"} : pol::Resource{}).value();
}

[[nodiscard]] gw::HttpRequest request(
    std::vector<std::pair<std::string, std::string>> headers = {},
    gw::HttpMethod method = gw::HttpMethod::Get)
{
    return gw::HttpRequest::create(method, "/api/items", std::move(headers), "",
                                   "192.0.2.10", fnd::CorrelationId{"request-1"}).value();
}

struct GatewayFixture {
    GatewayFixture()
        : clock(kNow), signer(gw::TrustedContextSigner::create(
              clock, gw::TrustedContextKey::create(fnd::SecretString{
                  "abcdef0123456789abcdef0123456789"}).value(),
              std::chrono::seconds{30}).value()),
          sessions(sessionRepository, clock,
              sess::SessionKey::create(fnd::SecretString{
                  std::string{kSessionKey}}).value(),
              sess::SessionPolicy::create(std::chrono::hours{8},
                                          std::chrono::minutes{30}).value()),
          limiter(gw::TokenBucketRateLimiter::create(clock, 100.0, 100.0, 1000U).value()),
          circuits(gw::CircuitBreaker::create(clock, 2U, std::chrono::seconds{30}).value())
    {
        EXPECT_TRUE(discovery.set(gw::ServiceId{"service"},
            {gw::Endpoint::create(gw::EndpointId{"one"}, "127.0.0.1", 9001U, false, 1U).value(),
             gw::Endpoint::create(gw::EndpointId{"two"}, "127.0.0.1", 9002U, false, 1U).value()}));
    }

    [[nodiscard]] sess::AuthenticatedSession authenticated(
        idp::AssuranceLevel assurance = idp::AssuranceLevel::Ial2)
    {
        const std::string assuranceName{idp::assuranceLevelName(assurance)};
        const std::string token = "gateway-policy-token-" + assuranceName;
        const auto digest = sec::hmacSha256(
            fnd::SecretString{std::string{kSessionKey}}, token).value();
        EXPECT_TRUE(sessionRepository.add(sess::Session::create(
            sess::SessionId{"gateway-policy-session-" + assuranceName},
            core::IdentityId{"identity-1"}, idp::ProviderId{"test"}, assurance,
            idp::AuthenticationStrength{
                assurance == idp::AssuranceLevel::Ial1
                    ? idp::AuthenticationFactor::Knowledge
                    : idp::AuthenticationFactor::Knowledge
                        | idp::AuthenticationFactor::Possession,
                false},
            kNow, sess::TokenDigest{digest}, kNow, std::chrono::hours{8},
            std::chrono::minutes{30}).value()));
        return sessions.authenticate(fnd::SecretString{token}).value();
    }
    fnd::ManualClockSource clock;
    gw::TrustedContextSigner signer;
    sess::InMemorySessionRepository sessionRepository;
    sess::SessionService sessions;
    AllowAccess access;
    gw::TokenBucketRateLimiter limiter;
    gw::StaticServiceDiscovery discovery;
    gw::WeightedRoundRobin balancer;
    gw::CircuitBreaker circuits;
};

TEST(PolicyAccessControllerTest, UsesDurableRolesAssuranceAndAuditsDenials)
{
    GatewayFixture fixture;
    org::InMemoryOrganizationRepository organizations;
    core::InMemoryIdentityRepository identities;
    org::InMemoryMembershipRepository memberships;
    ASSERT_TRUE(organizations.add(org::Organization::create(
        core::OrganizationId{"org"}, "Organization", kNow).value()));
    ASSERT_TRUE(identities.add(
        core::OrganizationId{"org"},
        core::Identity::create(core::IdentityId{"identity-1"},
                               core::SubjectKind::Human, kNow).value()));
    auto membership = org::Membership::invite(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"}, kNow).value();
    ASSERT_TRUE(membership.grantRole(org::Role{"reader"}));
    ASSERT_TRUE(membership.accept());
    ASSERT_TRUE(memberships.add(membership));

    auto rule = pol::RolePolicyRule::create(
        pol::Action{"read"}, pol::Resource{"thing"}, {pol::Role{"reader"}},
        pol::RoleMatchMode::All, idp::AssuranceLevel::Ial2).value();
    auto engine = pol::RolePolicyEngine::create({std::move(rule)}).value();
    RecordingDecisionSink auditSink;
    gw::PolicyAccessController access{
        engine.get(), organizations, identities, memberships, &auditSink};
    const sess::AuthenticatedSession ial2 = fixture.authenticated();
    EXPECT_TRUE(access.authorize(
        ial2, route(true), fnd::CorrelationId{"allowed"})
                    .isPermitted());
    EXPECT_EQ(auditSink.calls, 0U);

    ASSERT_TRUE(membership.revokeRole(org::Role{"reader"}));
    ASSERT_TRUE(membership.grantRole(org::Role{"viewer"}));
    ASSERT_TRUE(memberships.save(membership));
    const auto roleDenied = access.authorize(
        ial2, route(true), fnd::CorrelationId{"role-denied"});
    EXPECT_EQ(roleDenied.kind(), pol::DecisionKind::Deny);
    EXPECT_EQ(auditSink.calls, 1U);
    EXPECT_EQ(auditSink.identity, "identity-1");
    EXPECT_EQ(auditSink.kind, pol::DecisionKind::Deny);
    EXPECT_EQ(auditSink.requestId, "role-denied");

    ASSERT_TRUE(membership.grantRole(org::Role{"reader"}));
    ASSERT_TRUE(memberships.save(membership));
    const auto assuranceDenied = access.authorize(
        fixture.authenticated(idp::AssuranceLevel::Ial1), route(true),
        fnd::CorrelationId{"assurance-denied"});
    EXPECT_EQ(assuranceDenied.kind(), pol::DecisionKind::Deny);
    EXPECT_EQ(auditSink.calls, 2U);
    EXPECT_EQ(auditSink.requestId, "assurance-denied");
}

TEST(HttpRequestTest, RejectsAbsoluteFormControlCharactersAndAmbiguousFraming)
{
    EXPECT_FALSE(gw::HttpRequest::create(gw::HttpMethod::Get, "http://evil/", {}, "",
                                         "192.0.2.1", fnd::CorrelationId{"r"}));
    EXPECT_FALSE(gw::HttpRequest::create(gw::HttpMethod::Get, "/ok", {
        {"Content-Length", "4"}, {"Transfer-Encoding", "chunked"}}, "test",
        "192.0.2.1", fnd::CorrelationId{"r"}));
    EXPECT_FALSE(gw::HttpRequest::create(gw::HttpMethod::Get, "/ok", {
        {"X-Test", "safe\r\ninjected: true"}}, "", "192.0.2.1",
        fnd::CorrelationId{"r"}));
    EXPECT_FALSE(gw::HttpRequest::create(gw::HttpMethod::Get, "/bad\ttarget", {}, "",
                                         "192.0.2.1", fnd::CorrelationId{"r"}));
    EXPECT_FALSE(gw::HttpRequest::create(gw::HttpMethod::Get, "/ok", {}, "",
                                         "192.0.2.1", fnd::CorrelationId{}));
}

TEST(RouterTest, ChoosesLongestSegmentBoundaryPrefix)
{
    gw::Router router;
    EXPECT_TRUE(router.add(route()));
    auto nested = gw::Route::create(gw::RouteId{"nested"}, gw::HttpMethod::Get,
        "/api/admin", gw::ServiceId{"admin"}, false, {}, {}, {}).value();
    EXPECT_TRUE(router.add(nested));
    ASSERT_TRUE(router.match(gw::HttpMethod::Get, "/api/admin/users"));
    EXPECT_EQ(router.match(gw::HttpMethod::Get, "/api/admin/users")->id(),
              gw::RouteId{"nested"});
    EXPECT_FALSE(router.match(gw::HttpMethod::Get, "/apiary"));
    EXPECT_FALSE(gw::Route::create(gw::RouteId{"bad"}, gw::HttpMethod::Get,
                                   "//authority", gw::ServiceId{"service"},
                                   false, {}, {}, {}).has_value());
}

TEST(RateLimiterTest, RefillsDeterministicallyAndBoundsCardinality)
{
    fnd::ManualClockSource clock{kNow};
    auto limiter = gw::TokenBucketRateLimiter::create(clock, 2.0, 1.0, 2U).value();
    EXPECT_TRUE(limiter.allow("a"));
    EXPECT_TRUE(limiter.allow("a"));
    EXPECT_FALSE(limiter.allow("a"));
    clock.advance(std::chrono::seconds{1});
    EXPECT_TRUE(limiter.allow("a"));
    EXPECT_TRUE(limiter.allow("b"));
    EXPECT_TRUE(limiter.allow("c"));
    EXPECT_TRUE(limiter.allow("d"));
    EXPECT_FALSE(limiter.allow("e"));
}

TEST(CircuitBreakerTest, OpensAndPermitsOnlyOneHalfOpenProbe)
{
    fnd::ManualClockSource clock{kNow};
    auto breaker = gw::CircuitBreaker::create(clock, 2U, std::chrono::seconds{30}).value();
    const gw::EndpointId endpoint{"one"};
    EXPECT_TRUE(breaker.allow(endpoint));
    breaker.recordFailure(endpoint);
    EXPECT_TRUE(breaker.allow(endpoint));
    breaker.recordFailure(endpoint);
    EXPECT_EQ(breaker.state(endpoint), gw::CircuitState::Open);
    EXPECT_FALSE(breaker.allow(endpoint));
    clock.advance(std::chrono::seconds{30});
    EXPECT_TRUE(breaker.allow(endpoint));
    EXPECT_FALSE(breaker.allow(endpoint));
    breaker.recordSuccess(endpoint);
    EXPECT_EQ(breaker.state(endpoint), gw::CircuitState::Closed);
}

TEST(GatewayTest, ReplacesClientIdentityAndRemovesCredentialsAndHopByHopHeaders)
{
    GatewayFixture fixture;
    gw::Router router;
    EXPECT_TRUE(router.add(route(true)));
    RecordingProxy proxy;
    gw::Gateway gateway{router, fixture.sessions, fixture.access, fixture.limiter,
                        fixture.discovery, fixture.balancer, fixture.circuits, proxy,
                        fixture.signer,
                        std::chrono::seconds{2}};
    auto grant = fixture.sessions.issue(verifiedAuthentication()).value();
    auto incoming = request({
        {"Authorization", std::string{"Bearer "} + grant.token().expose()},
        {"X-OpenProof-Identity", "attacker"},
        {"Connection", "x-remove"}, {"X-Remove", "secret-hop"}});

    auto response = gateway.handle(std::move(incoming));
    EXPECT_EQ(response.status(), 200);
    ASSERT_TRUE(proxy.identityHeader);
    EXPECT_EQ(proxy.identityHeader.value(), "identity-1");
    ASSERT_TRUE(proxy.providerHeader);
    EXPECT_EQ(proxy.providerHeader.value(), "test");
    EXPECT_FALSE(proxy.authorizationHeader);
    EXPECT_FALSE(proxy.connectionHeader);
    EXPECT_FALSE(response.headers().contains("connection"));
    EXPECT_EQ(response.headers().at("cache-control"), "no-store");
}

TEST(GatewayTest, ProtectedRouteRequiresBearerAndFailsClosedOnDeniedAccess)
{
    GatewayFixture fixture;
    gw::Router router;
    EXPECT_TRUE(router.add(route(true)));
    RecordingProxy proxy;
    gw::Gateway gateway{router, fixture.sessions, fixture.access, fixture.limiter,
                        fixture.discovery, fixture.balancer, fixture.circuits, proxy,
                        fixture.signer,
                        std::chrono::seconds{2}};
    const auto response = gateway.handle(request());
    EXPECT_EQ(response.status(), 401);
    EXPECT_TRUE(proxy.endpoints.empty());
}

TEST(GatewayTest, SessionCookieIsAcceptedStrippedAndCannotConflictWithBearer)
{
    GatewayFixture fixture;
    gw::Router router;
    EXPECT_TRUE(router.add(route(true)));
    RecordingProxy proxy;
    gw::Gateway gateway{router, fixture.sessions, fixture.access, fixture.limiter,
                        fixture.discovery, fixture.balancer, fixture.circuits, proxy,
                        fixture.signer, std::chrono::seconds{2}};
    auto grant = fixture.sessions.issue(verifiedAuthentication()).value();
    const std::string token = grant.token().expose();
    auto accepted = gateway.handle(request({
        {"Cookie", "theme=dark; openproof_session=" + token}}));
    EXPECT_EQ(accepted.status(), 200);
    ASSERT_TRUE(proxy.cookieHeader);
    EXPECT_EQ(proxy.cookieHeader.value(), "theme=dark");

    auto ambiguous = gateway.handle(request({
        {"Authorization", "Bearer " + token},
        {"Cookie", "openproof_session=" + token}}));
    EXPECT_EQ(ambiguous.status(), 401);
}

TEST(GatewayTest, RetriesOnlyIdempotentRequestsAcrossDistinctEndpoints)
{
    GatewayFixture fixture;
    gw::Router getRouter;
    EXPECT_TRUE(getRouter.add(route(false, gw::HttpMethod::Get)));
    FailingProxy getProxy;
    gw::Gateway getGateway{getRouter, fixture.sessions, fixture.access, fixture.limiter,
                           fixture.discovery, fixture.balancer, fixture.circuits, getProxy,
                           fixture.signer,
                           std::chrono::seconds{2}};
    EXPECT_EQ(getGateway.handle(request({}, gw::HttpMethod::Get)).status(), 503);
    EXPECT_EQ(getProxy.attempted.size(), 2U);
    EXPECT_NE(getProxy.attempted[0], getProxy.attempted[1]);

    gw::Router postRouter;
    EXPECT_TRUE(postRouter.add(route(false, gw::HttpMethod::Post)));
    FailingProxy postProxy;
    auto freshCircuits = gw::CircuitBreaker::create(
        fixture.clock, 2U, std::chrono::seconds{30}).value();
    gw::Gateway postGateway{postRouter, fixture.sessions, fixture.access, fixture.limiter,
                            fixture.discovery, fixture.balancer, freshCircuits, postProxy,
                            fixture.signer,
                            std::chrono::seconds{2}};
    EXPECT_EQ(postGateway.handle(request({}, gw::HttpMethod::Post)).status(), 503);
    EXPECT_EQ(postProxy.attempted.size(), 1U);
}

TEST(TrustedContextSignerTest, DetectsTamperingAndExpiredContexts)
{
    GatewayFixture fixture;
    auto signedRequest = request();
    signedRequest.setHeader("x-openproof-request-id", "request-1");
    signedRequest.setHeader("x-openproof-identity", "identity-1");
    signedRequest.setHeader("x-openproof-organization", "org-1");
    ASSERT_TRUE(fixture.signer.seal(signedRequest).has_value());
    EXPECT_TRUE(fixture.signer.verify(signedRequest).has_value());

    signedRequest.setHeader("x-openproof-identity", "attacker");
    EXPECT_FALSE(fixture.signer.verify(signedRequest).has_value());
    signedRequest.setHeader("x-openproof-identity", "identity-1");
    fixture.clock.advance(std::chrono::seconds{31});
    EXPECT_FALSE(fixture.signer.verify(signedRequest).has_value());
}

TEST(GatewayTest, ServerErrorsContributeToCircuitHealth)
{
    GatewayFixture fixture;
    gw::Router router;
    EXPECT_TRUE(router.add(route()));
    ServerErrorProxy proxy;
    gw::Gateway gateway{router, fixture.sessions, fixture.access, fixture.limiter,
                        fixture.discovery, fixture.balancer, fixture.circuits, proxy,
                        fixture.signer, std::chrono::seconds{2}};
    EXPECT_EQ(gateway.handle(request()).status(), 503);
    EXPECT_EQ(gateway.handle(request()).status(), 503);
    EXPECT_EQ(fixture.circuits.state(gw::EndpointId{"one"}), gw::CircuitState::Closed);
    EXPECT_EQ(fixture.circuits.state(gw::EndpointId{"two"}), gw::CircuitState::Closed);
    EXPECT_EQ(gateway.handle(request()).status(), 503);
    EXPECT_EQ(gateway.handle(request()).status(), 503);
    EXPECT_EQ(fixture.circuits.state(gw::EndpointId{"one"}), gw::CircuitState::Open);
    EXPECT_EQ(fixture.circuits.state(gw::EndpointId{"two"}), gw::CircuitState::Open);
}

}
