#include <chrono>
#include <initializer_list>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

import openproof.application;
import openproof.client;
import openproof.evidence;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.oauth;
import openproof.oidc;
import openproof.sdk;
import openproof.security;
import openproof.session;
import openproof.token;
import openproof.trust;

namespace {

using namespace std::chrono_literals;
namespace application = openproof::application;
namespace client = openproof::client;
namespace evidence = openproof::evidence;
namespace foundation = openproof::foundation;
namespace identity = openproof::identity;
namespace oauth = openproof::oauth;
namespace oidc = openproof::oidc;
namespace sdk = openproof::sdk;
namespace security = openproof::security;
namespace session = openproof::session;
namespace token = openproof::token;
namespace trust = openproof::trust;

constexpr foundation::Instant kNow{foundation::Duration{1'786'400'000'000LL}};

[[nodiscard]] std::vector<client::Scope> parsedScopes(
    std::initializer_list<std::string> values)
{
    std::vector<client::Scope> output;
    for (const auto& value : values) {
        auto scope = client::Scope::create(value);
        EXPECT_TRUE(scope.has_value());
        if (scope.has_value()) {
            output.push_back(std::move(scope).value());
        }
    }
    return output;
}

struct ClientFixture final {
    foundation::ManualClockSource clock{kNow};
    application::InMemoryApplicationRepository applications;
    application::ApplicationRegistry registry{applications, clock};
    client::InMemoryClientRepository clients;
    client::ClientManager manager;
    application::Application product;
    client::ClientRegistration registration;

    ClientFixture()
        : manager(clients, applications, clock,
              std::move(client::ClientSecretKey::create(
                  foundation::SecretString{std::string(32U, 'c')}).value()))
        , product(std::move(registry.registerApplication(
              identity::core::OrganizationId{"org-main"}, "example-app", "Example App",
              application::Environment::Production).value()))
        , registration(std::move(manager.registerClient(
              product.id(), "Example Native", client::ClientKind::Native,
              {"http://127.0.0.1:49152/callback"},
              {"openid", "profile", "offline_access"}).value()))
    {
    }
};

TEST(ApplicationRegistryTest, IdentifiersAreTenantScopedAndRevocationIsTerminal)
{
    foundation::ManualClockSource clock{kNow};
    application::InMemoryApplicationRepository repository;
    application::ApplicationRegistry registry{repository, clock};

    auto first = registry.registerApplication(
        identity::core::OrganizationId{"org-a"}, "messenger", "Messenger",
        application::Environment::Production);
    auto second = registry.registerApplication(
        identity::core::OrganizationId{"org-b"}, "messenger", "Messenger",
        application::Environment::Production);

    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->id(), second->id());

    auto scoped = repository.findByIdentifier(
        identity::core::OrganizationId{"org-a"}, "messenger");
    ASSERT_TRUE(scoped.has_value());
    ASSERT_TRUE(scoped->has_value());
    EXPECT_EQ(scoped->value().owner(), identity::core::OrganizationId{"org-a"});

    auto revoked = registry.revoke(first->id());
    ASSERT_TRUE(revoked.has_value());
    EXPECT_FALSE(revoked->permitsAuthorization());
    EXPECT_FALSE(registry.activate(first->id()).has_value());
}

TEST(ClientManagementTest, PublicAndConfidentialClientsHaveDifferentCredentialRules)
{
    ClientFixture fixture;
    EXPECT_FALSE(fixture.registration.secret().has_value());
    EXPECT_TRUE(fixture.registration.client().permitsRedirect(
        "http://127.0.0.1:49152/callback"));
    EXPECT_TRUE(fixture.registration.client().permitsRedirect(
        "http://127.0.0.1:54321/callback"));
    EXPECT_FALSE(fixture.registration.client().permitsRedirect(
        "http://127.0.0.1:49152/callback/"));
    EXPECT_FALSE(fixture.registration.client().permitsRedirect(
        "http://[::1]:49152/callback"));

    auto web = fixture.manager.registerClient(
        fixture.product.id(), "Example Web", client::ClientKind::Web,
        {"https://app.example.com/auth/callback"}, {"openid", "profile"});
    ASSERT_TRUE(web.has_value());
    ASSERT_TRUE(web->secret().has_value());
    EXPECT_TRUE(web->secret()->expose().starts_with("ops_"));

    auto rotated = fixture.manager.rotateSecret(web->client().id());
    ASSERT_TRUE(rotated.has_value());
    EXPECT_NE(rotated->expose(), web->secret()->expose());

    EXPECT_TRUE(fixture.manager.suspend(web->client().id()).has_value());
    EXPECT_FALSE(fixture.manager.requireActive(web->client().id()).has_value());
    EXPECT_TRUE(fixture.manager.activate(web->client().id()).has_value());
    EXPECT_TRUE(fixture.manager.revoke(web->client().id()).has_value());
    EXPECT_FALSE(fixture.manager.activate(web->client().id()).has_value());

    EXPECT_FALSE(fixture.manager.registerClient(
        fixture.product.id(), "Hostile Web", client::ClientKind::Web,
        {"https://trusted.example@evil.example/callback"}, {"openid"})
                     .has_value());
    EXPECT_FALSE(fixture.manager.registerClient(
        fixture.product.id(), "Hostile Native", client::ClientKind::Native,
        {"http://127.0.0.1:49152@evil.example/callback"}, {"openid"})
                     .has_value());
    EXPECT_FALSE(fixture.manager.registerClient(
        fixture.product.id(), "Localhost Native", client::ClientKind::Native,
        {"http://localhost:49152/callback"}, {"openid"})
                     .has_value());
}

TEST(ClientManagementTest, ClientValueSemanticsCrossModuleBoundaryAreStable)
{
    ClientFixture fixture;

    client::Client source = fixture.registration.client();
    client::Client copied = source;
    EXPECT_EQ(copied.id(), source.id());

    client::Client assigned = copied;
    assigned = source;
    EXPECT_EQ(assigned.applicationId(), source.applicationId());

    client::Client moved = std::move(copied);
    EXPECT_EQ(moved.id(), source.id());

    client::Client moveAssigned = source;
    moveAssigned = std::move(moved);
    EXPECT_EQ(moveAssigned.id(), source.id());
}

TEST(ModuleBoundaryRegressionTest, OpaqueValueCopiesDetachBeforeMutation)
{
    ClientFixture fixture;

    client::Client originalClient = fixture.registration.client();
    client::Client copiedClient = originalClient;
    ASSERT_TRUE(copiedClient.suspend(kNow + 1s).has_value());
    EXPECT_EQ(originalClient.status(), client::ClientStatus::Active);
    EXPECT_EQ(copiedClient.status(), client::ClientStatus::Suspended);

    token::TokenContext context{
        originalClient.id(), identity::core::IdentityId{"identity-1"},
        identity::provider::ProviderId{"local"},
        identity::provider::AssuranceLevel::Ial2,
        identity::provider::AuthenticationStrength{
            identity::provider::AuthenticationFactor::Knowledge, false},
        {"openid"}, kNow};
    token::AccessTokenRecord originalAccess{
        token::TokenDigest{security::Sha256Digest{}},
        token::TokenFamilyId{"family-1"}, context, kNow, kNow + 15min};
    token::AccessTokenRecord copiedAccess = originalAccess;
    copiedAccess.revoke(kNow + 1s);
    EXPECT_EQ(originalAccess.state(), token::AccessTokenState::Active);
    EXPECT_EQ(copiedAccess.state(), token::AccessTokenState::Revoked);

    auto evidenceResult = evidence::Evidence::create(
        evidence::EvidenceId{"ev-cow"}, identity::core::IdentityId{"identity-1"},
        identity::provider::ProviderId{"github"}, "account", "verified", "true",
        100U, kNow);
    ASSERT_TRUE(evidenceResult.has_value());
    evidence::Evidence originalEvidence = evidenceResult.value();
    evidence::Evidence copiedEvidence = originalEvidence;
    ASSERT_TRUE(copiedEvidence.revoke().has_value());
    EXPECT_EQ(originalEvidence.status(), evidence::EvidenceStatus::Verified);
    EXPECT_EQ(copiedEvidence.status(), evidence::EvidenceStatus::Revoked);
}

TEST(ModuleBoundaryRegressionTest, ExportedRecordsRemainDestructibleInsideStandardContainers)
{
    static_assert(std::is_trivially_copyable_v<client::ClientSecretDigest>);
    static_assert(std::is_trivially_destructible_v<client::ClientSecretDigest>);
    static_assert(std::is_trivially_copyable_v<oauth::CodeDigest>);
    static_assert(std::is_trivially_destructible_v<oauth::CodeDigest>);
    static_assert(std::is_trivially_copyable_v<token::TokenDigest>);
    static_assert(std::is_trivially_destructible_v<token::TokenDigest>);
    static_assert(std::is_destructible_v<oauth::CodeDigest>);
    static_assert(std::is_destructible_v<oauth::AuthorizationCode>);
    static_assert(std::is_destructible_v<token::TokenDigest>);
    static_assert(std::is_destructible_v<token::AccessTokenRecord>);
    static_assert(std::is_destructible_v<token::RefreshTokenRecord>);
    static_assert(std::is_copy_constructible_v<client::ClientSecretDigest>);
    static_assert(std::is_copy_assignable_v<client::ClientSecretDigest>);
    static_assert(std::is_move_constructible_v<client::ClientSecretDigest>);
    static_assert(std::is_move_assignable_v<client::ClientSecretDigest>);
    static_assert(std::is_copy_constructible_v<std::optional<client::ClientSecretDigest>>);
    static_assert(std::is_copy_assignable_v<std::optional<client::ClientSecretDigest>>);

    const security::Sha256Digest digestBytes{};
    std::optional<client::ClientSecretDigest> digestA{
        client::ClientSecretDigest{digestBytes}};
    std::optional<client::ClientSecretDigest> digestB{
        client::ClientSecretDigest{digestBytes}};
    digestB = digestA;
    EXPECT_TRUE(digestB.has_value());

    std::map<oauth::CodeDigest, oauth::AuthorizationCode> authorizationCodes;
    std::map<std::string, token::AccessTokenRecord> accessTokens;
    std::map<std::string, token::RefreshTokenRecord> refreshTokens;

    EXPECT_TRUE(authorizationCodes.empty());
    EXPECT_TRUE(accessTokens.empty());
    EXPECT_TRUE(refreshTokens.empty());
}

TEST(OAuthTokenTest, AuthorizationCodePkceAndRefreshReplayAreFailClosed)
{
    ClientFixture fixture;
    oauth::InMemoryAuthorizationCodeStore codes;
    oauth::AuthorizationService authorization{
        fixture.manager, codes, fixture.clock,
        std::move(oauth::AuthorizationCodeKey::create(
            foundation::SecretString{std::string(32U, 'a')}).value()),
        2min};

    constexpr std::string_view verifier =
        "0123456789012345678901234567890123456789012";
    auto digest = security::sha256(verifier);
    ASSERT_TRUE(digest.has_value());
    auto challenge = oauth::PkceChallenge::create(
        foundation::toBase64Url(digest.value()));
    ASSERT_TRUE(challenge.has_value());

    auto request = oauth::AuthorizationRequest::create(
        fixture.registration.client().id(),
        "http://127.0.0.1:49152/callback",
        parsedScopes({"openid", "profile"}),
        std::move(challenge).value(), std::string{"state-1"},
        std::string{"nonce-1"});
    ASSERT_TRUE(request.has_value());

    auto offlineChallenge = oauth::PkceChallenge::create(
        foundation::toBase64Url(digest.value()));
    ASSERT_TRUE(offlineChallenge.has_value());
    auto offlineRequest = oauth::AuthorizationRequest::create(
        fixture.registration.client().id(),
        "http://127.0.0.1:49152/callback",
        parsedScopes({"openid", "offline_access"}),
        std::move(offlineChallenge).value(), std::string{"state-offline"},
        std::string{"nonce-offline"});
    ASSERT_TRUE(offlineRequest.has_value());

    auto authenticated = session::AuthenticatedSession::fromDelegatedAccess(
        identity::core::IdentityId{"identity-1"},
        identity::provider::ProviderId{"local"},
        identity::provider::AssuranceLevel::Ial2,
        identity::provider::AuthenticationStrength{
            identity::provider::AuthenticationFactor::Knowledge
                | identity::provider::AuthenticationFactor::Possession,
            false},
        kNow, kNow, kNow + 1h);
    ASSERT_TRUE(authenticated.has_value());
    // Remembered/interactive consent is enforced by the OAuth HTTP boundary
    // before it calls the protocol service. Once that boundary has approved the
    // request, offline_access is a valid registered scope at this layer.
    auto offlineGrant = authorization.authorize(
        authenticated.value(), std::move(offlineRequest).value());
    ASSERT_TRUE(offlineGrant.has_value());

    auto code = authorization.authorize(
        authenticated.value(), std::move(request).value());
    ASSERT_TRUE(code.has_value());
    EXPECT_TRUE(code->code().expose().starts_with("opa_"));

    constexpr std::string_view wrongVerifier =
        "1123456789012345678901234567890123456789012";
    EXPECT_FALSE(authorization.redeem(
        code->code(), fixture.registration.client().id(),
        "http://127.0.0.1:49152/callback", wrongVerifier).has_value());

    auto redeemed = authorization.redeem(
        code->code(), fixture.registration.client().id(),
        "http://127.0.0.1:49152/callback", verifier);
    ASSERT_TRUE(redeemed.has_value());
    EXPECT_EQ(identity::provider::assuranceLevelName(redeemed->assurance()), "ial2");
    EXPECT_TRUE(identity::provider::containsFactor(redeemed->strength().factors(),
                                    identity::provider::AuthenticationFactor::Knowledge));
    EXPECT_TRUE(identity::provider::containsFactor(redeemed->strength().factors(),
                                    identity::provider::AuthenticationFactor::Possession));
    EXPECT_FALSE(identity::provider::containsFactor(redeemed->strength().factors(),
                                     identity::provider::AuthenticationFactor::Inherence));
    EXPECT_FALSE(redeemed->strength().isPhishingResistant());
    EXPECT_FALSE(authorization.redeem(
        code->code(), fixture.registration.client().id(),
        "http://127.0.0.1:49152/callback", verifier).has_value());

    token::InMemoryTokenRepository tokens;
    auto policy = token::TokenPolicy::create(15min, std::chrono::hours{24 * 30});
    ASSERT_TRUE(policy.has_value());
    token::TokenService tokenService{
        tokens, fixture.manager, fixture.clock,
        std::move(token::TokenKey::create(
            foundation::SecretString{std::string(32U, 't')}).value()),
        policy.value()};

    auto issued = tokenService.issue(redeemed.value());
    ASSERT_TRUE(issued.has_value());
    EXPECT_TRUE(issued->accessToken().expose().starts_with("opa_"));
    EXPECT_TRUE(issued->refreshToken().expose().starts_with("opr_"));

    auto delegated = tokenService.authenticateDelegated(issued->accessToken());
    ASSERT_TRUE(delegated.has_value());
    EXPECT_EQ(delegated->clientId(), fixture.registration.client().id().value());
    EXPECT_TRUE(delegated->permits("openid"));

    auto originalRefresh = issued->refreshToken().clone();
    fixture.clock.advance(std::chrono::hours{24 * 29});
    auto rotated = tokenService.refresh(
        fixture.registration.client().id(), originalRefresh);
    ASSERT_TRUE(rotated.has_value());
    auto rotatedRefresh = rotated->refreshToken().clone();

    // The family expires 30 days after the initial grant, not 30 days after
    // every successful rotation.
    fixture.clock.advance(std::chrono::hours{24 * 2});
    EXPECT_FALSE(tokenService.refresh(
        fixture.registration.client().id(), rotatedRefresh).has_value());

    EXPECT_FALSE(tokenService.refresh(
        fixture.registration.client().id(), originalRefresh).has_value());
    EXPECT_FALSE(tokenService.introspect(rotated->accessToken()).has_value());
}

TEST(OAuthTokenTest, SenderConstraintIsPreservedAcrossDelegationAndRefresh)
{
    ClientFixture fixture;
    oauth::InMemoryAuthorizationCodeStore codes;
    oauth::AuthorizationService authorization{
        fixture.manager, codes, fixture.clock,
        std::move(oauth::AuthorizationCodeKey::create(
            foundation::SecretString{std::string(32U, 'a')}).value()),
        2min};

    constexpr std::string_view verifier =
        "0123456789012345678901234567890123456789012";
    auto digest = security::sha256(verifier);
    ASSERT_TRUE(digest.has_value());
    auto challenge = oauth::PkceChallenge::create(foundation::toBase64Url(digest.value()));
    ASSERT_TRUE(challenge.has_value());
    auto request = oauth::AuthorizationRequest::create(
        fixture.registration.client().id(), "http://127.0.0.1:49152/callback",
        parsedScopes({"openid", "profile"}), std::move(challenge).value(),
        std::string{"state-sender"}, std::string{"nonce-sender"});
    ASSERT_TRUE(request.has_value());
    auto authenticated = session::AuthenticatedSession::fromDelegatedAccess(
        identity::core::IdentityId{"identity-1"}, identity::provider::ProviderId{"local"},
        identity::provider::AssuranceLevel::Ial2,
        identity::provider::AuthenticationStrength{
            identity::provider::AuthenticationFactor::Possession, true},
        kNow, kNow, kNow + 1h);
    ASSERT_TRUE(authenticated.has_value());
    auto code = authorization.authorize(authenticated.value(), std::move(request).value());
    ASSERT_TRUE(code.has_value());
    auto redeemed = authorization.redeem(
        code->code(), fixture.registration.client().id(),
        "http://127.0.0.1:49152/callback", verifier);
    ASSERT_TRUE(redeemed.has_value());

    token::InMemoryTokenRepository tokens;
    auto policy = token::TokenPolicy::create(15min, std::chrono::hours{24 * 30});
    ASSERT_TRUE(policy.has_value());
    token::TokenService tokenService{
        tokens, fixture.manager, fixture.clock,
        std::move(token::TokenKey::create(
            foundation::SecretString{std::string(32U, 't')}).value()),
        policy.value()};
    auto binding = token::SenderConstraint::create(
        token::SenderConstraintKind::Dpop, "registered-jwk-thumbprint");
    ASSERT_TRUE(binding.has_value());
    auto issued = tokenService.issue(redeemed.value(), binding.value());
    ASSERT_TRUE(issued.has_value());
    auto delegated = tokenService.authenticateDelegated(issued->accessToken());
    ASSERT_TRUE(delegated.has_value());
    ASSERT_TRUE(delegated->senderConstraint().has_value());
    EXPECT_EQ(delegated->senderConstraint()->kind(),
              session::DelegatedSenderConstraintKind::Dpop);
    EXPECT_EQ(delegated->senderConstraint()->value(), "registered-jwk-thumbprint");

    auto refreshToken = issued->refreshToken().clone();
    EXPECT_FALSE(tokenService.refresh(
        fixture.registration.client().id(), refreshToken).has_value());
    auto rotated = tokenService.refresh(
        fixture.registration.client().id(), refreshToken, binding.value());
    ASSERT_TRUE(rotated.has_value());
    ASSERT_TRUE(rotated->context().senderConstraint().has_value());
    EXPECT_EQ(rotated->context().senderConstraint()->value(),
              "registered-jwk-thumbprint");
}

TEST(TrustEvidenceTest, VerifiedEvidenceAndRiskProduceDeterministicAssessment)
{
    foundation::ManualClockSource clock{kNow};
    evidence::InMemoryEvidenceRepository repository;
    auto github = evidence::Evidence::create(
        evidence::EvidenceId{"ev-github"}, identity::core::IdentityId{"identity-1"},
        identity::provider::ProviderId{"github"}, "developer_history",
        "account", "verified", 90U, kNow);
    auto wallet = evidence::Evidence::create(
        evidence::EvidenceId{"ev-wallet"}, identity::core::IdentityId{"identity-1"},
        identity::provider::ProviderId{"wallet"}, "wallet_ownership",
        "address", "verified", 80U, kNow);
    ASSERT_TRUE(github.has_value());
    ASSERT_TRUE(wallet.has_value());
    ASSERT_TRUE(repository.add(std::move(github).value()).has_value());
    ASSERT_TRUE(repository.add(std::move(wallet).value()).has_value());

    trust::TrustPolicy policy;
    ASSERT_TRUE(policy.setWeight("developer_history", 70U).has_value());
    ASSERT_TRUE(policy.setWeight("wallet_ownership", 30U).has_value());
    trust::TrustEngine engine{repository, clock, std::move(policy)};
    auto risk = trust::RiskSignal::create("velocity", 10U, "Recent activity spike");
    ASSERT_TRUE(risk.has_value());
    EXPECT_FALSE(trust::RiskSignal::create("bad\nkind", 10U, "reason").has_value());
    EXPECT_FALSE(trust::RiskSignal::create("velocity", 101U, "reason").has_value());

    auto assessment = engine.assess(
        identity::core::IdentityId{"identity-1"}, {risk.value()});
    ASSERT_TRUE(assessment.has_value());
    EXPECT_EQ(assessment->trustScore(), 77U);
    EXPECT_EQ(assessment->riskScore(), 10U);
    EXPECT_EQ(assessment->confidence(), 85U);
    EXPECT_EQ(assessment->evidenceIds().size(), 2U);
}

TEST(OidcIssuerTest, RejectsAuthorityConfusionAndAcceptsHttpsOrLoopbackDevelopment)
{
    EXPECT_TRUE(oidc::Issuer::create("https://identity.example").has_value());
    EXPECT_TRUE(oidc::Issuer::create("http://127.0.0.1:8080").has_value());
    EXPECT_FALSE(oidc::Issuer::create(
        "https://identity.example@evil.example").has_value());
    EXPECT_FALSE(oidc::Issuer::create(
        "http://127.0.0.1:8080@evil.example").has_value());
    EXPECT_FALSE(oidc::Issuer::create("http://identity.example").has_value());
}

TEST(CppSdkTest, GeneratesPkceStateAndKeepsTokenMaterialSecretTyped)
{
    auto config = sdk::ClientConfig::create(
        "https://identity.example", "example-native",
        "https://app.example.com/auth/callback",
        {"openid", "profile"});
    ASSERT_TRUE(config.has_value());
    sdk::IdentityClient client{std::move(config).value()};
    auto login = client.beginLogin();
    ASSERT_TRUE(login.has_value());
    EXPECT_TRUE(login->authorizationUrl().contains("code_challenge_method=S256"));
    EXPECT_TRUE(login->authorizationUrl().contains("response_type=code"));

    auto tokenRequest = client.authorizationCodeRequest(
        "authorization-code", login.value(), login->state().expose(),
        "https://identity.example");
    ASSERT_TRUE(tokenRequest.has_value());
    EXPECT_EQ(tokenRequest->method, "POST");
    EXPECT_TRUE(tokenRequest->body.expose().contains("code_verifier="));
    EXPECT_FALSE(client.authorizationCodeRequest(
        "authorization-code", login.value(), "wrong-state",
        "https://identity.example").has_value());
    EXPECT_FALSE(client.authorizationCodeRequest(
        "authorization-code", login.value(), login->state().expose(),
        "https://evil.example").has_value());

    foundation::SecretString accessToken{"opa_example"};
    auto userInfo = client.userInfoRequest(accessToken);
    ASSERT_TRUE(userInfo.has_value());
    EXPECT_EQ(userInfo->authorizationScheme, "Bearer");
    EXPECT_EQ(userInfo->authorizationCredential.expose(), "opa_example");
}

} // namespace
