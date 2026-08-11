#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include <libpq-fe.h>

import openproof.foundation;
import openproof.administration;
import openproof.audit;
import openproof.credentials;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;
import openproof.policy;
import openproof.provider.local;
import openproof.security;
import openproof.session;
import openproof.storage.postgres;

namespace {

namespace core = openproof::identity::core;
namespace admin = openproof::administration;
namespace audit = openproof::audit;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace pg = openproof::storage::postgres;
namespace pol = openproof::policy;
namespace org = openproof::organization;
namespace local = openproof::provider::local;
namespace sec = openproof::security;
namespace sess = openproof::session;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

class PostgresIntegrationTest : public testing::Test {
protected:
    void SetUp() override
    {
        const char* configured = std::getenv("OPENPROOF_TEST_POSTGRES");
        if (configured == nullptr || std::string_view{configured}.empty()) {
            GTEST_SKIP() << "OPENPROOF_TEST_POSTGRES is not configured";
        }
        connectionString = configured;
        auto config = pg::PoolConfig::create(
            fnd::SecretString{connectionString}, 4U, std::chrono::seconds{2});
        ASSERT_TRUE(config);
        auto created = pg::ConnectionPool::create(std::move(config).value());
        ASSERT_TRUE(created);
        pool = std::move(created).value();
        ASSERT_TRUE(pool->healthCheck());
        pg::Migrator migrator{*pool};
        auto migrated = migrator.applyDirectory(
            std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
        ASSERT_TRUE(migrated);

        direct.reset(PQconnectdb(connectionString.c_str()));
        ASSERT_NE(direct.get(), nullptr);
        ASSERT_EQ(PQstatus(direct.get()), CONNECTION_OK);
        execute("TRUNCATE openproof.authentication_transactions, "
                "openproof.organizations CASCADE");
        execute("INSERT INTO openproof.organizations(id,name,state,created_at_ms) "
                "VALUES('org','Test',0,1770000000000)");
        execute("INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
                "VALUES('identity-1','org',0,0,1770000000000)");
    }

    struct ConnectionDeleter final {
        void operator()(PGconn* connection) const noexcept { if (connection != nullptr) PQfinish(connection); }
    };
    struct ResultDeleter final {
        void operator()(PGresult* result) const noexcept { if (result != nullptr) PQclear(result); }
    };

    void execute(const char* sql)
    {
        std::unique_ptr<PGresult, ResultDeleter> result{PQexec(direct.get(), sql)};
        ASSERT_NE(result.get(), nullptr);
        ASSERT_EQ(PQresultStatus(result.get()), PGRES_COMMAND_OK);
    }

    std::string connectionString;
    std::unique_ptr<pg::ConnectionPool> pool;
    std::unique_ptr<PGconn, ConnectionDeleter> direct;
};

[[nodiscard]] sess::Session sessionValue(
    std::string_view token, std::string_view sessionId = "session-1",
    std::string_view identityId = "identity-1")
{
    return sess::Session::create(
        sess::SessionId{std::string{sessionId}},
        core::IdentityId{std::string{identityId}},
        idp::ProviderId{"provider"}, idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge
                                        | idp::AuthenticationFactor::Possession,
                                    false},
        kNow, sess::TokenDigest{sec::sha256(token).value()}, kNow,
        std::chrono::hours{1}, std::chrono::minutes{10}).value();
}

TEST_F(PostgresIntegrationTest, MigrationIsIdempotentAndPoolIsHealthy)
{
    pg::Migrator migrator{*pool};
    auto result = migrator.applyDirectory(
        std::filesystem::path{OPENPROOF_SOURCE_DIR} / "migrations");
    ASSERT_TRUE(result);
    EXPECT_EQ(result->applied, 0U);
    EXPECT_GE(result->alreadyApplied, 1U);
    EXPECT_EQ(pool->size(), 4U);
}

TEST_F(PostgresIntegrationTest, SessionUseRotationAndRevocationAreImmediate)
{
    pg::PostgresSessionRepository repository{*pool};
    ASSERT_TRUE(repository.add(sessionValue("old-token")));
    auto used = repository.use(sess::TokenDigest{sec::sha256("old-token").value()},
                               kNow + std::chrono::minutes{1});
    ASSERT_TRUE(used);
    EXPECT_EQ(used->identity(), core::IdentityId{"identity-1"});

    ASSERT_TRUE(repository.rotate(
        sess::SessionId{"session-1"},
        sess::TokenDigest{sec::sha256("old-token").value()},
        sess::TokenDigest{sec::sha256("new-token").value()},
        kNow + std::chrono::minutes{2}));
    EXPECT_FALSE(repository.use(
        sess::TokenDigest{sec::sha256("old-token").value()},
        kNow + std::chrono::minutes{2}));
    EXPECT_TRUE(repository.use(
        sess::TokenDigest{sec::sha256("new-token").value()},
        kNow + std::chrono::minutes{2}));
    ASSERT_TRUE(repository.revoke(sess::SessionId{"session-1"},
                                  kNow + std::chrono::minutes{3}));
    EXPECT_FALSE(repository.use(
        sess::TokenDigest{sec::sha256("new-token").value()},
        kNow + std::chrono::minutes{3}));
}

TEST_F(PostgresIntegrationTest, TransactionCanBeConsumedExactlyOnceAcrossThreads)
{
    pg::PostgresAuthenticationTransactionStore store{*pool};
    const fnd::SecretString nonce{"single-use-nonce"};
    const idp::BindingDigest binding = sec::sha256("binding").value();
    auto transaction = idp::AuthenticationTransaction::create(
        idp::TransactionId{"transaction-1"}, idp::ProviderId{"provider"},
        idp::InteractionModel::ChallengeResponse, nonce.clone(), binding,
        fnd::CorrelationId{"correlation"}, kNow, std::chrono::minutes{5}).value();
    transaction.setMetadata("challenge_id", "challenge");
    ASSERT_TRUE(store.begin(std::move(transaction)));

    std::atomic<unsigned int> winners{0U};
    auto redeem = [&] {
        auto result = store.consume(idp::TransactionId{"transaction-1"}, nonce,
                                    binding, kNow + std::chrono::seconds{1});
        if (result.has_value()) winners.fetch_add(1U);
    };
    std::thread first{redeem};
    std::thread second{redeem};
    first.join();
    second.join();
    EXPECT_EQ(winners.load(), 1U);
    auto stored = store.find(idp::TransactionId{"transaction-1"});
    ASSERT_TRUE(stored);
    ASSERT_TRUE(stored->has_value());
    EXPECT_EQ(stored->value().state(), idp::TransactionState::Consumed);
    EXPECT_EQ(stored->value().metadata().at("challenge_id"), "challenge");
}

TEST_F(PostgresIntegrationTest, FailedNonceBurnsTransactionAtomically)
{
    pg::PostgresAuthenticationTransactionStore store{*pool};
    const idp::BindingDigest binding = sec::sha256("binding").value();
    auto transaction = idp::AuthenticationTransaction::create(
        idp::TransactionId{"transaction-1"}, idp::ProviderId{"provider"},
        idp::InteractionModel::ChallengeResponse, fnd::SecretString{"right-nonce"},
        binding, fnd::CorrelationId{"correlation"}, kNow,
        std::chrono::minutes{5}).value();
    ASSERT_TRUE(store.begin(std::move(transaction)));
    EXPECT_FALSE(store.consume(idp::TransactionId{"transaction-1"},
                               fnd::SecretString{"wrong-nonce"}, binding,
                               kNow + std::chrono::seconds{1}));
    EXPECT_FALSE(store.consume(idp::TransactionId{"transaction-1"},
                               fnd::SecretString{"right-nonce"}, binding,
                               kNow + std::chrono::seconds{2}));
    auto stored = store.find(idp::TransactionId{"transaction-1"});
    ASSERT_TRUE(stored);
    ASSERT_TRUE(stored->has_value());
    EXPECT_EQ(stored->value().state(), idp::TransactionState::Failed);
}

TEST_F(PostgresIntegrationTest, RecoveryCodeIsConsumedExactlyOnceAcrossNodes)
{
    pg::PostgresRecoveryCodeRepository firstRepository{*pool};
    pg::PostgresRecoveryCodeRepository secondRepository{*pool};
    auto service = cred::RecoveryCodeService::create(
        firstRepository, fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto batch = service.issue(core::IdentityId{"identity-1"}, 4U);
    ASSERT_TRUE(batch.has_value());
    ASSERT_EQ(firstRepository.remaining(core::IdentityId{"identity-1"}).value(), 4U);

    auto secondService = cred::RecoveryCodeService::create(
        secondRepository, fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    const fnd::SecretString presented = batch->codes().front().clone();
    std::atomic<unsigned int> winners{0U};
    auto consume = [&] {
        if (secondService.consume(core::IdentityId{"identity-1"}, presented).has_value()) {
            winners.fetch_add(1U);
        }
    };
    std::thread first{consume};
    std::thread second{consume};
    first.join();
    second.join();
    EXPECT_EQ(winners.load(), 1U);
    EXPECT_EQ(firstRepository.remaining(core::IdentityId{"identity-1"}).value(), 3U);
}

TEST_F(PostgresIntegrationTest, IdentityOrganizationMembershipAndExternalLinksRoundTrip)
{
    pg::PostgresOrganizationRepository organizations{*pool};
    pg::PostgresIdentityRepository identities{*pool};
    pg::PostgresMembershipRepository memberships{*pool};
    pg::PostgresExternalIdentityDirectory external{*pool};

    auto organization = organizations.findById(core::OrganizationId{"org"});
    ASSERT_TRUE(organization);
    ASSERT_TRUE(organization->has_value());
    EXPECT_TRUE(organization->value().isUsable());
    auto identity = identities.findById(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"});
    ASSERT_TRUE(identity);
    ASSERT_TRUE(identity->has_value());
    EXPECT_TRUE(identity->value().canAuthenticate());

    auto membership = org::Membership::invite(
        org::OrganizationId{"org"}, org::IdentityId{"identity-1"}, kNow).value();
    ASSERT_TRUE(membership.grantRole(org::Role{"member"}));
    ASSERT_TRUE(membership.accept());
    ASSERT_TRUE(memberships.add(membership));
    auto persisted = memberships.find(
        org::OrganizationId{"org"}, org::IdentityId{"identity-1"});
    ASSERT_TRUE(persisted);
    ASSERT_TRUE(persisted->has_value());
    EXPECT_TRUE(persisted->value().hasRole(org::Role{"member"}));

    auto link = core::IdentityLink::request(
        core::IdentityId{"identity-1"},
        core::ExternalIdentityRef{idp::ProviderId{"local"},
                                  idp::ExternalSubject{"alice"}},
        kNow, std::chrono::minutes{5}).value();
    ASSERT_TRUE(link.requireVerification(kNow));
    ASSERT_TRUE(link.markVerified(kNow));
    ASSERT_TRUE(link.complete(kNow));
    ASSERT_TRUE(external.attach(link));
    auto owner = external.ownerOf(link.external());
    ASSERT_TRUE(owner);
    ASSERT_TRUE(owner->has_value());
    EXPECT_EQ(owner->value(), core::IdentityId{"identity-1"});
}

TEST_F(PostgresIntegrationTest, RejectedAuthorizationIsChainedAndPublished)
{
    fnd::ManualClockSource clock{kNow};
    const fnd::SecretString sessionSecret{
        "0123456789abcdef0123456789abcdef"};
    auto digest = sec::hmacSha256(sessionSecret, "denied-token").value();
    sess::InMemorySessionRepository sessionRepository;
    ASSERT_TRUE(sessionRepository.add(sess::Session::create(
        sess::SessionId{"denied-session"}, core::IdentityId{"identity-1"},
        idp::ProviderId{"local"}, idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{
            idp::AuthenticationFactor::Knowledge
                | idp::AuthenticationFactor::Possession,
            false},
        kNow, sess::TokenDigest{digest}, kNow, std::chrono::hours{1},
        std::chrono::minutes{10}).value()));
    sess::SessionService sessions{
        sessionRepository, clock,
        sess::SessionKey::create(sessionSecret.clone()).value(),
        sess::SessionPolicy::create(std::chrono::hours{1},
                                    std::chrono::minutes{10}).value()};
    auto authenticated = sessions.authenticate(
        fnd::SecretString{"denied-token"});
    ASSERT_TRUE(authenticated);

    pg::PostgresAuthorizationDecisionSink sink{
        *pool,
        audit::AuditKey::create(fnd::SecretString{
            "abcdef0123456789abcdef0123456789"}).value(),
        clock};
    ASSERT_TRUE(sink.record(
        authenticated.value(), core::OrganizationId{"org"},
        pol::Action{"proxy.GET:/api"}, pol::Resource{"upstream:/api"},
        pol::AuthorizationDecision::deny("required role is absent"),
        fnd::CorrelationId{"authorization-request"}));

    std::unique_ptr<PGresult, ResultDeleter> evidence{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.audit_events WHERE "
        "category='authorization' AND action='protected-route.evaluate' "
        "AND outcome='deny' AND encode(event_hash,'hex')<>repeat('0',64)),"
        "(SELECT count(*) FROM openproof.security_event_outbox WHERE "
        "payload->>'type'='authorization.protected-route.denied')")};
    ASSERT_NE(evidence.get(), nullptr);
    ASSERT_EQ(PQresultStatus(evidence.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 0), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 1), "1");
}

TEST_F(PostgresIntegrationTest, PersistentLocalTotpIsEncryptedAndConsumedOnce)
{
    pg::PostgresExternalIdentityDirectory external{*pool};
    auto link = core::IdentityLink::request(
        core::IdentityId{"identity-1"},
        core::ExternalIdentityRef{idp::ProviderId{"local"},
                                  idp::ExternalSubject{"alice"}},
        kNow, std::chrono::minutes{5}).value();
    ASSERT_TRUE(link.requireVerification(kNow));
    ASSERT_TRUE(link.markVerified(kNow));
    ASSERT_TRUE(link.complete(kNow));
    ASSERT_TRUE(external.attach(link));

    auto passwordPolicy = cred::PasswordPolicy::create(
        1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U).value();
    auto passwordHasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, passwordPolicy).value();
    auto encryptionKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto directory = pg::PostgresLocalAccountDirectory::create(
        *pool, std::move(passwordHasher), cred::TotpPolicy::recommended(),
        std::move(encryptionKey), 1U, idp::ProviderId{"local"});
    ASSERT_TRUE(directory);
    auto secret = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"}).value();
    const std::string code = cred::totpAt(
        secret, cred::TotpPolicy::recommended(), kNow).value();
    ASSERT_TRUE(directory.value()->enroll(
        idp::ExternalSubject{"alice"}, fnd::SecretString{"correct-password"},
        std::optional<cred::TotpSecret>{std::move(secret)}));

    std::atomic<unsigned int> winners{0U};
    auto verify = [&] {
        auto result = directory.value()->verify(
            idp::ExternalSubject{"alice"}, fnd::SecretString{"correct-password"},
            code, kNow);
        if (result.has_value()) winners.fetch_add(1U);
    };
    std::thread first{verify};
    std::thread second{verify};
    first.join();
    second.join();
    EXPECT_EQ(winners.load(), 1U);
}

TEST_F(PostgresIntegrationTest, InitialAdministratorBootstrapIsAtomicAuditedAndOneTime)
{
    execute("TRUNCATE openproof.audit_events, openproof.security_event_outbox, "
            "openproof.organizations CASCADE");
    auto command = admin::InitialAdministrator::create(
        core::OrganizationId{"bootstrap-org"}, "Bootstrap Organization",
        core::IdentityId{"bootstrap-identity"}, idp::ProviderId{"local"},
        idp::ExternalSubject{"owner@example.test"},
        fnd::SecretString{"correct-bootstrap-password"},
        cred::TotpSecret::create(
            fnd::SecretString{"12345678901234567890"}).value(), kNow);
    ASSERT_TRUE(command);

    auto policy = cred::PasswordPolicy::create(
        1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U).value();
    auto hasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy).value();
    auto encryptionKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto auditKey = audit::AuditKey::create(
        fnd::SecretString{"abcdef0123456789abcdef0123456789"}).value();
    auto bootstrap = pg::PostgresAdministrationRepository::create(
        *pool, std::move(hasher), std::move(encryptionKey), 1U,
        idp::ProviderId{"local"}, std::move(auditKey));
    ASSERT_TRUE(bootstrap);
    ASSERT_TRUE(bootstrap.value()->initialize(command.value()));

    auto repeated = bootstrap.value()->initialize(command.value());
    ASSERT_FALSE(repeated);
    EXPECT_EQ(repeated.error().code(), fnd::ErrorCode::AlreadyExists);

    pg::PostgresOrganizationRepository organizations{*pool};
    pg::PostgresIdentityRepository identities{*pool};
    pg::PostgresMembershipRepository memberships{*pool};
    pg::PostgresExternalIdentityDirectory external{*pool};
    auto tenant = organizations.findById(core::OrganizationId{"bootstrap-org"});
    auto identity = identities.findById(
        core::OrganizationId{"bootstrap-org"},
        core::IdentityId{"bootstrap-identity"});
    auto membership = memberships.find(
        core::OrganizationId{"bootstrap-org"},
        core::IdentityId{"bootstrap-identity"});
    auto owner = external.ownerOf(core::ExternalIdentityRef{
        idp::ProviderId{"local"}, idp::ExternalSubject{"owner@example.test"}});
    ASSERT_TRUE(tenant && tenant->has_value());
    ASSERT_TRUE(identity && identity->has_value());
    ASSERT_TRUE(membership && membership->has_value());
    ASSERT_TRUE(owner && owner->has_value());
    EXPECT_TRUE(membership->value().hasRole(org::Role{"owner"}));
    EXPECT_EQ(owner->value(), core::IdentityId{"bootstrap-identity"});

    std::unique_ptr<PGresult, ResultDeleter> evidence{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.audit_events WHERE "
        "action='bootstrap.initial-owner' AND encode(event_hash,'hex')<>repeat('0',64)),"
        "(SELECT count(*) FROM openproof.security_event_outbox),"
        "(SELECT encrypted_seed=convert_to('12345678901234567890','UTF8') "
        "FROM openproof.totp_credentials WHERE identity_id='bootstrap-identity')")};
    ASSERT_NE(evidence.get(), nullptr);
    ASSERT_EQ(PQresultStatus(evidence.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(evidence.get()), 1);
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 0), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 1), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 2), "f");

    auto verifierHasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy).value();
    auto verifierKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto accounts = pg::PostgresLocalAccountDirectory::create(
        *pool, std::move(verifierHasher), cred::TotpPolicy::recommended(),
        std::move(verifierKey), 1U, idp::ProviderId{"local"});
    ASSERT_TRUE(accounts);
    const std::string code = cred::totpAt(
        command->totp(), cred::TotpPolicy::recommended(), kNow).value();
    auto verified = accounts.value()->verify(
        idp::ExternalSubject{"owner@example.test"},
        fnd::SecretString{"correct-bootstrap-password"}, code, kNow);
    ASSERT_TRUE(verified) << verified.error().internalDetail();
    EXPECT_EQ(verified.value(), local::LocalVerification::PasswordAndTotp);
}

TEST_F(PostgresIntegrationTest, OwnerProvisioningIsAtomicAuditedAndDeniedToMembers)
{
    execute("TRUNCATE openproof.audit_events, openproof.security_event_outbox");
    execute("INSERT INTO openproof.memberships"
            "(organization_id,identity_id,state,invited_at_ms) "
            "VALUES('org','identity-1',1,1770000000000)");
    execute("INSERT INTO openproof.membership_roles"
            "(organization_id,identity_id,role) "
            "VALUES('org','identity-1','owner')");
    execute("INSERT INTO openproof.external_identities"
            "(provider,external_subject,identity_id,linked_at_ms) "
            "VALUES('local','owner@example.test','identity-1',1770000000000)");

    auto policy = cred::PasswordPolicy::create(
        1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U).value();
    auto hasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy).value();
    auto encryptionKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto auditKey = audit::AuditKey::create(
        fnd::SecretString{"abcdef0123456789abcdef0123456789"}).value();
    auto administration = pg::PostgresAdministrationRepository::create(
        *pool, std::move(hasher), std::move(encryptionKey), 1U,
        idp::ProviderId{"local"}, std::move(auditKey));
    ASSERT_TRUE(administration);

    const fnd::SecretString password{"generated-member-password-123456"};
    auto memberTotp = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"}).value();
    auto enrollment = admin::LocalMemberEnrollment::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        idp::ProviderId{"local"}, idp::ExternalSubject{"bob@example.test"},
        std::vector<org::Role>{org::Role{"viewer"}, org::Role{"member"}},
        password.clone(), std::move(memberTotp), kNow);
    ASSERT_TRUE(enrollment);
    ASSERT_TRUE(administration.value()->provision(
        core::IdentityId{"identity-1"}, enrollment.value()));

    pg::PostgresIdentityRepository identities{*pool};
    pg::PostgresMembershipRepository memberships{*pool};
    pg::PostgresExternalIdentityDirectory external{*pool};
    auto identity = identities.findById(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"});
    auto membership = memberships.find(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"});
    auto owner = external.ownerOf(core::ExternalIdentityRef{
        idp::ProviderId{"local"}, idp::ExternalSubject{"bob@example.test"}});
    ASSERT_TRUE(identity && identity->has_value());
    ASSERT_TRUE(membership && membership->has_value());
    ASSERT_TRUE(owner && owner->has_value());
    EXPECT_EQ(owner->value(), core::IdentityId{"identity-2"});
    EXPECT_TRUE(membership->value().hasRole(org::Role{"member"}));
    EXPECT_TRUE(membership->value().hasRole(org::Role{"viewer"}));
    EXPECT_FALSE(membership->value().hasRole(org::Role{"owner"}));

    auto verifierHasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, policy).value();
    auto verifierKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto accounts = pg::PostgresLocalAccountDirectory::create(
        *pool, std::move(verifierHasher), cred::TotpPolicy::recommended(),
        std::move(verifierKey), 1U, idp::ProviderId{"local"});
    ASSERT_TRUE(accounts);
    auto verifierTotp = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"}).value();
    const std::string code = cred::totpAt(
        verifierTotp, cred::TotpPolicy::recommended(), kNow).value();
    ASSERT_TRUE(accounts.value()->verify(
        idp::ExternalSubject{"bob@example.test"}, password, code, kNow));

    auto refused = admin::LocalMemberEnrollment::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-3"},
        idp::ProviderId{"local"}, idp::ExternalSubject{"mallory@example.test"},
        std::vector<org::Role>{org::Role{"member"}},
        fnd::SecretString{"another-generated-password-12345"},
        cred::TotpSecret::create(
            fnd::SecretString{"abcdefghijabcdefghij"}).value(), kNow);
    ASSERT_TRUE(refused);
    const auto denied = administration.value()->provision(
        core::IdentityId{"identity-2"}, refused.value());
    ASSERT_FALSE(denied);
    EXPECT_EQ(denied.error().code(), fnd::ErrorCode::PermissionDenied);
    auto absent = identities.findById(
        core::OrganizationId{"org"}, core::IdentityId{"identity-3"});
    ASSERT_TRUE(absent);
    EXPECT_FALSE(absent->has_value());

    std::unique_ptr<PGresult, ResultDeleter> evidence{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.audit_events WHERE "
        "action='local-member.create' AND encode(event_hash,'hex')<>repeat('0',64)),"
        "(SELECT count(*) FROM openproof.security_event_outbox),"
        "(SELECT count(*) FROM openproof.identities WHERE id='identity-3')")};
    ASSERT_NE(evidence.get(), nullptr);
    ASSERT_EQ(PQresultStatus(evidence.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(evidence.get()), 1);
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 0), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 1), "1");
    EXPECT_STREQ(PQgetvalue(evidence.get(), 0, 2), "0");

    auto finalOwnerRoles = admin::MemberRoleReplacement::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        std::vector<org::Role>{org::Role{"member"}},
        kNow + std::chrono::minutes{1}).value();
    auto refusedLastOwner = administration.value()->replaceRoles(
        core::IdentityId{"identity-1"}, finalOwnerRoles);
    ASSERT_FALSE(refusedLastOwner);
    EXPECT_EQ(refusedLastOwner.error().code(), fnd::ErrorCode::FailedPrecondition);
    auto suspendFinalOwner = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        admin::MemberLifecycleAction::Suspend,
        kNow + std::chrono::minutes{1}).value();
    auto refusedSuspension = administration.value()->changeLifecycle(
        core::IdentityId{"identity-1"}, suspendFinalOwner);
    ASSERT_FALSE(refusedSuspension);
    EXPECT_EQ(refusedSuspension.error().code(), fnd::ErrorCode::FailedPrecondition);

    pg::PostgresSessionRepository sessions{*pool};
    ASSERT_TRUE(sessions.add(sessionValue(
        "member-role-token", "member-role-session", "identity-2")));
    auto promote = admin::MemberRoleReplacement::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        std::vector<org::Role>{org::Role{"member"}, org::Role{"owner"}},
        kNow + std::chrono::minutes{2}).value();
    ASSERT_TRUE(administration.value()->replaceRoles(
        core::IdentityId{"identity-1"}, promote));
    EXPECT_FALSE(sessions.use(
        sess::TokenDigest{sec::sha256("member-role-token").value()},
        kNow + std::chrono::minutes{2}));
    auto promotedMembership = memberships.find(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"});
    ASSERT_TRUE(promotedMembership && promotedMembership->has_value());
    EXPECT_TRUE(promotedMembership->value().hasRole(org::Role{"owner"}));

    ASSERT_TRUE(sessions.add(sessionValue(
        "owner-lifecycle-token", "owner-lifecycle-session", "identity-1")));
    auto suspendOwner = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        admin::MemberLifecycleAction::Suspend,
        kNow + std::chrono::minutes{3}).value();
    ASSERT_TRUE(administration.value()->changeLifecycle(
        core::IdentityId{"identity-2"}, suspendOwner));
    EXPECT_FALSE(sessions.use(
        sess::TokenDigest{sec::sha256("owner-lifecycle-token").value()},
        kNow + std::chrono::minutes{3}));
    auto suspended = memberships.find(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"});
    ASSERT_TRUE(suspended && suspended->has_value());
    EXPECT_EQ(suspended->value().state(), org::MembershipState::Suspended);
    EXPECT_FALSE(suspended->value().hasRole(org::Role{"owner"}));

    auto reinstateOwner = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        admin::MemberLifecycleAction::Reinstate,
        kNow + std::chrono::minutes{4}).value();
    ASSERT_TRUE(administration.value()->changeLifecycle(
        core::IdentityId{"identity-2"}, reinstateOwner));
    auto reinstated = memberships.find(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"});
    ASSERT_TRUE(reinstated && reinstated->has_value());
    EXPECT_TRUE(reinstated->value().hasRole(org::Role{"owner"}));

    ASSERT_TRUE(sessions.add(sessionValue(
        "member-reset-token", "member-reset-session", "identity-2")));
    execute("INSERT INTO openproof.recovery_codes"
            "(identity_id,code_digest,issued_at_ms) "
            "VALUES('identity-2',decode(repeat('ab',32),'hex'),1770000000000)");
    const fnd::SecretString resetPassword{"reset-generated-password-12345678"};
    auto reset = admin::LocalCredentialReset::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        resetPassword.clone(),
        cred::TotpSecret::create(
            fnd::SecretString{"abcdefghijabcdefghij"}).value(),
        kNow + std::chrono::minutes{5}).value();
    ASSERT_TRUE(administration.value()->resetCredentials(
        core::IdentityId{"identity-1"}, reset));
    EXPECT_FALSE(sessions.use(
        sess::TokenDigest{sec::sha256("member-reset-token").value()},
        kNow + std::chrono::minutes{5}));
    auto resetTotp = cred::TotpSecret::create(
        fnd::SecretString{"abcdefghijabcdefghij"}).value();
    const std::string resetCode = cred::totpAt(
        resetTotp, cred::TotpPolicy::recommended(),
        kNow + std::chrono::minutes{5}).value();
    EXPECT_FALSE(accounts.value()->verify(
        idp::ExternalSubject{"bob@example.test"}, password, resetCode,
        kNow + std::chrono::minutes{5}));
    ASSERT_TRUE(accounts.value()->verify(
        idp::ExternalSubject{"bob@example.test"}, resetPassword, resetCode,
        kNow + std::chrono::minutes{5}));

    auto removeMember = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"},
        admin::MemberLifecycleAction::Remove,
        kNow + std::chrono::minutes{6}).value();
    ASSERT_TRUE(administration.value()->changeLifecycle(
        core::IdentityId{"identity-1"}, removeMember));
    auto removedMembership = memberships.find(
        core::OrganizationId{"org"}, core::IdentityId{"identity-2"});
    ASSERT_TRUE(removedMembership && removedMembership->has_value());
    EXPECT_EQ(removedMembership->value().state(), org::MembershipState::Removed);
    EXPECT_TRUE(removedMembership->value().roles().empty());

    auto removeFinalOwner = admin::MemberLifecycleChange::create(
        core::OrganizationId{"org"}, core::IdentityId{"identity-1"},
        admin::MemberLifecycleAction::Remove,
        kNow + std::chrono::minutes{7}).value();
    auto finalRemoval = administration.value()->changeLifecycle(
        core::IdentityId{"identity-1"}, removeFinalOwner);
    ASSERT_FALSE(finalRemoval);
    EXPECT_EQ(finalRemoval.error().code(), fnd::ErrorCode::FailedPrecondition);

    std::unique_ptr<PGresult, ResultDeleter> lifecycleEvidence{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.audit_events),"
        "(SELECT count(*) FROM openproof.security_event_outbox),"
        "(SELECT count(*) FROM openproof.recovery_codes WHERE identity_id='identity-2'),"
        "(SELECT count(*) FROM openproof.sessions WHERE identity_id IN "
        "('identity-1','identity-2') AND state=0)")};
    ASSERT_NE(lifecycleEvidence.get(), nullptr);
    ASSERT_EQ(PQresultStatus(lifecycleEvidence.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(lifecycleEvidence.get(), 0, 0), "6");
    EXPECT_STREQ(PQgetvalue(lifecycleEvidence.get(), 0, 1), "6");
    EXPECT_STREQ(PQgetvalue(lifecycleEvidence.get(), 0, 2), "0");
    EXPECT_STREQ(PQgetvalue(lifecycleEvidence.get(), 0, 3), "0");
}

}
