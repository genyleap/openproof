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
#include <vector>

#include <libpq-fe.h>

import openproof.foundation;
import openproof.administration;
import openproof.application;
import openproof.client;
import openproof.audit;
import openproof.credentials;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.identity.profile;
import openproof.oauth;
import openproof.organization;
import openproof.policy;
import openproof.provider.local;
import openproof.security;
import openproof.session;
import openproof.token;
import openproof.storage.postgres;

namespace {

namespace app = openproof::application;
namespace cli = openproof::client;
namespace core = openproof::identity::core;
namespace admin = openproof::administration;
namespace audit = openproof::audit;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace profile = openproof::identity::profile;
namespace oauth = openproof::oauth;
namespace pg = openproof::storage::postgres;
namespace pol = openproof::policy;
namespace org = openproof::organization;
namespace local = openproof::provider::local;
namespace sec = openproof::security;
namespace sess = openproof::session;
namespace tok = openproof::token;

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
        execute("TRUNCATE openproof.master_key_rotations, "
                "openproof.credential_key_rotations, "
                "openproof.audit_events, "
                "openproof.security_event_outbox, "
                "openproof.authentication_transactions, "
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
        ASSERT_EQ(PQresultStatus(result.get()), PGRES_COMMAND_OK)
            << PQresultErrorMessage(result.get());
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

TEST_F(PostgresIntegrationTest, TotpCredentialRekeyIsAtomicVersionedAndDryRunnable)
{
    pg::PostgresExternalIdentityDirectory external{*pool};
    auto link = core::IdentityLink::request(
        core::IdentityId{"identity-1"},
        core::ExternalIdentityRef{idp::ProviderId{"local"},
                                  idp::ExternalSubject{"rekey-user"}},
        kNow, std::chrono::minutes{5}).value();
    ASSERT_TRUE(link.requireVerification(kNow));
    ASSERT_TRUE(link.markVerified(kNow));
    ASSERT_TRUE(link.complete(kNow));
    ASSERT_TRUE(external.attach(link));

    const auto passwordPolicy = cred::PasswordPolicy::create(
        1024U, 8U, 1U, 16U, 32U, 2U * 1024U * 1024U).value();
    auto oldHasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, passwordPolicy).value();
    auto oldDirectoryKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto oldDirectory = pg::PostgresLocalAccountDirectory::create(
        *pool, std::move(oldHasher), cred::TotpPolicy::recommended(),
        std::move(oldDirectoryKey), 1U, idp::ProviderId{"local"});
    ASSERT_TRUE(oldDirectory);
    auto seed = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"}).value();
    const std::string firstCode = cred::totpAt(
        seed, cred::TotpPolicy::recommended(), kNow).value();
    ASSERT_TRUE(oldDirectory.value()->enroll(
        idp::ExternalSubject{"rekey-user"},
        fnd::SecretString{"correct-password"},
        std::optional<cred::TotpSecret>{std::move(seed)}));
    ASSERT_TRUE(oldDirectory.value()->verify(
        idp::ExternalSubject{"rekey-user"},
        fnd::SecretString{"correct-password"}, firstCode, kNow));

    std::unique_ptr<PGresult, ResultDeleter> before{PQexec(
        direct.get(),
        "SELECT encode(encrypted_seed,'hex'),key_version,last_accepted_step "
        "FROM openproof.totp_credentials WHERE identity_id='identity-1'")};
    ASSERT_NE(before.get(), nullptr);
    ASSERT_EQ(PQresultStatus(before.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(before.get()), 1);
    const std::string oldCiphertext = PQgetvalue(before.get(), 0, 0);
    const std::string acceptedStep = PQgetvalue(before.get(), 0, 2);

    pg::PostgresCredentialRekeyer rekeyer{*pool};
    auto unchangedOldKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto unchangedNewKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto unchanged = rekeyer.rotateTotp(
        unchangedOldKey, 1U, unchangedNewKey, 2U, true);
    ASSERT_FALSE(unchanged);
    EXPECT_EQ(unchanged.error().code(), fnd::ErrorCode::InvalidArgument);

    auto oldDryKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto newDryKey = sec::AeadKey::create(
        fnd::SecretString{"fedcba9876543210fedcba9876543210"}).value();
    auto dryRun = rekeyer.rotateTotp(oldDryKey, 1U, newDryKey, 2U, true);
    ASSERT_TRUE(dryRun);
    EXPECT_EQ(dryRun->rekeyed, 1U);
    EXPECT_EQ(dryRun->alreadyCurrent, 0U);
    EXPECT_TRUE(dryRun->dryRun);

    std::unique_ptr<PGresult, ResultDeleter> afterDryRun{PQexec(
        direct.get(),
        "SELECT key_version,encode(encrypted_seed,'hex'),"
        "(SELECT count(*) FROM openproof.credential_key_rotations) "
        "FROM openproof.totp_credentials WHERE identity_id='identity-1'")};
    ASSERT_NE(afterDryRun.get(), nullptr);
    ASSERT_EQ(PQresultStatus(afterDryRun.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(afterDryRun.get(), 0, 0), "1");
    EXPECT_EQ(PQgetvalue(afterDryRun.get(), 0, 1), oldCiphertext);
    EXPECT_STREQ(PQgetvalue(afterDryRun.get(), 0, 2), "0");

    auto wrongOldKey = sec::AeadKey::create(
        fnd::SecretString{std::string(32U, 'x')}).value();
    auto newAttemptKey = sec::AeadKey::create(
        fnd::SecretString{"fedcba9876543210fedcba9876543210"}).value();
    auto refused = rekeyer.rotateTotp(
        wrongOldKey, 1U, newAttemptKey, 2U, false);
    ASSERT_FALSE(refused);
    EXPECT_EQ(refused.error().code(), fnd::ErrorCode::AuthenticationFailed);

    auto oldKey = sec::AeadKey::create(
        fnd::SecretString{"0123456789abcdef0123456789abcdef"}).value();
    auto newKey = sec::AeadKey::create(
        fnd::SecretString{"fedcba9876543210fedcba9876543210"}).value();
    auto rotated = rekeyer.rotateTotp(oldKey, 1U, newKey, 2U, false);
    ASSERT_TRUE(rotated) << rotated.error().internalDetail();
    EXPECT_EQ(rotated->rekeyed, 1U);
    EXPECT_FALSE(rotated->dryRun);

    std::unique_ptr<PGresult, ResultDeleter> after{PQexec(
        direct.get(),
        "SELECT key_version,encode(encrypted_seed,'hex'),last_accepted_step,"
        "(SELECT count(*) FROM openproof.credential_key_rotations "
        "WHERE purpose='totp' AND from_version=1 AND to_version=2 "
        "AND rekeyed_rows=1) FROM openproof.totp_credentials "
        "WHERE identity_id='identity-1'")};
    ASSERT_NE(after.get(), nullptr);
    ASSERT_EQ(PQresultStatus(after.get()), PGRES_TUPLES_OK);
    ASSERT_EQ(PQntuples(after.get()), 1);
    EXPECT_STREQ(PQgetvalue(after.get(), 0, 0), "2");
    EXPECT_NE(PQgetvalue(after.get(), 0, 1), oldCiphertext);
    EXPECT_EQ(PQgetvalue(after.get(), 0, 2), acceptedStep);
    EXPECT_STREQ(PQgetvalue(after.get(), 0, 3), "1");

    auto newHasher = cred::PasswordHasher::create(
        fnd::SecretString{std::string(32U, 'p')}, passwordPolicy).value();
    auto newDirectoryKey = sec::AeadKey::create(
        fnd::SecretString{"fedcba9876543210fedcba9876543210"}).value();
    auto newDirectory = pg::PostgresLocalAccountDirectory::create(
        *pool, std::move(newHasher), cred::TotpPolicy::recommended(),
        std::move(newDirectoryKey), 2U, idp::ProviderId{"local"});
    ASSERT_TRUE(newDirectory);
    auto verifierSeed = cred::TotpSecret::create(
        fnd::SecretString{"12345678901234567890"}).value();
    const auto nextInstant = kNow + std::chrono::seconds{30};
    const std::string nextCode = cred::totpAt(
        verifierSeed, cred::TotpPolicy::recommended(), nextInstant).value();
    ASSERT_TRUE(newDirectory.value()->verify(
        idp::ExternalSubject{"rekey-user"},
        fnd::SecretString{"correct-password"}, nextCode, nextInstant));
}

TEST_F(PostgresIntegrationTest, MasterKeyRotationAtomicallyInvalidatesOnlyDerivedState)
{
    pg::PostgresAuthenticationTransactionStore transactions{*pool};
    auto transaction = idp::AuthenticationTransaction::create(
        idp::TransactionId{"master-rotation-transaction"},
        idp::ProviderId{"local"}, idp::InteractionModel::ChallengeResponse,
        fnd::SecretString{"master-rotation-nonce"}, sec::sha256("binding").value(),
        fnd::CorrelationId{"master-rotation"}, kNow,
        std::chrono::minutes{5}).value();
    ASSERT_TRUE(transactions.begin(std::move(transaction)));

    pg::PostgresSessionRepository sessions{*pool};
    ASSERT_TRUE(sessions.add(sessionValue(
        "master-rotation-session", "master-rotation-session")));

    execute("INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
            "VALUES('identity-1','scrypt$v1$1024$8$1$2097152$c2FsdHNhbHRzYWx0c2FsdA$"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1770000000000)");
    execute("INSERT INTO openproof.totp_credentials"
            "(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
            "VALUES('identity-1',decode('00','hex'),1,NULL,1770000000000)");
    execute("INSERT INTO openproof.recovery_codes(identity_id,code_digest,issued_at_ms) "
            "VALUES('identity-1',decode(repeat('11',32),'hex'),1770000000000)");
    execute("INSERT INTO openproof.audit_events"
            "(event_id,occurred_at_ms,correlation_id,category,action,outcome,detail,event_hash) "
            "VALUES('master-rotation-audit',1770000000000,'master-rotation',"
            "'security','master.rotate','planned','{}',decode(repeat('22',32),'hex'))");
    execute("INSERT INTO openproof.applications"
            "(id,organization_id,identifier,display_name,environment,status,created_at_ms,updated_at_ms) "
            "VALUES('master-app','org','master-app','Master App',2,0,1770000000000,1770000000000)");
    execute("INSERT INTO openproof.oauth_clients"
            "(id,application_id,display_name,kind,status,secret_digest,created_at_ms,updated_at_ms) "
            "VALUES('master-client','master-app','Master Client',0,0,"
            "decode(repeat('33',32),'hex'),1770000000000,1770000000000)");
    execute("INSERT INTO openproof.account_verification_challenges"
            "(id,identity_id,purpose,channel,destination,secret_digest,attempts,created_at_ms,expires_at_ms) "
            "VALUES('master-account-challenge','identity-1',0,0,'user@example.test',"
            "decode(repeat('44',32),'hex'),0,1770000000000,1770003600000)");
    execute("INSERT INTO openproof.passkey_registration_ceremonies"
            "(id,identity_id,expires_at_ms,consumed_at_ms) "
            "VALUES('master-passkey-registration','identity-1',1770003600000,NULL)");
    execute("INSERT INTO openproof.oauth_authorization_codes"
            "(code_digest,client_id,identity_id,redirect_uri,code_challenge,provider,"
            "assurance,factors,phishing_resistant,authenticated_at_ms,issued_at_ms,expires_at_ms) "
            "VALUES(decode(repeat('55',32),'hex'),'master-client','identity-1',"
            "'https://client.example/callback',repeat('a',43),'local',2,3,false,"
            "1770000000000,1770000000000,1770000300000)");
    execute("INSERT INTO openproof.oauth_token_families"
            "(id,client_id,identity_id,provider,assurance,factors,phishing_resistant,"
            "authenticated_at_ms,revoked_at_ms) VALUES('master-family','master-client',"
            "'identity-1','local',2,3,false,1770000000000,NULL)");
    execute("INSERT INTO openproof.oauth_device_authorizations"
            "(device_digest,user_code_digest,client_id,status,issued_at_ms,expires_at_ms,poll_interval_ms) "
            "VALUES(decode(repeat('66',32),'hex'),decode(repeat('77',32),'hex'),"
            "'master-client',0,1770000000000,1770000600000,5000)");
    execute("INSERT INTO openproof.oauth_pushed_authorization_requests"
            "(request_digest,client_id,redirect_uri,code_challenge,response_mode,issued_at_ms,expires_at_ms) "
            "VALUES(decode(repeat('88',32),'hex'),'master-client',"
            "'https://client.example/callback',repeat('b',43),0,1770000000000,1770000090000)");

    const auto oldFingerprint = sec::hmacSha256(
        fnd::SecretString{std::string(32U, 'm')},
        "openproof/master-key-fingerprint/v1").value();
    const auto newFingerprint = sec::hmacSha256(
        fnd::SecretString{std::string(32U, 'n')},
        "openproof/master-key-fingerprint/v1").value();
    pg::PostgresMasterKeyRotator rotator{*pool};
    EXPECT_TRUE(rotator.verifyActive(1U, oldFingerprint));
    EXPECT_FALSE(rotator.verifyActive(2U, newFingerprint));
    auto dryRun = rotator.rotate(1U, oldFingerprint, 2U, newFingerprint, true);
    ASSERT_TRUE(dryRun) << dryRun.error().internalDetail();
    EXPECT_TRUE(dryRun->dryRun);
    EXPECT_EQ(dryRun->invalidated(), 8U);

    std::unique_ptr<PGresult, ResultDeleter> afterDryRun{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.authentication_transactions)+"
        "(SELECT count(*) FROM openproof.sessions)+"
        "(SELECT count(*) FROM openproof.account_verification_challenges)+"
        "(SELECT count(*) FROM openproof.passkey_registration_ceremonies)+"
        "(SELECT count(*) FROM openproof.oauth_authorization_codes)+"
        "(SELECT count(*) FROM openproof.oauth_token_families)+"
        "(SELECT count(*) FROM openproof.oauth_device_authorizations)+"
        "(SELECT count(*) FROM openproof.oauth_pushed_authorization_requests),"
        "(SELECT count(*) FROM openproof.master_key_rotations)")};
    ASSERT_NE(afterDryRun.get(), nullptr);
    ASSERT_EQ(PQresultStatus(afterDryRun.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(afterDryRun.get(), 0, 0), "8");
    EXPECT_STREQ(PQgetvalue(afterDryRun.get(), 0, 1), "0");

    auto committed = rotator.rotate(1U, oldFingerprint, 2U, newFingerprint, false);
    ASSERT_TRUE(committed) << committed.error().internalDetail();
    EXPECT_FALSE(committed->dryRun);
    EXPECT_EQ(committed->invalidated(), 8U);
    EXPECT_FALSE(rotator.verifyActive(1U, oldFingerprint));
    EXPECT_TRUE(rotator.verifyActive(2U, newFingerprint));

    std::unique_ptr<PGresult, ResultDeleter> afterCommit{PQexec(
        direct.get(),
        "SELECT (SELECT count(*) FROM openproof.authentication_transactions)+"
        "(SELECT count(*) FROM openproof.sessions)+"
        "(SELECT count(*) FROM openproof.account_verification_challenges)+"
        "(SELECT count(*) FROM openproof.passkey_registration_ceremonies)+"
        "(SELECT count(*) FROM openproof.oauth_authorization_codes)+"
        "(SELECT count(*) FROM openproof.oauth_token_families)+"
        "(SELECT count(*) FROM openproof.oauth_device_authorizations)+"
        "(SELECT count(*) FROM openproof.oauth_pushed_authorization_requests),"
        "(SELECT count(*) FROM openproof.password_credentials),"
        "(SELECT count(*) FROM openproof.totp_credentials),"
        "(SELECT count(*) FROM openproof.recovery_codes),"
        "(SELECT count(*) FROM openproof.audit_events "
        "WHERE event_id='master-rotation-audit'),"
        "(SELECT count(*) FROM openproof.oauth_clients),"
        "(SELECT count(*) FROM openproof.master_key_rotations WHERE from_version=1 "
        "AND to_version=2 AND authentication_transactions=1 AND sessions=1 "
        "AND account_challenges=1 AND passkey_registrations=1 "
        "AND authorization_codes=1 AND token_families=1 "
        "AND device_authorizations=1 AND pushed_requests=1)")};
    ASSERT_NE(afterCommit.get(), nullptr);
    ASSERT_EQ(PQresultStatus(afterCommit.get()), PGRES_TUPLES_OK);
    EXPECT_STREQ(PQgetvalue(afterCommit.get(), 0, 0), "0");
    for (int column = 1; column <= 6; ++column) {
        EXPECT_STREQ(PQgetvalue(afterCommit.get(), 0, column), "1");
    }

    auto duplicate = rotator.rotate(1U, oldFingerprint, 2U, newFingerprint, false);
    ASSERT_FALSE(duplicate);
    EXPECT_EQ(duplicate.error().code(), fnd::ErrorCode::AlreadyExists);
    const auto wrongFingerprint = sec::hmacSha256(
        fnd::SecretString{std::string(32U, 'x')},
        "openproof/master-key-fingerprint/v1").value();
    const auto thirdFingerprint = sec::hmacSha256(
        fnd::SecretString{std::string(32U, 'z')},
        "openproof/master-key-fingerprint/v1").value();
    auto wrongHead = rotator.rotate(
        2U, wrongFingerprint, 3U, thirdFingerprint, true);
    ASSERT_FALSE(wrongHead);
    EXPECT_EQ(wrongHead.error().code(), fnd::ErrorCode::FailedPrecondition);
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


TEST_F(PostgresIntegrationTest, IdentityPlatformPersistenceAndOneTimeOAuthStateAreTransactional)
{
    pg::PostgresIdentityProviderStore store{*pool};

    const app::ApplicationId applicationId{"ride-app"};
    auto application = app::Application::create(
        applicationId, core::OrganizationId{"org"}, "ride", "Ride",
        app::Environment::Production, kNow);
    ASSERT_TRUE(application);
    ASSERT_TRUE(store.add(std::move(application).value()));

    auto loadedApplication = store.findById(applicationId);
    ASSERT_TRUE(loadedApplication && loadedApplication->has_value());
    EXPECT_EQ(loadedApplication->value().identifier(), "ride");
    EXPECT_EQ(loadedApplication->value().environment(), app::Environment::Production);

    auto redirect = cli::RedirectUri::create(
        "http://127.0.0.1:49152/callback", cli::ClientKind::Native);
    auto openid = cli::Scope::create("openid");
    auto profileScope = cli::Scope::create("profile");
    ASSERT_TRUE(redirect && openid && profileScope);

    const cli::ClientId clientId{"ride-native"};
    auto client = cli::Client::create(
        clientId, applicationId, "Ride Native", cli::ClientKind::Native,
        std::vector<cli::RedirectUri>{redirect.value()},
        std::vector<cli::Scope>{openid.value(), profileScope.value()},
        std::nullopt, kNow);
    ASSERT_TRUE(client);
    ASSERT_TRUE(store.add(std::move(client).value()));

    auto loadedClient = store.findById(clientId);
    ASSERT_TRUE(loadedClient && loadedClient->has_value());
    EXPECT_TRUE(loadedClient->value().isPublic());
    EXPECT_TRUE(loadedClient->value().permitsRedirect(
        "http://127.0.0.1:55001/callback"));

    auto identityProfile = profile::IdentityProfile::restore(
        core::IdentityId{"identity-1"}, std::string{"Rider One"},
        std::string{"rider-one"}, std::string{"rider@example.test"}, true,
        std::nullopt, false, std::string{"fa-IR"}, std::nullopt, kNow, kNow);
    ASSERT_TRUE(identityProfile);
    ASSERT_TRUE(store.save(identityProfile.value()));
    auto loadedProfile = store.find(core::IdentityId{"identity-1"});
    ASSERT_TRUE(loadedProfile && loadedProfile->has_value());
    ASSERT_TRUE(loadedProfile->value().email().has_value());
    EXPECT_EQ(loadedProfile->value().email().value(), "rider@example.test");
    EXPECT_TRUE(loadedProfile->value().emailVerified());

    constexpr std::string_view verifier =
        "0123456789012345678901234567890123456789012";
    auto verifierDigest = sec::sha256(verifier);
    ASSERT_TRUE(verifierDigest);
    auto challenge = oauth::PkceChallenge::create(
        fnd::toBase64Url(verifierDigest.value()));
    ASSERT_TRUE(challenge);

    const oauth::CodeDigest codeDigest{sec::sha256("stored-code").value()};
    auto authorizationCode = oauth::AuthorizationCode::create(
        codeDigest, clientId, core::IdentityId{"identity-1"},
        "http://127.0.0.1:55001/callback",
        std::vector<cli::Scope>{openid.value(), profileScope.value()},
        challenge.value(), std::string{"nonce-pg"}, idp::ProviderId{"local"},
        idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{
            idp::AuthenticationFactor::Knowledge
                | idp::AuthenticationFactor::Possession,
            false},
        kNow, kNow, std::chrono::minutes{2});
    ASSERT_TRUE(authorizationCode);
    ASSERT_TRUE(store.add(std::move(authorizationCode).value()));

    const std::string wrongChallenge = fnd::toBase64Url(
        sec::sha256("1123456789012345678901234567890123456789012").value());
    EXPECT_FALSE(store.consumeBound(
        codeDigest, kNow + std::chrono::seconds{10}, clientId.value(),
        "http://127.0.0.1:55001/callback", wrongChallenge));

    auto consumed = store.consumeBound(
        codeDigest, kNow + std::chrono::seconds{11}, clientId.value(),
        "http://127.0.0.1:55001/callback", challenge->value());
    ASSERT_TRUE(consumed);
    EXPECT_EQ(consumed->identity(), core::IdentityId{"identity-1"});
    EXPECT_FALSE(store.consumeBound(
        codeDigest, kNow + std::chrono::seconds{12}, clientId.value(),
        "http://127.0.0.1:55001/callback", challenge->value()));

    const tok::TokenFamilyId family{"family-pg"};
    tok::TokenContext context{
        clientId, core::IdentityId{"identity-1"}, idp::ProviderId{"local"},
        idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{
            idp::AuthenticationFactor::Knowledge
                | idp::AuthenticationFactor::Possession,
            false},
        std::vector<std::string>{"openid", "profile"}, kNow};
    const tok::TokenDigest accessDigest{sec::sha256("access-pg-0").value()};
    const tok::TokenDigest refreshDigest{sec::sha256("refresh-pg-0").value()};
    const auto absoluteRefreshExpiry = kNow + std::chrono::hours{24 * 30};
    ASSERT_TRUE(store.storeInitial(
        tok::AccessTokenRecord{
            accessDigest, family, context, kNow, kNow + std::chrono::minutes{15}},
        tok::RefreshTokenRecord{
            refreshDigest, family, 0U, context, kNow, absoluteRefreshExpiry}));

    auto storedAccess = store.findAccess(accessDigest);
    auto storedRefresh = store.findRefresh(refreshDigest);
    ASSERT_TRUE(storedAccess && storedRefresh);
    EXPECT_EQ(storedAccess->context().client(), clientId);
    EXPECT_EQ(storedRefresh->state(), tok::RefreshTokenState::Active);

    const tok::TokenDigest nextAccessDigest{sec::sha256("access-pg-1").value()};
    const tok::TokenDigest nextRefreshDigest{sec::sha256("refresh-pg-1").value()};
    ASSERT_TRUE(store.rotateRefresh(
        refreshDigest, kNow + std::chrono::minutes{1},
        tok::AccessTokenRecord{
            nextAccessDigest, family, context, kNow + std::chrono::minutes{1},
            kNow + std::chrono::minutes{16}},
        tok::RefreshTokenRecord{
            nextRefreshDigest, family, 1U, context,
            kNow + std::chrono::minutes{1}, absoluteRefreshExpiry}));

    auto usedRefresh = store.findRefresh(refreshDigest);
    auto rotatedRefresh = store.findRefresh(nextRefreshDigest);
    ASSERT_TRUE(usedRefresh && rotatedRefresh);
    EXPECT_EQ(usedRefresh->state(), tok::RefreshTokenState::Used);
    EXPECT_EQ(rotatedRefresh->state(), tok::RefreshTokenState::Active);
    EXPECT_EQ(rotatedRefresh->expiresAt(), absoluteRefreshExpiry);

    const auto replay = store.rotateRefresh(
        refreshDigest, kNow + std::chrono::minutes{2},
        tok::AccessTokenRecord{
            tok::TokenDigest{sec::sha256("access-pg-replay").value()}, family,
            context, kNow + std::chrono::minutes{2},
            kNow + std::chrono::minutes{17}},
        tok::RefreshTokenRecord{
            tok::TokenDigest{sec::sha256("refresh-pg-replay").value()}, family,
            1U, context, kNow + std::chrono::minutes{2}, absoluteRefreshExpiry});
    EXPECT_FALSE(replay);

    auto revokedReplacement = store.findRefresh(nextRefreshDigest);
    ASSERT_TRUE(revokedReplacement);
    EXPECT_EQ(revokedReplacement->state(), tok::RefreshTokenState::Revoked);
}

}
