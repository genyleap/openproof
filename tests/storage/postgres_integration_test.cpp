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
import openproof.credentials;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;
import openproof.session;
import openproof.storage.postgres;

namespace {

namespace core = openproof::identity::core;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace pg = openproof::storage::postgres;
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

[[nodiscard]] sess::Session sessionValue(std::string_view token)
{
    return sess::Session::create(
        sess::SessionId{"session-1"}, core::IdentityId{"identity-1"},
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

}
