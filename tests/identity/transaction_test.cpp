#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

import openproof.foundation;
import openproof.identity.provider;
import openproof.security;

namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace sec = openproof::security;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};
constexpr fnd::Duration kLifetime{std::chrono::milliseconds{300'000}};

[[nodiscard]] idp::BindingDigest bindingOf(std::string_view agentSecret)
{
    const auto digest = sec::sha256(agentSecret);
    EXPECT_TRUE(digest.has_value());
    return digest.value_or(idp::BindingDigest{});
}

[[nodiscard]] idp::AuthenticationTransaction makeTransaction(std::string nonce = "server-nonce",
                                                             std::string_view agent = "agent-a")
{
    auto transaction = idp::AuthenticationTransaction::create(
        idp::TransactionId{"txn-1"}, idp::ProviderId{"any-provider"},
        idp::InteractionModel::Redirect, std::move(nonce), bindingOf(agent),
        fnd::CorrelationId{"corr-1"}, kNow, kLifetime);
    EXPECT_TRUE(transaction.has_value());
    return std::move(transaction).value();
}

TEST(AuthenticationTransactionTest, StartsPendingAndRedeemsOnce)
{
    idp::AuthenticationTransaction transaction = makeTransaction();

    EXPECT_EQ(transaction.state(), idp::TransactionState::Pending);
    EXPECT_TRUE(transaction.isPendingAt(kNow));

    EXPECT_TRUE(transaction.consume("server-nonce", bindingOf("agent-a"), kNow).has_value());
    EXPECT_EQ(transaction.state(), idp::TransactionState::Consumed);
}

TEST(AuthenticationTransactionTest, RejectsCreationWithoutANonce)
{
    const auto transaction = idp::AuthenticationTransaction::create(
        idp::TransactionId{"txn-1"}, idp::ProviderId{"p"}, idp::InteractionModel::Redirect, "",
        bindingOf("agent-a"), fnd::CorrelationId{"corr-1"}, kNow, kLifetime);

    ASSERT_FALSE(transaction.has_value());
    EXPECT_EQ(transaction.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(AuthenticationTransactionTest, RejectsNonPositiveLifetime)
{
    const auto transaction = idp::AuthenticationTransaction::create(
        idp::TransactionId{"txn-1"}, idp::ProviderId{"p"}, idp::InteractionModel::Redirect, "n",
        bindingOf("agent-a"), fnd::CorrelationId{"corr-1"}, kNow, fnd::Duration::zero());

    ASSERT_FALSE(transaction.has_value());
    EXPECT_EQ(transaction.error().code(), fnd::ErrorCode::InvalidArgument);
}

// --- Attack 1: replay -------------------------------------------------------

TEST(AuthenticationTransactionTest, ReplayOfAConsumedTransactionIsRefused)
{
    idp::AuthenticationTransaction transaction = makeTransaction();

    ASSERT_TRUE(transaction.consume("server-nonce", bindingOf("agent-a"), kNow).has_value());

    const fnd::Status replay =
        transaction.consume("server-nonce", bindingOf("agent-a"), kNow);

    ASSERT_FALSE(replay.has_value());
    EXPECT_EQ(replay.error().code(), fnd::ErrorCode::FailedPrecondition);
    EXPECT_EQ(transaction.state(), idp::TransactionState::Consumed);
}

// --- Attack 2: nonce reuse / substitution -----------------------------------

TEST(AuthenticationTransactionTest, WrongNonceFailsTheTransactionTerminally)
{
    idp::AuthenticationTransaction transaction = makeTransaction();

    const fnd::Status attempt =
        transaction.consume("attacker-nonce", bindingOf("agent-a"), kNow);

    ASSERT_FALSE(attempt.has_value());
    EXPECT_EQ(attempt.error().code(), fnd::ErrorCode::AuthenticationFailed);

    // Terminal: the transaction must not remain a probeable oracle.
    EXPECT_EQ(transaction.state(), idp::TransactionState::Failed);

    const fnd::Status correct =
        transaction.consume("server-nonce", bindingOf("agent-a"), kNow);
    ASSERT_FALSE(correct.has_value())
        << "a transaction must not become redeemable again after a failed attempt";
}

// --- Attack 3: expiry -------------------------------------------------------

TEST(AuthenticationTransactionTest, ExpiryIsEvaluatedAtRedemptionAndIsInclusive)
{
    idp::AuthenticationTransaction transaction = makeTransaction();
    const fnd::Instant deadline = transaction.expiresAt();

    EXPECT_FALSE(transaction.isExpiredAt(deadline - std::chrono::milliseconds{1}));
    EXPECT_TRUE(transaction.isExpiredAt(deadline));

    const fnd::Status attempt =
        transaction.consume("server-nonce", bindingOf("agent-a"), deadline);

    ASSERT_FALSE(attempt.has_value());
    EXPECT_EQ(attempt.error().code(), fnd::ErrorCode::FailedPrecondition);
    EXPECT_EQ(transaction.state(), idp::TransactionState::Expired);
}

// --- Attack 4: cross-session substitution (login CSRF) ----------------------

TEST(AuthenticationTransactionTest, AnotherAgentCannotRedeemAValidAnswer)
{
    idp::AuthenticationTransaction transaction = makeTransaction("server-nonce", "victim-agent");

    // The attacker has the correct nonce -- a stolen or observed callback -- but
    // presents it from their own session.
    const fnd::Status attempt =
        transaction.consume("server-nonce", bindingOf("attacker-agent"), kNow);

    ASSERT_FALSE(attempt.has_value());
    EXPECT_EQ(attempt.error().code(), fnd::ErrorCode::AuthenticationFailed);
    EXPECT_EQ(transaction.state(), idp::TransactionState::Failed);
}

// The client-facing message must not say which of the two checks failed.
TEST(AuthenticationTransactionTest, FailureMessageDoesNotDistinguishNonceFromBinding)
{
    idp::AuthenticationTransaction wrongNonce = makeTransaction();
    idp::AuthenticationTransaction wrongBinding = makeTransaction();

    const fnd::Status a = wrongNonce.consume("bad", bindingOf("agent-a"), kNow);
    const fnd::Status b = wrongBinding.consume("server-nonce", bindingOf("other"), kNow);

    ASSERT_FALSE(a.has_value());
    ASSERT_FALSE(b.has_value());
    EXPECT_EQ(a.error().message(), b.error().message());
    EXPECT_EQ(a.error().code(), b.error().code());
    // The operator-only channel may and should distinguish them.
    EXPECT_NE(a.error().internalDetail(), b.error().internalDetail());
}

// --- Store: single-use enforcement -----------------------------------------

TEST(TransactionStoreTest, BeginRejectsAReusedIdentifier)
{
    idp::InMemoryAuthenticationTransactionStore store;

    ASSERT_TRUE(store.begin(makeTransaction()).has_value());

    const fnd::Status duplicate = store.begin(makeTransaction());
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code(), fnd::ErrorCode::AlreadyExists);
    EXPECT_EQ(store.size(), 1U);
}

TEST(TransactionStoreTest, UnknownIdentifierFailsAsAuthenticationFailure)
{
    idp::InMemoryAuthenticationTransactionStore store;

    const auto consumed =
        store.consume(idp::TransactionId{"absent"}, "n", bindingOf("agent-a"), kNow);

    ASSERT_FALSE(consumed.has_value());
    // Not NotFound: whether a transaction exists must not be a probeable signal.
    EXPECT_EQ(consumed.error().code(), fnd::ErrorCode::AuthenticationFailed);
}

TEST(TransactionStoreTest, ConsumeSucceedsExactlyOnce)
{
    idp::InMemoryAuthenticationTransactionStore store;
    ASSERT_TRUE(store.begin(makeTransaction()).has_value());

    const auto first =
        store.consume(idp::TransactionId{"txn-1"}, "server-nonce", bindingOf("agent-a"), kNow);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->state(), idp::TransactionState::Consumed);

    const auto second =
        store.consume(idp::TransactionId{"txn-1"}, "server-nonce", bindingOf("agent-a"), kNow);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code(), fnd::ErrorCode::FailedPrecondition);
}

// Single-use enforcement is only real if the check and the state change are
// atomic. Without that, concurrent redemptions both observe Pending and both
// succeed -- which is the defect this store exists to prevent.
TEST(TransactionStoreTest, ConcurrentRedemptionYieldsExactlyOneWinner)
{
    for (int attempt = 0; attempt < 20; ++attempt) {
        idp::InMemoryAuthenticationTransactionStore store;
        ASSERT_TRUE(store.begin(makeTransaction()).has_value());

        constexpr int kThreads = 8;
        std::atomic<int> successes{0};
        std::vector<std::jthread> racers;
        racers.reserve(kThreads);

        for (int index = 0; index < kThreads; ++index) {
            racers.emplace_back([&store, &successes] {
                const auto result = store.consume(idp::TransactionId{"txn-1"}, "server-nonce",
                                                  bindingOf("agent-a"), kNow);
                if (result.has_value()) {
                    successes.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        racers.clear();

        EXPECT_EQ(successes.load(std::memory_order_relaxed), 1)
            << "attempt " << attempt << ": a transaction was redeemed more than once";
    }
}

TEST(TransactionStoreTest, PurgeRemovesOnlyExpiredTransactions)
{
    idp::InMemoryAuthenticationTransactionStore store;
    ASSERT_TRUE(store.begin(makeTransaction()).has_value());

    EXPECT_EQ(store.purgeExpired(kNow), 0U);
    EXPECT_EQ(store.size(), 1U);

    EXPECT_EQ(store.purgeExpired(kNow + kLifetime), 1U);
    EXPECT_EQ(store.size(), 0U);
}

TEST(TransactionStoreTest, FindReportsAbsenceAsEmptyOptional)
{
    idp::InMemoryAuthenticationTransactionStore store;

    const auto missing = store.find(idp::TransactionId{"absent"});
    ASSERT_TRUE(missing.has_value());
    EXPECT_FALSE(missing.value().has_value());
}

}
