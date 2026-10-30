#include <gtest/gtest.h>

#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>

#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>

#include "coroutine_auth_transaction_store.hpp"

import openproof.foundation;
import openproof.identity.provider;

namespace {
namespace asio = boost::asio;
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace pg = openproof::storage::postgres;

TEST(NativePostgresAuthenticationTransactionStoreTest,
     LegacySynchronousEntryPointsFailClosedWithoutConnecting)
{
    asio::io_context io;
    pg::CoroutinePostgresAuthenticationTransactionStore store{
        io.get_executor(),
        fnd::SecretString{"host=invalid.invalid dbname=never-connect"},
        1U, std::chrono::milliseconds{50},
        std::chrono::milliseconds{50},
        std::chrono::milliseconds{50}};

    idp::AuthenticationTransactionStore& legacy = store;
    EXPECT_NE(dynamic_cast<idp::CoroutineAuthenticationTransactionStore*>(&legacy),
              nullptr);

    idp::BindingDigest binding{};
    auto pending = idp::AuthenticationTransaction::create(
        idp::TransactionId{"unknown"}, idp::ProviderId{"neutral"},
        idp::InteractionModel::ChallengeResponse,
        fnd::SecretString{"nonce-credential"}, binding,
        fnd::CorrelationId{"correlation"},
        fnd::Instant{std::chrono::milliseconds{1000}},
        std::chrono::minutes{5});
    ASSERT_TRUE(pending);
    const auto begin = legacy.begin(std::move(*pending));
    EXPECT_FALSE(begin);
    EXPECT_EQ(begin.error().code(), fnd::ErrorCode::Unavailable);

    const auto redeemed = legacy.consume(
        idp::TransactionId{"unknown"}, fnd::SecretString{"nonce-credential"},
        binding, fnd::Instant{std::chrono::milliseconds{1500}});
    EXPECT_FALSE(redeemed);
    EXPECT_EQ(redeemed.error().code(), fnd::ErrorCode::Unavailable);

    const auto found = legacy.find(idp::TransactionId{"unknown"});
    EXPECT_FALSE(found);
    EXPECT_EQ(found.error().code(), fnd::ErrorCode::Unavailable);

    EXPECT_THROW(legacy.purgeExpired(
        fnd::Instant{std::chrono::milliseconds{1500}}), std::logic_error);
    EXPECT_THROW(legacy.size(), std::logic_error);
}
} // namespace
