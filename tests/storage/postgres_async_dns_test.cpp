#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <chrono>
#include <future>
#include <stdexcept>
#include <string>
#include <utility>

#include "async_connection.hpp"

namespace {
namespace asio = boost::asio;
namespace pg = openproof::storage::postgres::async_detail;
using namespace std::chrono_literals;

void expectConnectionDenied(const std::string& dsn)
{
    asio::io_context io;
    bool refused = false;
    // Each fixture uses TCP port 1 on the local loopback only: no production
    // PostgreSQL endpoint is ever discovered or contacted by these tests.
    auto scenario = [&]() -> asio::awaitable<void> {
        try {
            auto conn = co_await pg::AsyncConnection::connect(dsn, 350ms);
            static_cast<void>(conn);
        } catch (const std::runtime_error& failure) {
            refused = true;
            const std::string message{failure.what()};
            EXPECT_EQ(message.find("openproof-test-secret"), std::string::npos);
        }
    };
    auto future = asio::co_spawn(io, scenario(), asio::use_future);
    io.run();
    ASSERT_NO_THROW(future.get());
    EXPECT_TRUE(refused);
}

TEST(PostgresAsyncDnsTest, HostnameKeywordConnectionUsesBoundedNativeDns)
{
    expectConnectionDenied(
        "host=localhost port=1 user=openproof_test "
        "dbname=openproof_disposable_test password=openproof-test-secret");
}

TEST(PostgresAsyncDnsTest, HostnameUriConnectionUsesBoundedNativeDns)
{
    expectConnectionDenied(
        "postgresql://openproof_test:openproof-test-secret@localhost:1/"
        "openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, MultipleHostsKeepPerHostPorts)
{
    expectConnectionDenied(
        "host=localhost,127.0.0.1 port=1,1 user=openproof_test "
        "dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, MultipleHostsAcceptOneSharedPort)
{
    expectConnectionDenied(
        "host=localhost,localhost port=1 user=openproof_test "
        "dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, MultiHostUriKeepsPortAssociations)
{
    expectConnectionDenied(
        "postgresql://openproof_test@localhost:1,127.0.0.1:1/"
        "openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, MixedPinnedAndResolvedHostaddrKeepsAssociations)
{
    expectConnectionDenied(
        "host=localhost,127.0.0.1 hostaddr=,127.0.0.1 "
        "port=1,1 user=openproof_test dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, PinnedFirstHostDoesNotForceDnsLookup)
{
    expectConnectionDenied(
        "host=unresolvable.invalid,localhost hostaddr=127.0.0.1, "
        "port=1,1 user=openproof_test dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, MixedUnixSocketAndHostnamePreservesFailover)
{
    expectConnectionDenied(
        "host=/tmp/openproof-no-such-pg-socket,localhost port=1,1 "
        "user=openproof_test dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, InvalidPortListFailsClosed)
{
    expectConnectionDenied(
        "host=localhost,localhost port=1,1,1 user=openproof_test "
        "dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, ExplicitHostaddrAvoidsHostnameResolution)
{
    expectConnectionDenied(
        "host=unresolvable.invalid hostaddr=127.0.0.1 port=1 "
        "user=openproof_test dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, InvalidConninfoFailsWithoutReactorConnection)
{
    expectConnectionDenied("openproof_invalid_connection_keyword=invalid");
}

} // namespace
