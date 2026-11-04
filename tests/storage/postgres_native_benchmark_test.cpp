#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "async_connection.hpp"

namespace {
namespace asio = boost::asio;
namespace pg = openproof::storage::postgres::async_detail;
using namespace std::chrono_literals;

class ScopedEnv final {
public:
    ScopedEnv(const char* name, const char* replacement) : m_name(name)
    {
        if (const char* original = std::getenv(name)) {
            m_previous = std::string{original};
        }
        const int status = replacement == nullptr
            ? ::unsetenv(name) : ::setenv(name, replacement, 1);
        if (status != 0) throw std::runtime_error{"Unable to set test environment"};
    }
    ScopedEnv(const ScopedEnv&) = delete;
    ScopedEnv& operator=(const ScopedEnv&) = delete;
    ~ScopedEnv()
    {
        if (m_previous) (void)::setenv(m_name.c_str(), m_previous->c_str(), 1);
        else (void)::unsetenv(m_name.c_str());
    }
private:
    std::string m_name;
    std::optional<std::string> m_previous;
};

TEST(PostgresAsyncDnsTest, ParallelStalledConnectionsDoNotSerializeReactor)
{
    // This isolates the advantage of scheduling native libpq awaitables on
    // one Asio event loop. The sequential control uses the SAME native
    // connector, not the old PQconnectdb provider, so this is NOT an
    // end-to-end comparison of entire OpenProof runtimes.
    constexpr int attempts = 6;
    constexpr auto timeout = 180ms;
    ScopedEnv service{"PGSERVICE", nullptr};
    asio::io_context serverIo;
    asio::ip::tcp::acceptor acceptor{
        serverIo, asio::ip::tcp::endpoint{
            asio::ip::make_address("127.0.0.1"), 0U}};
    std::vector<asio::ip::tcp::socket> heldConnections;
    heldConnections.reserve(static_cast<std::size_t>(attempts * 2));
    std::atomic<int> accepted{0};

    auto acceptAll = [&]() -> asio::awaitable<void> {
        for (int index = 0; index < attempts * 2; ++index) {
            boost::system::error_code error;
            auto socket = co_await acceptor.async_accept(
                asio::redirect_error(asio::use_awaitable, error));
            if (error) co_return;
            heldConnections.emplace_back(std::move(socket));
            accepted.fetch_add(1, std::memory_order_release);
        }
    };
    asio::co_spawn(serverIo, acceptAll(), asio::detached);
    std::jthread server([&serverIo] { serverIo.run(); });

    const std::string dsn =
        "host=localhost hostaddr=127.0.0.1 port="
        + std::to_string(acceptor.local_endpoint().port())
        + " user=openproof_benchmark dbname=disposable sslmode=disable";

    std::atomic<int> expired{0};
    auto attempt = [&]() -> asio::awaitable<void> {
        try {
            static_cast<void>(co_await pg::AsyncConnection::connect(dsn, timeout));
        } catch (const std::runtime_error& failure) {
            if (std::string_view{failure.what()}.find("timed out")
                != std::string_view::npos) {
                expired.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };

    const auto serialStart = std::chrono::steady_clock::now();
    for (int index = 0; index < attempts; ++index) {
        asio::io_context client;
        auto future = asio::co_spawn(client, attempt(), asio::use_future);
        client.run();
        EXPECT_NO_THROW(future.get());
    }
    const auto serialEnd = std::chrono::steady_clock::now();
    asio::io_context concurrentClient;
    std::vector<std::future<void>> futures;
    futures.reserve(static_cast<std::size_t>(attempts));
    const auto concurrentStart = std::chrono::steady_clock::now();
    for (int index = 0; index < attempts; ++index) {
        futures.push_back(asio::co_spawn(
            concurrentClient, attempt(), asio::use_future));
    }
    concurrentClient.run();
    for (auto& future : futures) EXPECT_NO_THROW(future.get());
    const auto concurrentEnd = std::chrono::steady_clock::now();

    serverIo.stop();
    server.join();
    const auto serialMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        serialEnd - serialStart).count();
    const auto concurrentMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        concurrentEnd - concurrentStart).count();
    std::cout << "NativePgLoopbackBench attempts=" << attempts
              << " deadline_ms=" << timeout.count()
              << " sequential_ms=" << serialMs
              << " concurrent_ms=" << concurrentMs << '\n';
    EXPECT_EQ(accepted.load(std::memory_order_acquire), attempts * 2);
    EXPECT_EQ(expired.load(std::memory_order_relaxed), attempts * 2);
    // The host is shared, but socket waits do not hold the reactor thread.
    // Leave headroom for loaded CI hosts rather than asserting exact speedup.
    ASSERT_GT(serialMs, 0);
    EXPECT_LT(concurrentMs * 2, serialMs);
}

} // namespace
