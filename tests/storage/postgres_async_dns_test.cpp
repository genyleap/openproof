#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <libpq-fe.h>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <future>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <unistd.h>

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

// A real libpq service file, owned only by this test and never read from
// system or production configuration.
class TemporaryServiceFile final {
public:
    TemporaryServiceFile()
    {
        char pattern[] = "/tmp/openproof-pg-service-XXXXXX";
        const int fd = ::mkstemp(pattern);
        if (fd < 0) throw std::runtime_error{"Unable to create test service file"};
        m_path = pattern;
        (void)::close(fd);
        std::ofstream output{m_path};
        output << "[openproof_async_loopback]\n"
                  "host=localhost\n"
                  "port=1\n";
        if (!output) throw std::runtime_error{"Unable to write test service file"};
    }
    TemporaryServiceFile(const TemporaryServiceFile&) = delete;
    TemporaryServiceFile& operator=(const TemporaryServiceFile&) = delete;
    ~TemporaryServiceFile() { (void)::unlink(m_path.c_str()); }
    [[nodiscard]] const std::string& path() const noexcept { return m_path; }
private:
    std::string m_path;
};

[[nodiscard]] std::string parsedConnectionOption(
    const std::string& dsn, std::string_view wanted)
{
    char* parseError = nullptr;
    PQconninfoOption* options = PQconninfoParse(dsn.c_str(), &parseError);
    if (parseError != nullptr) PQfreemem(parseError);
    if (!options) return {};
    std::string result;
    for (const PQconninfoOption* option = options;
         option->keyword != nullptr; ++option) {
        if (std::string_view{option->keyword} == wanted && option->val) {
            result = option->val;
            break;
        }
    }
    PQconninfoFree(options);
    return result;
}

void expectConnectionDenied(
    const std::string& dsn, std::string_view expectedFailure = {})
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
            if (!expectedFailure.empty()) {
                EXPECT_NE(message.find(expectedFailure), std::string::npos);
            }
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

TEST(PostgresAsyncDnsTest, InheritedPgHostUsesNativeDns)
{
    ScopedEnv pinned{"PGHOSTADDR", nullptr};
    ScopedEnv host{"PGHOST", "localhost"};
    ScopedEnv port{"PGPORT", "1"};
    expectConnectionDenied(
        "user=openproof_test dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, InheritedPgHostAndPortListsPreserveFailover)
{
    ScopedEnv pinned{"PGHOSTADDR", nullptr};
    ScopedEnv host{"PGHOST", "localhost,127.0.0.1"};
    ScopedEnv port{"PGPORT", "1,1"};
    expectConnectionDenied(
        "user=openproof_test dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, InheritedPgHostaddrDoesNotTriggerDns)
{
    ScopedEnv pinned{"PGHOSTADDR", "127.0.0.1"};
    ScopedEnv host{"PGHOST", "unresolvable.invalid"};
    ScopedEnv port{"PGPORT", "1"};
    expectConnectionDenied(
        "user=openproof_test dbname=openproof_disposable_test");
}

TEST(PostgresAsyncDnsTest, ExplicitServiceFileRejectedBeforeNetwork)
{
    TemporaryServiceFile serviceFile;
    ScopedEnv file{"PGSERVICEFILE", serviceFile.path().c_str()};
    ScopedEnv service{"PGSERVICE", nullptr};
    ScopedEnv host{"PGHOST", nullptr};
    ScopedEnv hostaddr{"PGHOSTADDR", nullptr};
    ScopedEnv port{"PGPORT", nullptr};
    const std::string dsn =
        "service=openproof_async_loopback user=openproof_test "
        "dbname=openproof_disposable_test";
    EXPECT_TRUE(parsedConnectionOption(dsn, "host").empty());
    EXPECT_TRUE(parsedConnectionOption(dsn, "port").empty());
    expectConnectionDenied(dsn, "service files");
}

TEST(PostgresAsyncDnsTest, InheritedServiceFileRejectedBeforeNetwork)
{
    TemporaryServiceFile serviceFile;
    ScopedEnv file{"PGSERVICEFILE", serviceFile.path().c_str()};
    ScopedEnv service{"PGSERVICE", "openproof_async_loopback"};
    ScopedEnv host{"PGHOST", nullptr};
    ScopedEnv hostaddr{"PGHOSTADDR", nullptr};
    ScopedEnv port{"PGPORT", nullptr};
    const std::string dsn =
        "user=openproof_test dbname=openproof_disposable_test";
    EXPECT_TRUE(parsedConnectionOption(dsn, "host").empty());
    EXPECT_TRUE(parsedConnectionOption(dsn, "port").empty());
    expectConnectionDenied(dsn, "service files");
}

TEST(PostgresAsyncDnsTest, InvalidConninfoFailsWithoutReactorConnection)
{
    expectConnectionDenied("openproof_invalid_connection_keyword=invalid");
}

} // namespace
