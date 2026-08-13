#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <thread>
#include <vector>

import openproof.client;
import openproof.credentials;
import openproof.foundation;
import openproof.gateway;
import openproof.security;
import openproof.telemetry;

namespace client = openproof::client;
namespace cred = openproof::credentials;
namespace fnd = openproof::foundation;
namespace gw = openproof::gateway;
namespace security = openproof::security;
namespace telemetry = openproof::telemetry;

namespace {

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'770'000'000'000}};

}

TEST(HardeningTest, MalformedBoundaryCorpusNeverEscapesAsAnException)
{
    std::mt19937_64 random{0x4f70656e50726f6fULL};
    std::uniform_int_distribution<int> length{0, 180};
    std::uniform_int_distribution<int> byte{0, 255};
    for (std::size_t iteration = 0U; iteration < 10'000U; ++iteration) {
        std::string input;
        input.reserve(static_cast<std::size_t>(length(random)));
        const int count = length(random);
        for (int index = 0; index < count; ++index) {
            input.push_back(static_cast<char>(byte(random)));
        }
        EXPECT_NO_THROW({
            static_cast<void>(gw::HttpRequest::create(
                gw::HttpMethod::Get, input, {{"x-fuzz", input}}, input,
                "192.0.2.1", fnd::CorrelationId{"fuzz"}));
            static_cast<void>(cred::PasswordHash::parse(input));
            static_cast<void>(telemetry::TraceContext::parseTraceParent(input));
            static_cast<void>(client::RedirectUri::create(
                input, client::ClientKind::Web));
            static_cast<void>(client::RedirectUri::create(
                input, client::ClientKind::Native));
            static_cast<void>(security::validateRs256PublicKey(input));
            static_cast<void>(security::rsaJwkThumbprint(input, input));
            static_cast<void>(security::verifyRs256Jwk(input, input, input));
        });
    }
}

TEST(HardeningTest, ConcurrentRateLimitCannotOverspendOneBucket)
{
    fnd::ManualClockSource clock{kNow};
    auto limiter = gw::TokenBucketRateLimiter::create(clock, 100.0, 1.0, 10U).value();
    std::atomic<unsigned int> allowed{0U};
    std::vector<std::thread> workers;
    for (std::size_t worker = 0U; worker < 16U; ++worker) {
        workers.emplace_back([&] {
            for (std::size_t attempt = 0U; attempt < 100U; ++attempt) {
                if (limiter.allow("shared-client")) allowed.fetch_add(1U);
            }
        });
    }
    for (auto& worker : workers) worker.join();
    EXPECT_EQ(allowed.load(), 100U);
}

TEST(HardeningTest, ConcurrentHalfOpenCircuitAllowsExactlyOneProbe)
{
    fnd::ManualClockSource clock{kNow};
    auto circuit = gw::CircuitBreaker::create(
        clock, 1U, std::chrono::seconds{5}).value();
    const gw::EndpointId endpoint{"upstream"};
    ASSERT_TRUE(circuit.allow(endpoint));
    circuit.recordFailure(endpoint);
    clock.advance(std::chrono::seconds{5});

    std::atomic<unsigned int> probes{0U};
    std::vector<std::thread> workers;
    for (std::size_t worker = 0U; worker < 32U; ++worker) {
        workers.emplace_back([&] {
            if (circuit.allow(endpoint)) probes.fetch_add(1U);
        });
    }
    for (auto& worker : workers) worker.join();
    EXPECT_EQ(probes.load(), 1U);
}
