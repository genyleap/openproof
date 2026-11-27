#include "../../src/gateway/asio_service_ids_extern.hpp"
#include <gtest/gtest.h>
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio.hpp>
#include <chrono>
#include <future>
#include <optional>
#include <string>
#include <utility>
#include "coroutine_local_provider.hpp"

namespace {
namespace asio = boost::asio;
namespace local = openproof::provider::local;
namespace idp = openproof::identity::provider;
namespace fnd = openproof::foundation;
using namespace std::chrono_literals;

class Verifier final : public local::CoroutineLocalProofVerifier {
public:
    local::LocalVerification result = local::LocalVerification::Password;
    bool denied = false;
    unsigned int calls = 0U;
    asio::awaitable<fnd::Result<local::LocalCredentialProof>> verifyAsync(
        idp::ExternalSubject subject, fnd::SecretString password,
        std::optional<fnd::SecretString>, std::optional<fnd::SecretString>, fnd::Instant) override
    {
        ++calls;
        if (denied || subject.value() != "alice" || password.expose() != "fixture-password")
            co_return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        co_return local::LocalCredentialProof{result, "fixture-owner",fnd::Instant{1770000000000ms}};
    }
};
struct Fixture {
    asio::io_context io;
    fnd::ManualClockSource clock{fnd::Instant{1770000000000ms}};
    Verifier verifier;
    local::CoroutineLocalAuthenticationProvider provider{idp::ProviderId{"local"}, verifier, clock, 5min};
    template<class T> T run(asio::awaitable<T> task) {
        io.restart();
        std::optional<T> value;
        auto capture = [](asio::awaitable<T> pending, std::optional<T>& output) -> asio::awaitable<void> {
            output.emplace(co_await std::move(pending));
        };
        auto result = asio::co_spawn(io, capture(std::move(task), value), asio::use_future);
        io.run();
        result.get();
        return std::move(value.value());
    }
    static idp::AuthenticationResponse response(bool totp = false, bool recovery = false) {
        idp::AuthenticationResponse value{idp::ChallengeId{"fixture"}, idp::ClientContext{}};
        value.setParameter("subject", idp::CredentialValue{std::string{"alice"}});
        value.setParameter("password", idp::CredentialValue{std::string{"fixture-password"}});
        if (totp) value.setParameter("totp", idp::CredentialValue{std::string{"123456"}});
        if (recovery) value.setParameter("recovery_code", idp::CredentialValue{std::string{"fixture-recovery"}});
        return value;
    }
};

TEST(NativeLocalProviderTest, ChallengeAndPasswordAssurance)
{
    Fixture f;
    idp::AuthenticationRequest request{idp::ProviderId{"local"}, idp::ClientContext{}};
    request.setParameter("subject", "alice");
    auto challenge = f.run(f.provider.beginAuthenticationAsync(std::move(request)));
    ASSERT_TRUE(challenge);
    EXPECT_EQ(challenge->expiresAt(), f.clock.now() + 5min);
    EXPECT_EQ(f.verifier.calls, 0U);
    auto proof = f.run(f.provider.completeAuthenticationAsync(Fixture::response()));
    ASSERT_TRUE(proof);
    EXPECT_EQ(proof->claimedAssurance(), idp::AssuranceLevel::Ial1);
    ASSERT_TRUE(proof->requiredCanonicalOwner());
    EXPECT_EQ(*proof->requiredCanonicalOwner(), "fixture-owner");
    ASSERT_TRUE(proof->passwordGeneration());
    EXPECT_EQ(*proof->passwordGeneration(),fnd::Instant{1770000000000ms});
    EXPECT_FALSE(proof->strength().isMultiFactor());
    EXPECT_FALSE(f.provider.completeAuthentication(Fixture::response()));
    EXPECT_EQ(f.verifier.calls, 1U);
}

TEST(NativeLocalProviderTest, FactorAssuranceAndFailClosed)
{
    Fixture f;
    f.verifier.result = local::LocalVerification::PasswordAndTotp;
    EXPECT_FALSE(f.run(f.provider.completeAuthenticationAsync(Fixture::response())));
    auto totp = f.run(f.provider.completeAuthenticationAsync(Fixture::response(true)));
    ASSERT_TRUE(totp);
    EXPECT_EQ(totp->claimedAssurance(), idp::AssuranceLevel::Ial2);
    EXPECT_TRUE(totp->strength().isMultiFactor());
    f.verifier.result = local::LocalVerification::PasswordAndRecoveryCode;
    auto recovery = f.run(f.provider.completeAuthenticationAsync(Fixture::response(false, true)));
    ASSERT_TRUE(recovery);
    EXPECT_EQ(recovery->claimedAssurance(), idp::AssuranceLevel::Ial2);
    EXPECT_FALSE(f.run(f.provider.completeAuthenticationAsync(Fixture::response(true))));
    const auto before = f.verifier.calls;
    EXPECT_FALSE(f.run(f.provider.completeAuthenticationAsync(Fixture::response(true, true))));
    EXPECT_EQ(f.verifier.calls, before);
    f.verifier.denied = true;
    EXPECT_FALSE(f.run(f.provider.completeAuthenticationAsync(Fixture::response(false, true))));
}
}
