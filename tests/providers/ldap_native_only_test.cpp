#include <gtest/gtest.h>
#include <chrono>
#include <string>
#include <utility>

import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.enterprise;

namespace {
namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace enterprise = openproof::provider::enterprise;

TEST(LdapNativeOnlyTest, LegacyCompletionFailsClosedWithoutDirectoryNetworkIo)
{
    auto config = enterprise::LdapProviderConfig::create(
        "ldaps://directory.example.invalid:636",
        "ou=people,dc=example,dc=invalid",
        "uid", "entryUUID", "cn", "mail", {}, {},
        fnd::SecretString{std::string(32U, 'K')}, {},
        std::chrono::minutes{5});
    ASSERT_TRUE(config);
    fnd::ManualClockSource clock{
        fnd::Instant{std::chrono::milliseconds{1'790'000'000'000LL}}};
    enterprise::LdapAuthenticationProvider provider{
        std::move(config).value(), clock};
    idp::AuthenticationResponse response{
        idp::ChallengeId{"synthetic-unroutable"}, idp::ClientContext{}};
    // Even a malformed response must never make the legacy synchronous
    // entry open a connection. Native completion requires co_await.
    const auto result = provider.completeAuthentication(response);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), fnd::ErrorCode::Unavailable);
}
} // namespace
