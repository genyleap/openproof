#include <gtest/gtest.h>

#include <chrono>
#include <optional>
#include <utility>

import openproof.evidence.verifiers;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

namespace {
namespace evidence = openproof::evidence::verification;
namespace fnd = openproof::foundation;
namespace identity = openproof::identity::core;
namespace idp = openproof::identity::provider;

constexpr fnd::Instant kNow{std::chrono::seconds{1'770'000'000}};

class MemoryChallengeStore final : public evidence::ChallengeStore {
public:
    [[nodiscard]] fnd::Status add(evidence::Challenge challenge) override
    {
        if (m_challenge.has_value()) return fnd::fail(fnd::ErrorCode::AlreadyExists);
        m_challenge = std::move(challenge);
        return fnd::ok();
    }

    [[nodiscard]] fnd::Status consume(
        const evidence::ChallengeDigest& digest, const identity::IdentityId& identity,
        const idp::ProviderId& provider, fnd::Instant now) override
    {
        if (!m_challenge || m_consumed) return fnd::fail(fnd::ErrorCode::NotFound);
        if (m_challenge->digest() != digest || m_challenge->identity() != identity
            || m_challenge->provider() != provider) {
            return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        }
        if (now > m_challenge->expiresAt()) return fnd::fail(fnd::ErrorCode::AuthenticationFailed);
        m_consumed = true;
        return fnd::ok();
    }

private:
    std::optional<evidence::Challenge> m_challenge;
    bool m_consumed{};
};

TEST(EvidenceChallengeTest, ChallengeIsBoundAndSingleUse)
{
    MemoryChallengeStore store;
    fnd::ManualClockSource clock{kNow};
    evidence::ChallengeService challenges{store, clock, std::chrono::minutes{5}};
    const identity::IdentityId identityId{"identity-proof"};
    const idp::ProviderId provider{"signed-jwt-evidence"};

    auto issued = challenges.issue(identityId, provider);
    ASSERT_TRUE(issued);
    EXPECT_FALSE(issued->token.empty());
    EXPECT_EQ(issued->expiresAt, kNow + std::chrono::minutes{5});

    auto wrongIdentity = challenges.consume(
        identity::IdentityId{"other-identity"}, provider, issued->token);
    ASSERT_FALSE(wrongIdentity);

    ASSERT_TRUE(challenges.consume(identityId, provider, issued->token));
    auto replay = challenges.consume(identityId, provider, issued->token);
    ASSERT_FALSE(replay);
}

TEST(EvidenceChallengeTest, ExpiredChallengeIsRejected)
{
    MemoryChallengeStore store;
    fnd::ManualClockSource clock{kNow};
    evidence::ChallengeService challenges{store, clock, std::chrono::minutes{1}};
    const identity::IdentityId identityId{"identity-expired"};
    const idp::ProviderId provider{"x509-evidence"};

    auto issued = challenges.issue(identityId, provider);
    ASSERT_TRUE(issued);
    clock.advance(std::chrono::minutes{2});

    auto expired = challenges.consume(identityId, provider, issued->token);
    ASSERT_FALSE(expired);
}

} // namespace
