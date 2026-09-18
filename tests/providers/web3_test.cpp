#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

import openproof.foundation;
import openproof.identity.provider;
import openproof.provider.web3;

namespace {

namespace fnd = openproof::foundation;
namespace idp = openproof::identity::provider;
namespace web3 = openproof::provider::web3;

constexpr fnd::Instant kNow{std::chrono::milliseconds{1'788'086'400'000LL}};
constexpr std::string_view kAddress{"0x1111111111111111111111111111111111111111"};
constexpr std::uint64_t kFid = 6841U;

class FakeFarcasterChain final : public web3::FarcasterChainVerifier {
public:
    fnd::Result<bool> chainMatches() override { return matchingChain; }

    fnd::Result<bool> verifySignature(
        std::string_view address, std::string_view message,
        std::string_view signature) override
    {
        lastAddress = address;
        lastMessage = message;
        lastSignature = signature;
        ++signatureChecks;
        return validSignature;
    }

    fnd::Result<std::optional<web3::FarcasterSignerKind>> authorizeSigner(
        std::uint64_t fid, std::string_view address) override
    {
        lastFid = fid;
        lastAddress = address;
        ++authorizationChecks;
        return authorization;
    }

    bool matchingChain{true};
    bool validSignature{true};
    std::optional<web3::FarcasterSignerKind> authorization{
        web3::FarcasterSignerKind::Custody};
    int signatureChecks{};
    int authorizationChecks{};
    std::uint64_t lastFid{};
    std::string lastAddress;
    std::string lastMessage;
    std::string lastSignature;
};

[[nodiscard]] web3::FarcasterProviderConfig configuration(
    std::uint64_t chainId = 10U, std::string keyRegistry =
        "0x00000000fc1237824fb747abde0ff18990e59b7e")
{
    auto config = web3::FarcasterProviderConfig::create(
        "login.openproof.test", "https://login.openproof.test/auth/farcaster",
        chainId, "https://optimism-rpc.openproof.test",
        "0x00000000fc6c5f01fc30151999387bb99a9f489b",
        fnd::SecretString{std::string(48U, 'f')}, std::chrono::minutes{5}, {}, {},
        std::move(keyRegistry));
    EXPECT_TRUE(config);
    return std::move(config).value();
}

[[nodiscard]] idp::AuthenticationRequest request(bool direct)
{
    idp::AuthenticationRequest value{idp::ProviderId{"farcaster"}, idp::ClientContext{}};
    if (direct) {
        value.setParameter("address", std::string{kAddress});
        value.setParameter("fid", std::to_string(kFid));
    }
    return value;
}

[[nodiscard]] idp::AuthenticationResponse response(
    const idp::AuthenticationChallenge& challenge, std::string message)
{
    idp::AuthenticationResponse value{challenge.id(), idp::ClientContext{}};
    value.setParameter("message", idp::CredentialValue{std::move(message)});
    value.setParameter("signature", idp::CredentialValue{"0x0102"});
    return value;
}

[[nodiscard]] std::string parameter(
    const idp::AuthenticationChallenge& challenge, std::string_view name)
{
    const auto found = challenge.parameters().find(name);
    EXPECT_NE(found, challenge.parameters().end());
    return found == challenge.parameters().end() ? std::string{} : found->second;
}

TEST(FarcasterProviderTest, ConfigurationRequiresFip11OptimismMainnet)
{
    auto wrongChain = web3::FarcasterProviderConfig::create(
        "login.openproof.test", "https://login.openproof.test/auth/farcaster",
        8453U, "https://rpc.openproof.test",
        "0x00000000fc6c5f01fc30151999387bb99a9f489b",
        fnd::SecretString{std::string(48U, 'f')}, std::chrono::minutes{5});
    EXPECT_FALSE(wrongChain);

    auto invalidKeyRegistry = web3::FarcasterProviderConfig::create(
        "login.openproof.test", "https://login.openproof.test/auth/farcaster",
        10U, "https://rpc.openproof.test",
        "0x00000000fc6c5f01fc30151999387bb99a9f489b",
        fnd::SecretString{std::string(48U, 'f')}, std::chrono::minutes{5}, {}, {},
        "not-an-address");
    EXPECT_FALSE(invalidKeyRegistry);
}

TEST(FarcasterProviderTest, RelayStartPublishesAuthKitConfigurationWithoutRequiringAnAddress)
{
    fnd::ManualClockSource clock{kNow};
    auto chain = std::make_unique<FakeFarcasterChain>();
    auto* observed = chain.get();
    web3::FarcasterAuthenticationProvider provider{
        configuration(), clock, std::move(chain)};

    auto challenge = provider.beginAuthentication(request(false));

    ASSERT_TRUE(challenge);
    EXPECT_EQ(observed->authorizationChecks, 0);
    EXPECT_EQ(parameter(*challenge, "domain"), "login.openproof.test");
    EXPECT_EQ(parameter(*challenge, "uri"),
              "https://login.openproof.test/auth/farcaster");
    EXPECT_EQ(parameter(*challenge, "statement"), "Farcaster Auth");
    EXPECT_EQ(parameter(*challenge, "chain_id"), "10");
    EXPECT_EQ(parameter(*challenge, "resource_prefix"), "farcaster://fids/");
    EXPECT_EQ(parameter(*challenge, "nonce").size(), 32U);
    EXPECT_FALSE(challenge->parameters().contains("message"));
}

TEST(FarcasterProviderTest, DirectCustodyFlowUsesCanonicalFip11Message)
{
    fnd::ManualClockSource clock{kNow};
    auto chain = std::make_unique<FakeFarcasterChain>();
    auto* observed = chain.get();
    web3::FarcasterAuthenticationProvider provider{
        configuration(), clock, std::move(chain)};

    auto challenge = provider.beginAuthentication(request(true));
    ASSERT_TRUE(challenge);
    const std::string message = parameter(*challenge, "message");
    EXPECT_NE(message.find("\n\nFarcaster Auth\n\n"), std::string::npos);
    EXPECT_NE(message.find("\nChain ID: 10\n"), std::string::npos);
    EXPECT_NE(message.find("\nResources:\n- farcaster://fids/6841"), std::string::npos);
    EXPECT_EQ(message.find("Request ID:"), std::string::npos);
    EXPECT_EQ(parameter(*challenge, "signer_kind"), "custody");

    auto outcome = provider.completeAuthentication(response(*challenge, message));
    ASSERT_TRUE(outcome);
    EXPECT_EQ(outcome->subject(), idp::ExternalSubject{"6841"});
    EXPECT_EQ(outcome->claims().getExtension("signer_kind"), "custody");
    EXPECT_EQ(outcome->evidence().get("protocol"), "farcaster_fip11_siwf");
    EXPECT_EQ(observed->signatureChecks, 1);
    EXPECT_EQ(observed->authorizationChecks, 2);
    EXPECT_EQ(observed->lastFid, kFid);
}

TEST(FarcasterProviderTest, AuthAddressIsAcceptedAndRecordedDistinctly)
{
    fnd::ManualClockSource clock{kNow};
    auto chain = std::make_unique<FakeFarcasterChain>();
    chain->authorization = web3::FarcasterSignerKind::AuthAddress;
    web3::FarcasterAuthenticationProvider provider{
        configuration(), clock, std::move(chain)};
    auto challenge = provider.beginAuthentication(request(true));
    ASSERT_TRUE(challenge);

    auto outcome = provider.completeAuthentication(
        response(*challenge, parameter(*challenge, "message")));

    ASSERT_TRUE(outcome);
    EXPECT_EQ(outcome->claims().getExtension("signer_kind"), "auth_address");
    EXPECT_FALSE(outcome->claims().getExtension("custody_address").has_value());
    EXPECT_TRUE(outcome->evidence().get("key_registry").has_value());
}

TEST(FarcasterProviderTest, RejectsLegacyCustomStatementBeforeSignatureVerification)
{
    fnd::ManualClockSource clock{kNow};
    auto chain = std::make_unique<FakeFarcasterChain>();
    auto* observed = chain.get();
    web3::FarcasterAuthenticationProvider provider{
        configuration(), clock, std::move(chain)};
    auto challenge = provider.beginAuthentication(request(true));
    ASSERT_TRUE(challenge);
    std::string message = parameter(*challenge, "message");
    message.replace(message.find("Farcaster Auth"), std::string_view{"Farcaster Auth"}.size(),
                    "Sign in to OpenProof with this FID");

    auto outcome = provider.completeAuthentication(response(*challenge, std::move(message)));

    EXPECT_FALSE(outcome);
    EXPECT_EQ(outcome.error().code(), fnd::ErrorCode::AuthenticationFailed);
    EXPECT_EQ(observed->signatureChecks, 0);
}

TEST(FarcasterProviderTest, RechecksAuthorizationAfterSignatureAndFailsClosedOnRevocation)
{
    fnd::ManualClockSource clock{kNow};
    auto chain = std::make_unique<FakeFarcasterChain>();
    auto* observed = chain.get();
    web3::FarcasterAuthenticationProvider provider{
        configuration(), clock, std::move(chain)};
    auto challenge = provider.beginAuthentication(request(true));
    ASSERT_TRUE(challenge);
    observed->authorization.reset();

    auto outcome = provider.completeAuthentication(
        response(*challenge, parameter(*challenge, "message")));

    EXPECT_FALSE(outcome);
    EXPECT_EQ(observed->signatureChecks, 1);
    EXPECT_EQ(observed->authorizationChecks, 2);
}

} // namespace
