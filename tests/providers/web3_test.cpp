#include <gtest/gtest.h>

#include <chrono>
#include <map>
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

[[nodiscard]] web3::WalletProviderConfig walletConfiguration()
{
    auto config = web3::WalletProviderConfig::create(
        "login.openproof.test", "https://login.openproof.test/auth/wallet",
        std::map<std::uint64_t, std::string>{},
        fnd::SecretString{std::string(48U, 'w')}, std::chrono::minutes{5});
    EXPECT_TRUE(config);
    return std::move(config).value();
}

[[nodiscard]] idp::AuthenticationRequest walletRequest(std::uint64_t chainId)
{
    idp::AuthenticationRequest value{
        idp::ProviderId{"ethereum-wallet"}, idp::ClientContext{}};
    value.setParameter("address", std::string{kAddress});
    value.setParameter("chain_id", std::to_string(chainId));
    return value;
}

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

TEST(WalletProviderTest, ChallengeUsesRequestedEvmChainWithoutRpcDependency)
{
    fnd::ManualClockSource clock{kNow};
    auto config = web3::WalletProviderConfig::create(
        "login.openproof.test", "https://login.openproof.test/auth/wallet",
        std::map<std::uint64_t, std::string>{},
        fnd::SecretString{std::string(48U, 'w')}, std::chrono::minutes{5});
    ASSERT_TRUE(config);
    web3::WalletAuthenticationProvider provider{std::move(config).value(), clock};

    idp::AuthenticationRequest baseRequest{
        idp::ProviderId{"ethereum-wallet"}, idp::ClientContext{}};
    baseRequest.setParameter("address", std::string{kAddress});
    baseRequest.setParameter("chain_id", "8453");

    auto baseChallenge = provider.beginAuthentication(baseRequest);
    ASSERT_TRUE(baseChallenge);
    EXPECT_EQ(parameter(*baseChallenge, "chain_id"), "8453");
    EXPECT_NE(parameter(*baseChallenge, "message").find("\nChain ID: 8453\n"),
              std::string::npos);

    idp::AuthenticationRequest arbitrumRequest{
        idp::ProviderId{"ethereum-wallet"}, idp::ClientContext{}};
    arbitrumRequest.setParameter("address", std::string{kAddress});
    arbitrumRequest.setParameter("chain_id", "42161");

    auto arbitrumChallenge = provider.beginAuthentication(arbitrumRequest);
    ASSERT_TRUE(arbitrumChallenge);
    EXPECT_EQ(parameter(*arbitrumChallenge, "chain_id"), "42161");
    EXPECT_NE(parameter(*arbitrumChallenge, "message").find("\nChain ID: 42161\n"),
              std::string::npos);
}

TEST(WalletProviderTest, SmartWalletRpcMappingsAreChainSpecific)
{
    auto config = web3::WalletProviderConfig::create(
        "login.openproof.test", "https://login.openproof.test/auth/wallet",
        std::map<std::uint64_t, std::string>{
            {1U, "https://ethereum-rpc.openproof.test"},
            {8453U, "https://base-rpc.openproof.test"}},
        fnd::SecretString{std::string(48U, 'w')}, std::chrono::minutes{5});
    ASSERT_TRUE(config);
    ASSERT_TRUE(config->rpcEndpoint(1U));
    ASSERT_TRUE(config->rpcEndpoint(8453U));
    EXPECT_EQ(*config->rpcEndpoint(1U), "https://ethereum-rpc.openproof.test");
    EXPECT_EQ(*config->rpcEndpoint(8453U), "https://base-rpc.openproof.test");
    EXPECT_FALSE(config->rpcEndpoint(42161U));
}

TEST(WalletProviderTest, ChallengeUsesTheWalletsRequestedEvmChain)
{
    fnd::ManualClockSource clock{kNow};
    web3::WalletAuthenticationProvider provider{walletConfiguration(), clock};

    for (const std::uint64_t chainId : {1U, 8453U, 42161U, 10U, 5042U, 4663U}) {
        auto challenge = provider.beginAuthentication(walletRequest(chainId));
        ASSERT_TRUE(challenge);
        EXPECT_EQ(parameter(*challenge, "chain_id"), std::to_string(chainId));
        EXPECT_NE(parameter(*challenge, "message").find(
                      "\nChain ID: " + std::to_string(chainId) + "\n"),
                  std::string::npos);
        EXPECT_NE(challenge->id().value().find(
                      "siwe_" + std::to_string(kNow.time_since_epoch().count())
                      + "_" + std::to_string(chainId) + "_"),
                  std::string::npos);
    }
}

TEST(WalletProviderTest, ConfigurationCanEnableEoaLoginWithoutAnyRpcDependency)
{
    auto config = walletConfiguration();
    EXPECT_FALSE(config.rpcEndpoint(1U).has_value());
    EXPECT_FALSE(config.rpcEndpoint(8453U).has_value());
    EXPECT_FALSE(config.rpcEndpoint(42161U).has_value());
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
    EXPECT_EQ(parameter(*challenge, "resource_prefix"), "farcaster://fid/");
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
    EXPECT_NE(message.find("\nResources:\n- farcaster://fid/6841"), std::string::npos);
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

TEST(FarcasterProviderTest, AcceptsLegacyPluralFidResourceDuringMigration)
{
    fnd::ManualClockSource clock{kNow};
    auto chain = std::make_unique<FakeFarcasterChain>();
    web3::FarcasterAuthenticationProvider provider{
        configuration(), clock, std::move(chain)};
    auto challenge = provider.beginAuthentication(request(true));
    ASSERT_TRUE(challenge);
    std::string message = parameter(*challenge, "message");
    const auto current = message.find("farcaster://fid/");
    ASSERT_NE(current, std::string::npos);
    message.replace(current, std::string_view{"farcaster://fid/"}.size(),
                    "farcaster://fids/");

    auto outcome = provider.completeAuthentication(
        response(*challenge, std::move(message)));

    ASSERT_TRUE(outcome);
    EXPECT_EQ(outcome->subject(), idp::ExternalSubject{"6841"});
}

TEST(FarcasterProviderTest, AcceptsCurrentSdkCompatibilityVariants)
{
    fnd::ManualClockSource clock{kNow};
    auto chain = std::make_unique<FakeFarcasterChain>();
    web3::FarcasterAuthenticationProvider provider{
        configuration(), clock, std::move(chain)};
    auto challenge = provider.beginAuthentication(request(true));
    ASSERT_TRUE(challenge);
    std::string message = parameter(*challenge, "message");

    const auto statement = message.find("Farcaster Auth");
    ASSERT_NE(statement, std::string::npos);
    message.replace(statement, std::string_view{"Farcaster Auth"}.size(),
                    "Farcaster Connect");

    const auto resource = message.find("farcaster://fid/6841");
    ASSERT_NE(resource, std::string::npos);
    message.insert(resource + std::string_view{"farcaster://fid/6841"}.size(), "/");
    message.append("\n- https://example.com/resource");

    auto outcome = provider.completeAuthentication(
        response(*challenge, std::move(message)));

    ASSERT_TRUE(outcome);
    EXPECT_EQ(outcome->subject(), idp::ExternalSubject{"6841"});
}

TEST(FarcasterProviderTest, AcceptsOptionalSiweFieldsBeforeResources)
{
    fnd::ManualClockSource clock{kNow};
    auto chain = std::make_unique<FakeFarcasterChain>();
    web3::FarcasterAuthenticationProvider provider{
        configuration(), clock, std::move(chain)};
    auto challenge = provider.beginAuthentication(request(true));
    ASSERT_TRUE(challenge);
    std::string message = parameter(*challenge, "message");

    const auto resources = message.find("\nResources:");
    ASSERT_NE(resources, std::string::npos);
    message.insert(resources,
        "\nNot Before: 2025-01-15T12:00:00.000Z"
        "\nRequest ID: openproof-test");

    auto outcome = provider.completeAuthentication(
        response(*challenge, std::move(message)));

    ASSERT_TRUE(outcome);
    EXPECT_EQ(outcome->subject(), idp::ExternalSubject{"6841"});
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
