module;

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

export module openproof.provider.web3;

import openproof.foundation;
import openproof.identity.provider;

export namespace openproof::provider::web3 {

/** @brief Validated SIWE configuration for an Ethereum wallet authentication provider. */
class WalletProviderConfig final {
public:
    [[nodiscard]] static foundation::Result<WalletProviderConfig> create(
        std::string domain, std::string uri, std::uint64_t chainId,
        std::string rpcEndpoint, foundation::SecretString derivationKey,
        foundation::Duration challengeLifetime, std::string caFile = {},
        foundation::SecretString authorizationHeader = {});

    WalletProviderConfig(const WalletProviderConfig&) = delete;
    WalletProviderConfig& operator=(const WalletProviderConfig&) = delete;
    WalletProviderConfig(WalletProviderConfig&&) noexcept = default;
    WalletProviderConfig& operator=(WalletProviderConfig&&) noexcept = default;

    [[nodiscard]] std::string_view domain() const noexcept;
    [[nodiscard]] std::string_view uri() const noexcept;
    [[nodiscard]] std::uint64_t chainId() const noexcept;
    [[nodiscard]] std::string_view rpcEndpoint() const noexcept;
    [[nodiscard]] const foundation::SecretString& derivationKey() const noexcept;
    [[nodiscard]] foundation::Duration challengeLifetime() const noexcept;
    [[nodiscard]] std::string_view caFile() const noexcept;
    [[nodiscard]] const foundation::SecretString& authorizationHeader() const noexcept;

private:
    WalletProviderConfig(std::string domain, std::string uri, std::uint64_t chainId,
                         std::string rpcEndpoint, foundation::SecretString derivationKey,
                         foundation::Duration challengeLifetime, std::string caFile,
                         foundation::SecretString authorizationHeader);

    std::string m_domain;
    std::string m_uri;
    std::uint64_t m_chainId{};
    std::string m_rpcEndpoint;
    foundation::SecretString m_derivationKey;
    foundation::Duration m_challengeLifetime{};
    std::string m_caFile;
    foundation::SecretString m_authorizationHeader;
};

/** @brief ERC-4361 Sign-In with Ethereum provider supporting EOAs and ERC-1271 wallets. */
class WalletAuthenticationProvider final : public identity::provider::AuthenticationProvider {
public:
    WalletAuthenticationProvider(WalletProviderConfig config,
                                 const foundation::ClockSource& clock);
    ~WalletAuthenticationProvider() override;

    [[nodiscard]] identity::provider::ProviderId id() const override;
    [[nodiscard]] identity::provider::InteractionModel interactionModel() const noexcept override;
    [[nodiscard]] identity::provider::AssuranceLevel maximumClaimableAssurance() const noexcept override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationChallenge>
    beginAuthentication(const identity::provider::AuthenticationRequest& request) override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationOutcome>
    completeAuthentication(const identity::provider::AuthenticationResponse& response) override;

private:
    class Implementation;
    std::unique_ptr<Implementation> m_implementation;
};

/** @brief Validated Farcaster FIP-11 signer-authentication configuration. */
class FarcasterProviderConfig final {
public:
    [[nodiscard]] static foundation::Result<FarcasterProviderConfig> create(
        std::string domain, std::string uri, std::uint64_t optimismChainId,
        std::string optimismRpcEndpoint, std::string idRegistryAddress,
        foundation::SecretString derivationKey, foundation::Duration challengeLifetime,
        std::string caFile = {}, foundation::SecretString authorizationHeader = {},
        std::string keyRegistryAddress = {});

    FarcasterProviderConfig(const FarcasterProviderConfig&) = delete;
    FarcasterProviderConfig& operator=(const FarcasterProviderConfig&) = delete;
    FarcasterProviderConfig(FarcasterProviderConfig&&) noexcept = default;
    FarcasterProviderConfig& operator=(FarcasterProviderConfig&&) noexcept = default;

    [[nodiscard]] std::string_view domain() const noexcept;
    [[nodiscard]] std::string_view uri() const noexcept;
    [[nodiscard]] std::uint64_t chainId() const noexcept;
    [[nodiscard]] std::string_view rpcEndpoint() const noexcept;
    [[nodiscard]] std::string_view idRegistryAddress() const noexcept;
    [[nodiscard]] std::string_view keyRegistryAddress() const noexcept;
    [[nodiscard]] const foundation::SecretString& derivationKey() const noexcept;
    [[nodiscard]] foundation::Duration challengeLifetime() const noexcept;
    [[nodiscard]] std::string_view caFile() const noexcept;
    [[nodiscard]] const foundation::SecretString& authorizationHeader() const noexcept;

private:
    FarcasterProviderConfig(std::string domain, std::string uri,
                            std::uint64_t optimismChainId,
                            std::string optimismRpcEndpoint,
                            std::string idRegistryAddress,
                            foundation::SecretString derivationKey,
                            foundation::Duration challengeLifetime,
                            std::string caFile,
                            foundation::SecretString authorizationHeader,
                            std::string keyRegistryAddress);

    std::string m_domain;
    std::string m_uri;
    std::uint64_t m_chainId{};
    std::string m_rpcEndpoint;
    std::string m_idRegistryAddress;
    std::string m_keyRegistryAddress;
    foundation::SecretString m_derivationKey;
    foundation::Duration m_challengeLifetime{};
    std::string m_caFile;
    foundation::SecretString m_authorizationHeader;
};

/** @brief How a SIWF signer is currently authorized for an FID. */
enum class FarcasterSignerKind : std::uint8_t {
    Custody,
    AuthAddress,
};

/**
 * @brief Narrow Optimism verification boundary used by the Farcaster adapter.
 *
 * The production implementation uses authenticated HTTPS JSON-RPC. Tests and
 * embedded deployments may inject an equivalent verifier without weakening
 * the provider's SIWF message and challenge validation.
 */
class FarcasterChainVerifier {
public:
    FarcasterChainVerifier(const FarcasterChainVerifier&) = delete;
    FarcasterChainVerifier& operator=(const FarcasterChainVerifier&) = delete;
    virtual ~FarcasterChainVerifier() = default;

    [[nodiscard]] virtual foundation::Result<bool> chainMatches() = 0;
    [[nodiscard]] virtual foundation::Result<bool> verifySignature(
        std::string_view address, std::string_view message,
        std::string_view signature) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<FarcasterSignerKind>>
    authorizeSigner(std::uint64_t fid, std::string_view address) = 0;

protected:
    FarcasterChainVerifier() = default;
};

/** @brief Farcaster provider proving a FID through its current on-chain custody address. */
class FarcasterAuthenticationProvider final : public identity::provider::AuthenticationProvider {
public:
    FarcasterAuthenticationProvider(FarcasterProviderConfig config,
                                    const foundation::ClockSource& clock,
                                    std::unique_ptr<FarcasterChainVerifier> verifier = {});
    ~FarcasterAuthenticationProvider() override;

    [[nodiscard]] identity::provider::ProviderId id() const override;
    [[nodiscard]] identity::provider::InteractionModel interactionModel() const noexcept override;
    [[nodiscard]] identity::provider::AssuranceLevel maximumClaimableAssurance() const noexcept override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationChallenge>
    beginAuthentication(const identity::provider::AuthenticationRequest& request) override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationOutcome>
    completeAuthentication(const identity::provider::AuthenticationResponse& response) override;

private:
    class Implementation;
    std::unique_ptr<Implementation> m_implementation;
};

} // namespace openproof::provider::web3
