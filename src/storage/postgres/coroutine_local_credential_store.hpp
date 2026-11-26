#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

namespace openproof::credentials { class BoundedPasswordExecutor; }

namespace openproof::storage::postgres {

// Internal credential snapshot, not an authentication proof. Only ciphertext
// and the encoded password hash leave SQL; plaintext never enters this store.
struct LocalCredentialSnapshot final {
    identity::core::IdentityId owner;
    std::string passwordHash;
    std::optional<std::string> encryptedTotpHex;
    std::optional<std::string> keyVersion;
    std::optional<std::string> lastAcceptedStep;
    std::string passwordChangedAt;
    std::optional<std::string> totpEnrolledAt;
};

class CoroutineLocalCredentialStore final {
public:
    CoroutineLocalCredentialStore(boost::asio::any_io_executor executor,
        foundation::SecretString connectionString, identity::core::OrganizationId tenant,
        identity::provider::ProviderId provider, std::size_t capacity,
        foundation::Duration acquireTimeout, foundation::Duration connectTimeout,
        foundation::Duration queryTimeout);
    ~CoroutineLocalCredentialStore();
    CoroutineLocalCredentialStore(const CoroutineLocalCredentialStore&) = delete;
    CoroutineLocalCredentialStore& operator=(const CoroutineLocalCredentialStore&) = delete;

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::optional<LocalCredentialSnapshot>>>
    readAsync(identity::provider::ExternalSubject subject);
    // Owner-scoped read; never return a password hash to the HTTP layer.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<
        std::pair<identity::core::IdentityId, std::optional<bool>>>>
    readPasswordUpgradeStatusAsync(identity::core::IdentityId owner,
                                   const credentials::BoundedPasswordExecutor& policy);
    // Explicit password-policy upgrade for a session-authenticated owner.
    // No factor enrollment, session issuance or password-reset semantics.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<
        std::pair<identity::core::IdentityId, bool>>>
    confirmPasswordUpgradeAsync(identity::core::IdentityId owner,
        foundation::SecretString password, credentials::BoundedPasswordExecutor& policy);
    // Only for password-only authentication, after verification of the
    // captured hash. An intervening MFA enrollment must deny the proof.
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    confirmPasswordOnlyAsync(identity::provider::ExternalSubject subject,
                             LocalCredentialSnapshot snapshot);
    // Caller verifies the TOTP cryptographically first. Compare exact
    // credential generation and consume the monotonic step atomically.
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    consumeTotpAsync(identity::provider::ExternalSubject subject,
                     LocalCredentialSnapshot snapshot, std::uint64_t step);
    // Require an enrolled second factor and the same verified password/MFA
    // generation when redeeming a recovery-code digest. Never accept plaintext.
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    consumeRecoveryAsync(identity::provider::ExternalSubject subject,
                         LocalCredentialSnapshot snapshot, credentials::RecoveryCodeDigest digest);
    // Best-effort password policy upgrade AFTER complete factor verification.
    // Preserve changed_at_ms; a rehash is not a password change.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<bool>>
    rehashAsync(identity::provider::ExternalSubject subject, LocalCredentialSnapshot snapshot,
                credentials::PasswordHash replacement);
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

}
