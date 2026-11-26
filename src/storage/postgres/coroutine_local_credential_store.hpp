#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;

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
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

}
