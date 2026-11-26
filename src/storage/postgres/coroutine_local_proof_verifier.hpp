#pragma once
#include <boost/asio/awaitable.hpp>
#include <optional>
#include "coroutine_local_provider.hpp"
#include "coroutine_local_credential_store.hpp"
#include "bounded_password_executor.hpp"
import openproof.security;

namespace openproof::storage::postgres {
class CoroutinePostgresLocalProofVerifier final : public provider::local::CoroutineLocalProofVerifier {
public:
    CoroutinePostgresLocalProofVerifier(CoroutineLocalCredentialStore& store,
        credentials::BoundedPasswordExecutor& passwords, credentials::TotpPolicy totpPolicy,
        security::AeadKey totpKey, unsigned int keyVersion, foundation::SecretString recoveryPepper);
    [[nodiscard]] boost::asio::awaitable<foundation::Result<provider::local::LocalVerification>>
    verifyAsync(identity::provider::ExternalSubject subject, foundation::SecretString password,
        std::optional<foundation::SecretString> totp,
        std::optional<foundation::SecretString> recovery, foundation::Instant now) override;
private:
    CoroutineLocalCredentialStore& m_store;
    credentials::BoundedPasswordExecutor& m_passwords;
    credentials::TotpPolicy m_totpPolicy;
    security::AeadKey m_totpKey;
    unsigned int m_keyVersion;
    foundation::SecretString m_recoveryPepper;
};
}
