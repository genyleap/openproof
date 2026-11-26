#include <boost/asio/awaitable.hpp>
#include <charconv>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include "coroutine_local_proof_verifier.hpp"

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace local = provider::local;
namespace {
template<typename T> std::optional<T> decimal(const std::string& value)
{
    T result{};
    const auto [end, ec] = std::from_chars(value.data(), value.data()+value.size(), result);
    if (ec != std::errc{} || end != value.data()+value.size()) return std::nullopt;
    return result;
}
}
CoroutinePostgresLocalProofVerifier::CoroutinePostgresLocalProofVerifier(
    CoroutineLocalCredentialStore& store, credentials::BoundedPasswordExecutor& passwords,
    credentials::TotpPolicy totpPolicy, security::AeadKey totpKey,
    unsigned int keyVersion, foundation::SecretString recoveryPepper)
    : m_store(store), m_passwords(passwords), m_totpPolicy(totpPolicy),
      m_totpKey(std::move(totpKey)), m_keyVersion(keyVersion),
      m_recoveryPepper(std::move(recoveryPepper))
{
    if (keyVersion == 0U || m_recoveryPepper.expose().size() < 32U)
        throw std::invalid_argument{"Invalid local proof verifier configuration"};
}
asio::awaitable<foundation::Result<local::LocalVerification>>
CoroutinePostgresLocalProofVerifier::verifyAsync(identity::provider::ExternalSubject subject,
    foundation::SecretString password, std::optional<foundation::SecretString> totp,
    std::optional<foundation::SecretString> recovery, foundation::Instant now)
{
    if (!local::LocalAccountDirectory::isValidSubject(subject)
        || password.empty() || password.expose().size() > 1024U
        || (totp && recovery) || (totp && totp->expose().size() > 8U)
        || (recovery && (recovery->empty() || recovery->expose().size() > 128U)))
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    auto found = co_await m_store.readAsync(subject);
    if (!found) co_return foundation::fail(found.error());
    std::optional<credentials::PasswordHash> hash;
    if (found->has_value()) {
        auto parsed = credentials::PasswordHash::parse(found->value().passwordHash);
        if (!parsed) co_return foundation::fail(foundation::ErrorCode::Unavailable);
        hash.emplace(std::move(parsed).value());
    }
    // Do not hold a SQL lease while running the memory-hard KDF.
    auto matches = co_await m_passwords.verifyAsync(password.clone(), hash);
    if (!matches) co_return foundation::fail(matches.error());
    if (!matches.value() || !found->has_value() || !hash)
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    auto snapshot = std::move(found->value());
    auto verified = local::LocalVerification::Password;
    if (!snapshot.encryptedTotpHex) {
        if (recovery) co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        auto confirmed = co_await m_store.confirmPasswordOnlyAsync(subject, snapshot);
        if (!confirmed) co_return foundation::fail(confirmed.error());
    } else {
        if (!snapshot.keyVersion || decimal<unsigned int>(*snapshot.keyVersion) != m_keyVersion)
            co_return foundation::fail(foundation::ErrorCode::FailedPrecondition);
        if (recovery) {
            auto digest = security::hmacSha256(m_recoveryPepper, recovery->expose());
            if (!digest) co_return foundation::fail(digest.error());
            auto consumed = co_await m_store.consumeRecoveryAsync(subject, snapshot, digest.value());
            if (!consumed) co_return foundation::fail(consumed.error());
            verified = local::LocalVerification::PasswordAndRecoveryCode;
        } else {
            if (!totp) co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
            auto ciphertext = foundation::fromHex(*snapshot.encryptedTotpHex);
            if (!ciphertext) co_return foundation::fail(ciphertext.error());
            auto decrypted = security::openAes256Gcm(m_totpKey, ciphertext.value(),
                "openproof/totp/v1:" + std::string{snapshot.owner.value()});
            if (!decrypted) co_return foundation::fail(decrypted.error());
            auto secret = credentials::TotpSecret::create(std::move(decrypted).value());
            if (!secret) co_return foundation::fail(secret.error());
            std::optional<std::uint64_t> previous;
            if (snapshot.lastAcceptedStep) {
                previous = decimal<std::uint64_t>(*snapshot.lastAcceptedStep);
                if (!previous) co_return foundation::fail(foundation::ErrorCode::Unavailable);
            }
            auto accepted = credentials::verifyTotp(secret.value(), m_totpPolicy,
                totp->expose(), now, previous);
            if (!accepted) co_return foundation::fail(accepted.error());
            auto consumed = co_await m_store.consumeTotpAsync(subject, snapshot, accepted.value());
            if (!consumed) co_return foundation::fail(consumed.error());
            verified = local::LocalVerification::PasswordAndTotp;
        }
    }
    // Best-effort rehash after all factors, never before redemption. A
    // saturated worker or a losing CAS does not erase a valid proof.
    if (verified != local::LocalVerification::PasswordAndRecoveryCode) {
        auto replacement = co_await m_passwords.rehashAsync(std::move(password), *hash);
        if (replacement && replacement->has_value()) {
            static_cast<void>(co_await m_store.rehashAsync(subject, std::move(snapshot),
                std::move(replacement->value())));
        }
    }
    co_return verified;
}
}
