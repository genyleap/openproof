module;

#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>

export module openproof.storage.postgres;

import openproof.foundation;
import openproof.credentials;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.session;

export namespace openproof::storage::postgres {

class PoolConfig final {
public:
    [[nodiscard]] static foundation::Result<PoolConfig>
    create(foundation::SecretString connectionString, std::size_t connections,
           foundation::Duration acquireTimeout);
    PoolConfig(const PoolConfig&) = delete;
    PoolConfig& operator=(const PoolConfig&) = delete;
    PoolConfig(PoolConfig&&) noexcept = default;
    PoolConfig& operator=(PoolConfig&&) noexcept = default;
    ~PoolConfig() = default;

private:
    friend class ConnectionPool;
    PoolConfig(foundation::SecretString connectionString, std::size_t connections,
               foundation::Duration acquireTimeout);
    foundation::SecretString m_connectionString;
    std::size_t m_connections{};
    foundation::Duration m_acquireTimeout{};
};

class ConnectionPool final {
public:
    [[nodiscard]] static foundation::Result<std::unique_ptr<ConnectionPool>>
    create(PoolConfig config);
    ConnectionPool(const ConnectionPool&) = delete;
    ConnectionPool& operator=(const ConnectionPool&) = delete;
    ~ConnectionPool();

    [[nodiscard]] foundation::Status healthCheck();
    [[nodiscard]] std::size_t size() const noexcept;

private:
    friend class Migrator;
    friend class PostgresSessionRepository;
    friend class PostgresAuthenticationTransactionStore;
    friend class PostgresRecoveryCodeRepository;
    class Implementation;
    explicit ConnectionPool(std::unique_ptr<Implementation> implementation);
    std::unique_ptr<Implementation> m_implementation;
};

struct MigrationReport final {
    std::size_t applied{};
    std::size_t alreadyApplied{};
};

class Migrator final {
public:
    explicit Migrator(ConnectionPool& pool);
    /** Applies lexically ordered .sql files and rejects changed applied files. */
    [[nodiscard]] foundation::Result<MigrationReport>
    applyDirectory(const std::filesystem::path& directory);
private:
    ConnectionPool* m_pool;
};

class PostgresSessionRepository final : public session::SessionRepository {
public:
    explicit PostgresSessionRepository(ConnectionPool& pool);
    [[nodiscard]] foundation::Status add(session::Session session) override;
    [[nodiscard]] foundation::Result<session::Session>
    use(const session::TokenDigest& token, foundation::Instant now) override;
    [[nodiscard]] foundation::Status rotate(
        const session::SessionId& id, const session::TokenDigest& expected,
        session::TokenDigest replacement, foundation::Instant now) override;
    [[nodiscard]] foundation::Status revoke(
        const session::SessionId& id, foundation::Instant now) override;
    [[nodiscard]] foundation::Result<std::size_t> revokeAll(
        const identity::core::IdentityId& identity,
        foundation::Instant now) override;
    [[nodiscard]] foundation::Result<std::optional<session::Session>>
    find(const session::SessionId& id) const override;
    [[nodiscard]] std::size_t purgeExpired(foundation::Instant now) override;
    [[nodiscard]] std::size_t size() const override;
private:
    ConnectionPool* m_pool;
};

class PostgresAuthenticationTransactionStore final
    : public identity::provider::AuthenticationTransactionStore {
public:
    explicit PostgresAuthenticationTransactionStore(ConnectionPool& pool);
    [[nodiscard]] foundation::Status begin(
        identity::provider::AuthenticationTransaction transaction) override;
    [[nodiscard]] foundation::Result<identity::provider::AuthenticationTransaction>
    consume(const identity::provider::TransactionId& id,
            const foundation::SecretString& presentedNonce,
            const identity::provider::BindingDigest& presentedBinding,
            foundation::Instant now) override;
    [[nodiscard]] foundation::Result<std::optional<identity::provider::AuthenticationTransaction>>
    find(const identity::provider::TransactionId& id) const override;
    [[nodiscard]] std::size_t purgeExpired(foundation::Instant now) override;
    [[nodiscard]] std::size_t size() const override;
private:
    ConnectionPool* m_pool;
};

/** PostgreSQL-backed recovery codes with transactional replacement and atomic use. */
class PostgresRecoveryCodeRepository final
    : public credentials::RecoveryCodeRepository {
public:
    explicit PostgresRecoveryCodeRepository(ConnectionPool& pool);
    [[nodiscard]] foundation::Status replace(
        const identity::core::IdentityId& identity,
        std::vector<credentials::RecoveryCodeDigest> digests) override;
    [[nodiscard]] foundation::Status consume(
        const identity::core::IdentityId& identity,
        const credentials::RecoveryCodeDigest& digest) override;
    [[nodiscard]] foundation::Result<std::size_t> remaining(
        const identity::core::IdentityId& identity) const override;
private:
    ConnectionPool* m_pool;
};

}
