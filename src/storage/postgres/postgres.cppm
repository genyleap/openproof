module;

#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>
#include <vector>

export module openproof.storage.postgres;

import openproof.administration;
import openproof.audit;
import openproof.foundation;
import openproof.credentials;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.organization;
import openproof.provider.local;
import openproof.security;
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
    friend class PostgresIdentityRepository;
    friend class PostgresExternalIdentityDirectory;
    friend class PostgresOrganizationRepository;
    friend class PostgresMembershipRepository;
    friend class PostgresLocalAccountDirectory;
    friend class PostgresAdministrationRepository;
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

class PostgresIdentityRepository final : public identity::core::IdentityRepository {
public:
    explicit PostgresIdentityRepository(ConnectionPool& pool);
    [[nodiscard]] foundation::Status add(
        const identity::core::OrganizationId& organization,
        identity::core::Identity identity) override;
    [[nodiscard]] foundation::Result<std::optional<identity::core::Identity>>
    findById(const identity::core::OrganizationId& organization,
             const identity::core::IdentityId& id) const override;
    [[nodiscard]] foundation::Status changeStatus(
        const identity::core::OrganizationId& organization,
        const identity::core::IdentityId& id,
        identity::core::IdentityStatus status) override;
    [[nodiscard]] foundation::Result<std::vector<identity::core::IdentityId>>
    idsOfKind(const identity::core::OrganizationId& organization,
              identity::core::SubjectKind kind) const override;
    [[nodiscard]] foundation::Result<std::size_t>
    countIn(const identity::core::OrganizationId& organization) const override;
private:
    ConnectionPool* m_pool;
};

class PostgresExternalIdentityDirectory final
    : public identity::core::ExternalIdentityDirectory {
public:
    explicit PostgresExternalIdentityDirectory(ConnectionPool& pool);
    [[nodiscard]] foundation::Status attach(
        const identity::core::IdentityLink& link) override;
    [[nodiscard]] foundation::Result<std::optional<identity::core::IdentityId>>
    ownerOf(const identity::core::ExternalIdentityRef& external) const override;
    [[nodiscard]] foundation::Status detach(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& expectedOwner) override;
    [[nodiscard]] foundation::Status reassign(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& expectedCurrentOwner,
        const identity::core::IdentityId& newOwner) override;
    [[nodiscard]] foundation::Result<std::vector<identity::core::ExternalIdentityRef>>
    externalIdentitiesOf(const identity::core::IdentityId& owner) const override;
    [[nodiscard]] std::size_t size() const override;
private:
    ConnectionPool* m_pool;
};

class PostgresOrganizationRepository final : public organization::OrganizationRepository {
public:
    explicit PostgresOrganizationRepository(ConnectionPool& pool);
    [[nodiscard]] foundation::Status add(organization::Organization organization) override;
    [[nodiscard]] foundation::Result<std::optional<organization::Organization>>
    findById(const organization::OrganizationId& id) const override;
    [[nodiscard]] foundation::Status changeStatus(
        const organization::OrganizationId& id,
        organization::OrganizationStatus status) override;
    [[nodiscard]] foundation::Result<std::size_t> count() const override;
private:
    ConnectionPool* m_pool;
};

class PostgresMembershipRepository final : public organization::MembershipRepository {
public:
    explicit PostgresMembershipRepository(ConnectionPool& pool);
    [[nodiscard]] foundation::Status add(organization::Membership membership) override;
    [[nodiscard]] foundation::Result<std::optional<organization::Membership>>
    find(const organization::OrganizationId& organization,
         const organization::IdentityId& identity) const override;
    [[nodiscard]] foundation::Status save(const organization::Membership& membership) override;
    [[nodiscard]] foundation::Result<std::vector<organization::IdentityId>>
    membersOf(const organization::OrganizationId& organization) const override;
    [[nodiscard]] foundation::Result<std::vector<organization::OrganizationId>>
    organizationsOf(const organization::IdentityId& identity) const override;
    [[nodiscard]] foundation::Result<std::size_t>
    countIn(const organization::OrganizationId& organization) const override;
private:
    ConnectionPool* m_pool;
};

/** Persistent local credentials; TOTP seeds are AES-256-GCM encrypted at rest. */
class PostgresLocalAccountDirectory final
    : public provider::local::LocalAccountDirectory {
public:
    [[nodiscard]] static foundation::Result<std::unique_ptr<PostgresLocalAccountDirectory>>
    create(ConnectionPool& pool, credentials::PasswordHasher passwordHasher,
           credentials::TotpPolicy totpPolicy, security::AeadKey totpKey,
           unsigned int keyVersion, identity::provider::ProviderId provider);
    ~PostgresLocalAccountDirectory() override;
    [[nodiscard]] foundation::Status enroll(
        identity::provider::ExternalSubject subject,
        const foundation::SecretString& password,
        std::optional<credentials::TotpSecret> totp) override;
    [[nodiscard]] foundation::Status changePassword(
        const identity::provider::ExternalSubject& subject,
        const foundation::SecretString& password) override;
    [[nodiscard]] foundation::Result<provider::local::LocalVerification> verify(
        const identity::provider::ExternalSubject& subject,
        const foundation::SecretString& password,
        std::optional<std::string_view> totp,
        foundation::Instant now) override;
private:
    PostgresLocalAccountDirectory(ConnectionPool& pool,
        credentials::PasswordHasher passwordHasher,
        credentials::TotpPolicy totpPolicy, security::AeadKey totpKey,
        unsigned int keyVersion, identity::provider::ProviderId provider,
        credentials::PasswordHash dummyHash);
    ConnectionPool* m_pool;
    credentials::PasswordHasher m_passwordHasher;
    credentials::TotpPolicy m_totpPolicy;
    security::AeadKey m_totpKey;
    unsigned int m_keyVersion{};
    identity::provider::ProviderId m_provider;
    credentials::PasswordHash m_dummyHash;
};

/**
 * PostgreSQL implementation of the one-time initial-owner ceremony.
 * All aggregates, credentials and audit/outbox records commit together.
 */
class PostgresAdministrationRepository final
    : public administration::BootstrapRepository,
      public administration::LocalMemberAdministrator {
public:
    [[nodiscard]] static foundation::Result<std::unique_ptr<PostgresAdministrationRepository>>
    create(ConnectionPool& pool, credentials::PasswordHasher passwordHasher,
           security::AeadKey totpKey, unsigned int keyVersion,
           identity::provider::ProviderId provider, audit::AuditKey auditKey);
    ~PostgresAdministrationRepository() override;

    [[nodiscard]] foundation::Status initialize(
        const administration::InitialAdministrator& administrator) override;
    [[nodiscard]] foundation::Status provision(
        const identity::core::IdentityId& actor,
        const administration::LocalMemberEnrollment& enrollment) override;
    [[nodiscard]] foundation::Status replaceRoles(
        const identity::core::IdentityId& actor,
        const administration::MemberRoleReplacement& replacement) override;
    [[nodiscard]] foundation::Status changeLifecycle(
        const identity::core::IdentityId& actor,
        const administration::MemberLifecycleChange& change) override;
    [[nodiscard]] foundation::Status resetCredentials(
        const identity::core::IdentityId& actor,
        const administration::LocalCredentialReset& reset) override;

private:
    PostgresAdministrationRepository(
        ConnectionPool& pool, credentials::PasswordHasher passwordHasher,
        security::AeadKey totpKey, unsigned int keyVersion,
        identity::provider::ProviderId provider, audit::AuditKey auditKey);

    ConnectionPool* m_pool;
    credentials::PasswordHasher m_passwordHasher;
    security::AeadKey m_totpKey;
    unsigned int m_keyVersion{};
    identity::provider::ProviderId m_provider;
    audit::AuditKey m_auditKey;
};

}
