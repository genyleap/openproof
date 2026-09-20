module;

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

export module openproof.storage.postgres;

import openproof.account;
import openproof.administration;
import openproof.application;
import openproof.client;
import openproof.consent;
import openproof.audit;
import openproof.foundation;
import openproof.credentials;
import openproof.evidence;
import openproof.evidence.verifiers;
import openproof.enterprise.scim;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.identity.profile;
import openproof.organization;
import openproof.oauth;
import openproof.policy;
import openproof.provider.local;
import openproof.provider.passkey;
import openproof.resource;
import openproof.security;
import openproof.session;
import openproof.token;

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
    friend class PostgresCredentialRekeyer;
    friend class PostgresMasterKeyRotator;
    friend class PostgresAdministrationRepository;
    friend class PostgresAuthorizationDecisionSink;
    friend class PostgresIdentityProviderStore;
    friend class PostgresAccountRepository;
    friend class PostgresResourceRepository;
    friend class PostgresConsentRepository;
    friend class PostgresPasskeyRepository;
    friend class PostgresScimDirectoryRepository;
    friend class PostgresEvidenceChallengeStore;
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

struct CredentialRekeyReport final {
    std::size_t rekeyed{};
    std::size_t alreadyCurrent{};
    bool dryRun{};
};

/** Offline, transactionally atomic rotation of encrypted credential envelopes. */
class PostgresCredentialRekeyer final {
public:
    explicit PostgresCredentialRekeyer(ConnectionPool& pool);
    /**
     * Validates every TOTP envelope, then replaces old-version ciphertexts in one
     * serializable transaction. The TOTP table is exclusively locked so no
     * credential can enter between inventory and commit. A dry run always rolls back.
     */
    [[nodiscard]] foundation::Result<CredentialRekeyReport> rotateTotp(
        const security::AeadKey& currentKey, unsigned int currentVersion,
        const security::AeadKey& replacementKey, unsigned int replacementVersion,
        bool dryRun);

private:
    ConnectionPool* m_pool;
};

struct MasterKeyRotationReport final {
    std::size_t authenticationTransactions{};
    std::size_t sessions{};
    std::size_t accountChallenges{};
    std::size_t passkeyRegistrations{};
    std::size_t authorizationCodes{};
    std::size_t tokenFamilies{};
    std::size_t deviceAuthorizations{};
    std::size_t pushedRequests{};
    bool dryRun{};

    [[nodiscard]] std::size_t invalidated() const noexcept
    {
        return authenticationTransactions + sessions + accountChallenges
            + passkeyRegistrations
            + authorizationCodes + tokenFamilies + deviceAuthorizations
            + pushedRequests;
    }
};

/** Offline atomic retirement of every state verifier derived from a master key. */
class PostgresMasterKeyRotator final {
public:
    explicit PostgresMasterKeyRotator(ConnectionPool& pool);
    /** Fails closed when configured version/material disagrees with journal head. */
    [[nodiscard]] foundation::Status verifyActive(
        unsigned int version, const security::Sha256Digest& fingerprint) const;
    /**
     * Deletes all short-lived state tied to the retired master and records the
     * non-secret key fingerprints in the same serializable transaction. A dry
     * run performs the full locked mutation and then always rolls it back.
     */
    [[nodiscard]] foundation::Result<MasterKeyRotationReport> rotate(
        unsigned int currentVersion, const security::Sha256Digest& currentFingerprint,
        unsigned int replacementVersion,
        const security::Sha256Digest& replacementFingerprint, bool dryRun);

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
    [[nodiscard]] foundation::Result<std::vector<session::Session>>
    list(const identity::core::IdentityId& identity) const override;
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
    [[nodiscard]] foundation::Status detachIfAnotherAuthenticationMethod(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& expectedOwner,
        const std::vector<identity::provider::ProviderId>& authenticationProviders) override;
    [[nodiscard]] foundation::Status reassign(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& expectedCurrentOwner,
        const identity::core::IdentityId& newOwner) override;
    [[nodiscard]] foundation::Status
    updatePresentation(const identity::core::ExternalIdentityRef& external) override;
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
    [[nodiscard]] foundation::Status enrollPending(
        identity::core::IdentityId identity,
        identity::provider::ExternalSubject subject,
        const foundation::SecretString& password,
        std::optional<credentials::TotpSecret> totp) override;
    [[nodiscard]] foundation::Status rebindSubject(
        const identity::core::IdentityId& identity,
        const identity::provider::ExternalSubject& previous,
        identity::provider::ExternalSubject replacement) override;
    [[nodiscard]] foundation::Status removePending(
        const identity::core::IdentityId& identity,
        const identity::provider::ExternalSubject& subject) override;
    [[nodiscard]] foundation::Status changePassword(
        const identity::provider::ExternalSubject& subject,
        const foundation::SecretString& password) override;
    [[nodiscard]] foundation::Status verifyPassword(
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

/** Persists every rejected protected-route decision in the audit chain/outbox. */
class PostgresAuthorizationDecisionSink final
    : public policy::AuthorizationDecisionSink {
public:
    PostgresAuthorizationDecisionSink(
        ConnectionPool& pool, audit::AuditKey auditKey,
        const foundation::ClockSource& clock);

    [[nodiscard]] foundation::Status record(
        const session::AuthenticatedSession& authenticatedSession,
        const identity::core::OrganizationId& organization,
        const policy::Action& action, const policy::Resource& resource,
        const policy::AuthorizationDecision& decision,
        const foundation::CorrelationId& correlation) override;

private:
    ConnectionPool* m_pool;
    audit::AuditKey m_auditKey;
    const foundation::ClockSource* m_clock;
};

/**
 * @brief Durable store for the central application registry and OAuth/OIDC state.
 *
 * One adapter implements the related repository ports so authorization-code and
 * refresh-token transitions can use PostgreSQL transactions without leaking SQL
 * into the protocol/domain modules.
 */
/** Durable account verification challenges and pending external-subject reservations. */
class PostgresAccountRepository final : public account::AccountRepository {
public:
    explicit PostgresAccountRepository(ConnectionPool& pool);

    [[nodiscard]] foundation::Status replace(account::VerificationChallenge challenge) override;
    [[nodiscard]] foundation::Result<account::VerificationChallenge> consume(
        const account::VerificationId& id, const account::VerificationDigest& presented,
        foundation::Instant now, std::uint32_t maximumAttempts,
        const identity::core::IdentityId* expectedIdentity = nullptr) override;
    [[nodiscard]] foundation::Status reserveSubject(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& identity,
        foundation::Instant now, foundation::Instant expiresAt) override;
    [[nodiscard]] foundation::Result<std::optional<identity::core::IdentityId>>
    reservedOwner(const identity::core::ExternalIdentityRef& external,
                  foundation::Instant now) const override;
    [[nodiscard]] foundation::Status releaseSubject(
        const identity::core::ExternalIdentityRef& external,
        const identity::core::IdentityId& expectedOwner) override;

private:
    ConnectionPool* m_pool;
};

/** @brief PostgreSQL-backed OAuth resource and service-identity registry. */
class PostgresResourceRepository final : public resource::ResourceRepository {
public:
    explicit PostgresResourceRepository(ConnectionPool& pool);

    [[nodiscard]] foundation::Status add(resource::ResourceServer resource) override;
    [[nodiscard]] foundation::Status save(const resource::ResourceServer& resource) override;
    [[nodiscard]] foundation::Result<std::optional<resource::ResourceServer>>
    findByAudience(std::string_view audience) const override;
    [[nodiscard]] foundation::Result<std::vector<resource::ResourceServer>> list() const override;
    [[nodiscard]] foundation::Status saveService(resource::ServiceIdentity service) override;
    [[nodiscard]] foundation::Result<std::optional<resource::ServiceIdentity>>
    serviceForClient(const client::ClientId& clientId) const override;

private:
    ConnectionPool* m_pool;
};

/** @brief PostgreSQL-backed remembered authorization consent store. */
class PostgresConsentRepository final : public consent::ConsentRepository {
public:
    explicit PostgresConsentRepository(ConnectionPool& pool);

    [[nodiscard]] foundation::Status save(consent::ConsentGrant grant) override;
    [[nodiscard]] foundation::Result<std::optional<consent::ConsentGrant>> findActive(
        const identity::core::IdentityId& identity, const client::ClientId& clientId,
        std::string_view audience, foundation::Instant now) const override;
    [[nodiscard]] foundation::Result<std::vector<consent::ConsentGrant>> list(
        const identity::core::IdentityId& identity) const override;
    [[nodiscard]] foundation::Status revoke(
        const consent::ConsentId& id, const identity::core::IdentityId& identity,
        foundation::Instant now) override;

private:
    ConnectionPool* m_pool;
};

/** @brief PostgreSQL-backed WebAuthn credential and registration-ceremony store. */
class PostgresPasskeyRepository final : public provider::passkey::PasskeyRepository {
public:
    explicit PostgresPasskeyRepository(ConnectionPool& pool);

    [[nodiscard]] foundation::Status addCeremony(
        provider::passkey::RegistrationCeremony ceremony) override;
    [[nodiscard]] foundation::Status consumeCeremony(
        const identity::provider::ChallengeId& id,
        const identity::core::IdentityId& identity,
        foundation::Instant now) override;
    [[nodiscard]] foundation::Status addCredential(
        provider::passkey::PasskeyCredential credential) override;
    [[nodiscard]] foundation::Result<std::optional<provider::passkey::PasskeyCredential>>
    findCredential(std::string_view credentialId) const override;
    [[nodiscard]] foundation::Result<std::vector<provider::passkey::PasskeyCredential>>
    listCredentials(const identity::core::IdentityId& identity) const override;
    [[nodiscard]] foundation::Status advanceCounter(
        std::string_view credentialId, std::uint32_t expected,
        std::uint32_t replacement, foundation::Instant usedAt) override;
    [[nodiscard]] foundation::Status removeCredentialIfAnotherExists(
        const identity::core::IdentityId& identity,
        std::string_view credentialId) override;
    [[nodiscard]] foundation::Status removeCredential(
        const identity::core::IdentityId& identity,
        std::string_view credentialId) override;

private:
    ConnectionPool* m_pool;
};


/** @brief PostgreSQL-backed durable SCIM directory metadata and group membership. */
class PostgresScimDirectoryRepository final : public enterprise::scim::DirectoryRepository {
public:
    explicit PostgresScimDirectoryRepository(ConnectionPool& pool);

    [[nodiscard]] foundation::Status addUser(enterprise::scim::UserRecord user) override;
    [[nodiscard]] foundation::Status saveUser(const enterprise::scim::UserRecord& user) override;
    [[nodiscard]] foundation::Status removeUser(
        const identity::core::OrganizationId& organization,
        const identity::core::IdentityId& identity) override;
    [[nodiscard]] foundation::Result<std::optional<enterprise::scim::UserRecord>> findUser(
        const identity::core::OrganizationId& organization,
        const identity::core::IdentityId& identity) const override;
    [[nodiscard]] foundation::Result<std::optional<enterprise::scim::UserRecord>> findUserByName(
        const identity::core::OrganizationId& organization, std::string_view userName) const override;
    [[nodiscard]] foundation::Result<std::vector<enterprise::scim::UserRecord>> users(
        const identity::core::OrganizationId& organization) const override;

    [[nodiscard]] foundation::Status addGroup(enterprise::scim::GroupRecord group) override;
    [[nodiscard]] foundation::Status saveGroup(const enterprise::scim::GroupRecord& group) override;
    [[nodiscard]] foundation::Status removeGroup(
        const identity::core::OrganizationId& organization,
        const enterprise::scim::GroupId& id) override;
    [[nodiscard]] foundation::Result<std::optional<enterprise::scim::GroupRecord>> findGroup(
        const identity::core::OrganizationId& organization,
        const enterprise::scim::GroupId& id) const override;
    [[nodiscard]] foundation::Result<std::optional<enterprise::scim::GroupRecord>> findGroupByName(
        const identity::core::OrganizationId& organization, std::string_view displayName) const override;
    [[nodiscard]] foundation::Result<std::vector<enterprise::scim::GroupRecord>> groups(
        const identity::core::OrganizationId& organization) const override;
    [[nodiscard]] foundation::Result<std::vector<identity::core::IdentityId>> groupMembers(
        const identity::core::OrganizationId& organization,
        const enterprise::scim::GroupId& id) const override;
    [[nodiscard]] foundation::Status replaceGroupMembers(
        const identity::core::OrganizationId& organization,
        const enterprise::scim::GroupId& id,
        std::vector<identity::core::IdentityId> members) override;

private:
    ConnectionPool* m_pool;
};

/** @brief Durable one-time challenge store for evidence verification ceremonies. */
class PostgresEvidenceChallengeStore final
    : public evidence::verification::ChallengeStore {
public:
    explicit PostgresEvidenceChallengeStore(ConnectionPool& pool);
    [[nodiscard]] foundation::Status add(
        evidence::verification::Challenge challenge) override;
    [[nodiscard]] foundation::Status consume(
        const evidence::verification::ChallengeDigest& digest,
        const identity::core::IdentityId& identity,
        const identity::provider::ProviderId& provider,
        foundation::Instant now) override;
private:
    ConnectionPool* m_pool;
};

class PostgresIdentityProviderStore final
    : public application::ApplicationRepository,
      public client::ClientRepository,
      public identity::profile::IdentityProfileRepository,
      public evidence::EvidenceRepository,
      public oauth::AuthorizationCodeStore,
      public oauth::DeviceAuthorizationStore,
      public oauth::PushedAuthorizationRequestStore,
      public oauth::ClientRequestSigningKeyStore,
      public oauth::JarReplayStore,
      public oauth::DpopReplayStore,
      public oauth::MtlsForwardingReplayStore,
      public token::TokenRepository {
public:
    explicit PostgresIdentityProviderStore(ConnectionPool& pool);

    [[nodiscard]] foundation::Status add(application::Application application) override;
    [[nodiscard]] foundation::Status save(const application::Application& application) override;
    [[nodiscard]] foundation::Result<std::optional<application::Application>>
    findById(const application::ApplicationId& id) const override;
    [[nodiscard]] foundation::Result<std::optional<application::Application>>
    findByIdentifier(const identity::core::OrganizationId& owner,
                     std::string_view identifier) const override;
    [[nodiscard]] foundation::Result<std::vector<application::Application>> list() const override;

    [[nodiscard]] foundation::Status add(client::Client client) override;
    [[nodiscard]] foundation::Status save(const client::Client& client) override;
    [[nodiscard]] foundation::Result<std::optional<client::Client>>
    findById(const client::ClientId& id) const override;
    [[nodiscard]] foundation::Result<std::vector<client::Client>>
    clientsOf(const application::ApplicationId& applicationId) const override;

    [[nodiscard]] foundation::Status save(const identity::profile::IdentityProfile& profile) override;
    [[nodiscard]] foundation::Result<std::optional<identity::profile::IdentityProfile>>
    find(const identity::core::IdentityId& identity) const override;

    [[nodiscard]] foundation::Status add(evidence::Evidence evidence) override;
    [[nodiscard]] foundation::Status addBatch(std::vector<evidence::Evidence> evidence) override;
    [[nodiscard]] foundation::Status revoke(const evidence::EvidenceId& id) override;
    [[nodiscard]] foundation::Result<std::optional<evidence::Evidence>>
    find(const evidence::EvidenceId& id) const override;
    [[nodiscard]] foundation::Result<std::vector<evidence::Evidence>>
    forIdentity(const identity::core::IdentityId& identity) const override;

    [[nodiscard]] foundation::Status add(oauth::AuthorizationCode code) override;
    [[nodiscard]] foundation::Result<oauth::AuthorizationCode>
    consumeBound(const oauth::CodeDigest& digest, foundation::Instant now,
                 std::string_view expectedClientId,
                 std::string_view expectedRedirectUri,
                 std::string_view expectedCodeChallenge) override;

    [[nodiscard]] foundation::Status add(oauth::DeviceAuthorization authorization) override;
    [[nodiscard]] foundation::Result<oauth::DeviceAuthorization> findByUserCode(
        const oauth::DeviceUserCodeDigest& userCode, foundation::Instant now) override;
    [[nodiscard]] foundation::Result<oauth::DeviceAuthorization> approve(
        const oauth::DeviceUserCodeDigest& userCode,
        const session::AuthenticatedSession& authenticated,
        foundation::Instant now) override;
    [[nodiscard]] foundation::Status deny(
        const oauth::DeviceUserCodeDigest& userCode, foundation::Instant now) override;
    [[nodiscard]] foundation::Result<oauth::DevicePollResult> poll(
        const oauth::DeviceCodeDigest& deviceCode, const client::ClientId& expectedClient,
        foundation::Instant now) override;

    [[nodiscard]] foundation::Status add(
        oauth::PushedAuthorizationRequest request) override;
    [[nodiscard]] foundation::Result<oauth::PushedAuthorizationRequest> find(
        const oauth::PushedRequestDigest& digest, foundation::Instant now) const override;
    [[nodiscard]] foundation::Result<oauth::PushedAuthorizationRequest> consume(
        const oauth::PushedRequestDigest& digest, const client::ClientId& expectedClient,
        foundation::Instant now) override;

    [[nodiscard]] foundation::Status save(
        oauth::ClientRequestSigningKey key) override;
    [[nodiscard]] foundation::Result<std::optional<oauth::ClientRequestSigningKey>> find(
        const client::ClientId& clientId) const override;
    [[nodiscard]] foundation::Status remove(const client::ClientId& clientId) override;
    [[nodiscard]] foundation::Status consume(
        const client::ClientId& clientId, std::string_view jwtId,
        foundation::Instant expiresAt, foundation::Instant now) override;
    [[nodiscard]] foundation::Status consumeDpopReplay(
        std::string_view jwkThumbprint, std::string_view jwtId,
        foundation::Instant expiresAt, foundation::Instant now) override;
    [[nodiscard]] foundation::Status consumeMtlsForwardingReplay(
        std::string_view certificateThumbprint, std::string_view nonce,
        foundation::Instant expiresAt, foundation::Instant now) override;

    [[nodiscard]] foundation::Status storeInitial(
        token::AccessTokenRecord access, token::RefreshTokenRecord refresh) override;
    [[nodiscard]] foundation::Status storeAccessOnly(
        token::AccessTokenRecord access) override;
    [[nodiscard]] foundation::Result<token::AccessTokenRecord>
    findAccess(const token::TokenDigest& digest) override;
    [[nodiscard]] foundation::Result<token::RefreshTokenRecord>
    findRefresh(const token::TokenDigest& digest) override;
    [[nodiscard]] foundation::Status rotateRefresh(
        const token::TokenDigest& presented, foundation::Instant now,
        token::AccessTokenRecord replacementAccess,
        token::RefreshTokenRecord replacementRefresh) override;
    [[nodiscard]] foundation::Status revokeFamily(
        const token::TokenFamilyId& family, foundation::Instant now) override;
    [[nodiscard]] foundation::Status revokeToken(
        const token::TokenDigest& digest, foundation::Instant now) override;

private:
    ConnectionPool* m_pool;
};


}
