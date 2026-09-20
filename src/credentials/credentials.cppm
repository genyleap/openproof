module;

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.credentials;

import openproof.foundation;
import openproof.identity.core;
import openproof.security;

export namespace openproof::credentials {

/** Parameters for the memory-hard password derivation. */
class PasswordPolicy final {
public:
    [[nodiscard]] static foundation::Result<PasswordPolicy>
    create(std::uint64_t cost, std::uint64_t blockSize, std::uint64_t parallelism,
           std::size_t saltBytes, std::size_t derivedBytes, std::uint64_t maximumMemoryBytes);

    /** 32 MiB scrypt work factor with a 64 MiB hard memory ceiling. */
    [[nodiscard]] static PasswordPolicy recommended() noexcept;

    [[nodiscard]] std::uint64_t cost() const noexcept;
    [[nodiscard]] std::uint64_t blockSize() const noexcept;
    [[nodiscard]] std::uint64_t parallelism() const noexcept;
    [[nodiscard]] std::size_t saltBytes() const noexcept;
    [[nodiscard]] std::size_t derivedBytes() const noexcept;
    [[nodiscard]] std::uint64_t maximumMemoryBytes() const noexcept;

private:
    PasswordPolicy(std::uint64_t cost, std::uint64_t blockSize,
                   std::uint64_t parallelism, std::size_t saltBytes,
                   std::size_t derivedBytes, std::uint64_t maximumMemoryBytes) noexcept;

    std::uint64_t m_cost{};
    std::uint64_t m_blockSize{};
    std::uint64_t m_parallelism{};
    std::size_t m_saltBytes{};
    std::size_t m_derivedBytes{};
    std::uint64_t m_maximumMemoryBytes{};
};

/** A versioned, self-describing scrypt result. Sensitive, but not a credential. */
class PasswordHash final {
public:
    [[nodiscard]] static foundation::Result<PasswordHash> parse(std::string encoded);
    [[nodiscard]] std::string_view encoded() const noexcept;

private:
    friend class PasswordHasher;
    explicit PasswordHash(std::string encoded);
    std::string m_encoded;
};

/** Password hashing with server-side HMAC pepper followed by scrypt. */
class PasswordHasher final {
public:
    [[nodiscard]] static foundation::Result<PasswordHasher>
    create(foundation::SecretString pepper, PasswordPolicy policy);

    PasswordHasher(const PasswordHasher&) = delete;
    PasswordHasher& operator=(const PasswordHasher&) = delete;
    PasswordHasher(PasswordHasher&&) noexcept = default;
    PasswordHasher& operator=(PasswordHasher&&) noexcept = default;
    ~PasswordHasher() = default;

    [[nodiscard]] foundation::Result<PasswordHash>
    hash(const foundation::SecretString& password) const;
    [[nodiscard]] foundation::Result<bool>
    verify(const foundation::SecretString& password, const PasswordHash& expected) const;

private:
    PasswordHasher(foundation::SecretString pepper, PasswordPolicy policy);
    foundation::SecretString m_pepper;
    PasswordPolicy m_policy;
};

class TotpPolicy final {
public:
    [[nodiscard]] static foundation::Result<TotpPolicy>
    create(foundation::Duration step, unsigned int digits,
           unsigned int pastWindow, unsigned int futureWindow);
    [[nodiscard]] static TotpPolicy recommended() noexcept;

    [[nodiscard]] foundation::Duration step() const noexcept;
    [[nodiscard]] unsigned int digits() const noexcept;
    [[nodiscard]] unsigned int pastWindow() const noexcept;
    [[nodiscard]] unsigned int futureWindow() const noexcept;

private:
    TotpPolicy(foundation::Duration step, unsigned int digits,
               unsigned int pastWindow, unsigned int futureWindow) noexcept;
    foundation::Duration m_step{};
    unsigned int m_digits{};
    unsigned int m_pastWindow{};
    unsigned int m_futureWindow{};
};

/** Raw TOTP seed. It is move-only, wiped on destruction and never printable. */
class TotpSecret final {
public:
    [[nodiscard]] static foundation::Result<TotpSecret>
    create(foundation::SecretString bytes);
    [[nodiscard]] static foundation::Result<TotpSecret> generate(std::size_t byteCount = 20U);

    TotpSecret(const TotpSecret&) = delete;
    TotpSecret& operator=(const TotpSecret&) = delete;
    TotpSecret(TotpSecret&&) noexcept = default;
    TotpSecret& operator=(TotpSecret&&) noexcept = default;
    ~TotpSecret() = default;

    [[nodiscard]] const foundation::SecretString& bytes() const noexcept;
    /** Base32 is returned only at explicit enrollment time. Treat it as a credential. */
    [[nodiscard]] foundation::SecretString enrollmentBase32() const;

private:
    explicit TotpSecret(foundation::SecretString bytes);
    foundation::SecretString m_bytes;
};

[[nodiscard]] foundation::Result<std::string>
totpAt(const TotpSecret& secret, const TotpPolicy& policy, foundation::Instant now);

/** Returns the accepted time step; rejects malformed, stale and replayed codes uniformly. */
[[nodiscard]] foundation::Result<std::uint64_t>
verifyTotp(const TotpSecret& secret, const TotpPolicy& policy,
           std::string_view presented, foundation::Instant now,
           std::optional<std::uint64_t> lastAcceptedStep);

using RecoveryCodeDigest = security::Sha256Digest;

class RecoveryCodeBatch final {
public:
    RecoveryCodeBatch(const RecoveryCodeBatch&) = delete;
    RecoveryCodeBatch& operator=(const RecoveryCodeBatch&) = delete;
    RecoveryCodeBatch(RecoveryCodeBatch&&) noexcept = default;
    RecoveryCodeBatch& operator=(RecoveryCodeBatch&&) noexcept = default;
    ~RecoveryCodeBatch() = default;

    [[nodiscard]] const std::vector<foundation::SecretString>& codes() const noexcept;

private:
    friend class RecoveryCodeService;
    explicit RecoveryCodeBatch(std::vector<foundation::SecretString> codes);
    std::vector<foundation::SecretString> m_codes;
};

class RecoveryCodeRepository {
public:
    RecoveryCodeRepository(const RecoveryCodeRepository&) = delete;
    RecoveryCodeRepository& operator=(const RecoveryCodeRepository&) = delete;
    RecoveryCodeRepository(RecoveryCodeRepository&&) = delete;
    RecoveryCodeRepository& operator=(RecoveryCodeRepository&&) = delete;
    virtual ~RecoveryCodeRepository() = default;

    /** Replaces every previous code in one operation; an empty set revokes all codes. */
    [[nodiscard]] virtual foundation::Status
    replace(const identity::core::IdentityId& identity,
            std::vector<RecoveryCodeDigest> digests) = 0;
    /** Atomically checks and consumes exactly one matching code. */
    [[nodiscard]] virtual foundation::Status
    consume(const identity::core::IdentityId& identity,
            const RecoveryCodeDigest& digest) = 0;
    [[nodiscard]] virtual foundation::Result<std::size_t>
    remaining(const identity::core::IdentityId& identity) const = 0;

protected:
    RecoveryCodeRepository() = default;
};

class InMemoryRecoveryCodeRepository final : public RecoveryCodeRepository {
public:
    [[nodiscard]] foundation::Status
    replace(const identity::core::IdentityId& identity,
            std::vector<RecoveryCodeDigest> digests) override;
    [[nodiscard]] foundation::Status
    consume(const identity::core::IdentityId& identity,
            const RecoveryCodeDigest& digest) override;
    [[nodiscard]] foundation::Result<std::size_t>
    remaining(const identity::core::IdentityId& identity) const override;

private:
    mutable std::mutex m_mutex;
    std::map<identity::core::IdentityId, std::vector<RecoveryCodeDigest>> m_codes;
};

class RecoveryCodeService final {
public:
    [[nodiscard]] static foundation::Result<RecoveryCodeService>
    create(RecoveryCodeRepository& repository, foundation::SecretString pepper);

    RecoveryCodeService(const RecoveryCodeService&) = delete;
    RecoveryCodeService& operator=(const RecoveryCodeService&) = delete;
    RecoveryCodeService(RecoveryCodeService&&) noexcept = default;
    RecoveryCodeService& operator=(RecoveryCodeService&&) = delete;
    ~RecoveryCodeService() = default;

    [[nodiscard]] foundation::Result<RecoveryCodeBatch>
    issue(const identity::core::IdentityId& identity, std::size_t count);
    [[nodiscard]] foundation::Status
    consume(const identity::core::IdentityId& identity,
            const foundation::SecretString& presented);
    /** Invalidates every outstanding recovery code for the identity. */
    [[nodiscard]] foundation::Status
    revoke(const identity::core::IdentityId& identity);

private:
    RecoveryCodeService(RecoveryCodeRepository& repository,
                        foundation::SecretString pepper);
    [[nodiscard]] foundation::Result<RecoveryCodeDigest>
    digest(const foundation::SecretString& code) const;

    RecoveryCodeRepository* m_repository;
    foundation::SecretString m_pepper;
};

}
