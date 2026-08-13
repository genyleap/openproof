module;

#include <memory>
#include <string>

export module openproof.token:repository;

import openproof.foundation;
import :model;

export namespace openproof::token {

/** @brief Atomic persistence port for access and rotating refresh tokens. */
class TokenRepository {
public:
    TokenRepository(const TokenRepository&) = delete;
    TokenRepository& operator=(const TokenRepository&) = delete;
    virtual ~TokenRepository() = default;

    [[nodiscard]] virtual foundation::Status storeInitial(
        AccessTokenRecord access, RefreshTokenRecord refresh) = 0;
    [[nodiscard]] virtual foundation::Status storeAccessOnly(
        AccessTokenRecord access) = 0;
    [[nodiscard]] virtual foundation::Result<AccessTokenRecord>
    findAccess(const TokenDigest& digest) = 0;
    [[nodiscard]] virtual foundation::Result<RefreshTokenRecord>
    findRefresh(const TokenDigest& digest) = 0;
    [[nodiscard]] virtual foundation::Status rotateRefresh(
        const TokenDigest& presented, foundation::Instant now,
        AccessTokenRecord replacementAccess, RefreshTokenRecord replacementRefresh) = 0;
    [[nodiscard]] virtual foundation::Status revokeFamily(
        const TokenFamilyId& family, foundation::Instant now) = 0;
    [[nodiscard]] virtual foundation::Status revokeToken(
        const TokenDigest& digest, foundation::Instant now) = 0;
protected:
    TokenRepository() = default;
};

class InMemoryTokenRepository final : public TokenRepository {
public:
    InMemoryTokenRepository();
    ~InMemoryTokenRepository() override;
    InMemoryTokenRepository(const InMemoryTokenRepository&) = delete;
    InMemoryTokenRepository& operator=(const InMemoryTokenRepository&) = delete;
    InMemoryTokenRepository(InMemoryTokenRepository&&) = delete;
    InMemoryTokenRepository& operator=(InMemoryTokenRepository&&) = delete;

    [[nodiscard]] foundation::Status storeInitial(
        AccessTokenRecord access, RefreshTokenRecord refresh) override;
    [[nodiscard]] foundation::Status storeAccessOnly(
        AccessTokenRecord access) override;
    [[nodiscard]] foundation::Result<AccessTokenRecord>
    findAccess(const TokenDigest& digest) override;
    [[nodiscard]] foundation::Result<RefreshTokenRecord>
    findRefresh(const TokenDigest& digest) override;
    [[nodiscard]] foundation::Status rotateRefresh(
        const TokenDigest& presented, foundation::Instant now,
        AccessTokenRecord replacementAccess, RefreshTokenRecord replacementRefresh) override;
    [[nodiscard]] foundation::Status revokeFamily(
        const TokenFamilyId& family, foundation::Instant now) override;
    [[nodiscard]] foundation::Status revokeToken(
        const TokenDigest& digest, foundation::Instant now) override;
private:
    [[nodiscard]] static std::string key(const TokenDigest& digest);
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}
