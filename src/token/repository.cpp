module;

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

module openproof.token;

namespace openproof::token {

namespace {
[[nodiscard]] foundation::Error invalidCredential(std::string detail)
{
    return foundation::Error{foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}
}

struct InMemoryTokenRepository::Impl final {
    std::mutex mutex;
    std::map<std::string, std::unique_ptr<AccessTokenRecord>, std::less<>> access;
    std::map<std::string, std::unique_ptr<RefreshTokenRecord>, std::less<>> refresh;
};

InMemoryTokenRepository::InMemoryTokenRepository()
    : m_impl(std::make_unique<Impl>())
{
}

InMemoryTokenRepository::~InMemoryTokenRepository() = default;

std::string InMemoryTokenRepository::key(const TokenDigest& digest)
{ return foundation::toHex(digest.bytes()); }

foundation::Status InMemoryTokenRepository::storeInitial(
    AccessTokenRecord access, RefreshTokenRecord refresh)
{
    const std::lock_guard guard{m_impl->mutex};
    const auto accessKey = key(access.digest());
    const auto refreshKey = key(refresh.digest());
    if (m_impl->access.contains(accessKey) || m_impl->refresh.contains(refreshKey)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The generated token fingerprint already exists.");
    }
    m_impl->access.emplace(
        accessKey, std::make_unique<AccessTokenRecord>(std::move(access)));
    m_impl->refresh.emplace(
        refreshKey, std::make_unique<RefreshTokenRecord>(std::move(refresh)));
    return foundation::ok();
}

foundation::Status InMemoryTokenRepository::storeAccessOnly(AccessTokenRecord access)
{
    const std::lock_guard guard{m_impl->mutex};
    const auto accessKey = key(access.digest());
    if (m_impl->access.contains(accessKey)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The generated token fingerprint already exists.");
    }
    m_impl->access.emplace(
        accessKey, std::make_unique<AccessTokenRecord>(std::move(access)));
    return foundation::ok();
}

foundation::Result<AccessTokenRecord>
InMemoryTokenRepository::findAccess(const TokenDigest& digest)
{
    const std::lock_guard guard{m_impl->mutex};
    const auto found = m_impl->access.find(key(digest));
    if (found == m_impl->access.end()) {
        return foundation::fail(invalidCredential("Unknown access token."));
    }
    return *found->second;
}

foundation::Result<RefreshTokenRecord>
InMemoryTokenRepository::findRefresh(const TokenDigest& digest)
{
    const std::lock_guard guard{m_impl->mutex};
    const auto found = m_impl->refresh.find(key(digest));
    if (found == m_impl->refresh.end()) {
        return foundation::fail(invalidCredential("Unknown refresh token."));
    }
    return *found->second;
}

foundation::Status InMemoryTokenRepository::rotateRefresh(
    const TokenDigest& presented, foundation::Instant now,
    AccessTokenRecord replacementAccess, RefreshTokenRecord replacementRefresh)
{
    const std::lock_guard guard{m_impl->mutex};
    const auto found = m_impl->refresh.find(key(presented));
    if (found == m_impl->refresh.end()) {
        return foundation::fail(invalidCredential("Unknown refresh token."));
    }
    if (!found->second->usableAt(now)) {
        const TokenFamilyId family = found->second->family();
        for (auto& [_, record] : m_impl->access) {
            if (record->family() == family) record->revoke(now);
        }
        for (auto& [_, record] : m_impl->refresh) {
            if (record->family() == family) record->revoke(now);
        }
        return foundation::fail(invalidCredential(
            "Refresh token reuse or expiry detected; family revoked."));
    }
    if (replacementAccess.family() != found->second->family()
        || replacementRefresh.family() != found->second->family()
        || replacementRefresh.sequence() != found->second->sequence() + 1U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The refresh rotation replacement is inconsistent.");
    }
    const auto accessKey = key(replacementAccess.digest());
    const auto refreshKey = key(replacementRefresh.digest());
    if (m_impl->access.contains(accessKey) || m_impl->refresh.contains(refreshKey)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The generated token fingerprint already exists.");
    }
    found->second->markUsed(now);
    m_impl->access.emplace(
        accessKey, std::make_unique<AccessTokenRecord>(std::move(replacementAccess)));
    m_impl->refresh.emplace(
        refreshKey, std::make_unique<RefreshTokenRecord>(std::move(replacementRefresh)));
    return foundation::ok();
}

foundation::Status InMemoryTokenRepository::revokeFamily(
    const TokenFamilyId& family, foundation::Instant now)
{
    const std::lock_guard guard{m_impl->mutex};
    for (auto& [_, record] : m_impl->access) {
        if (record->family() == family) record->revoke(now);
    }
    for (auto& [_, record] : m_impl->refresh) {
        if (record->family() == family) record->revoke(now);
    }
    return foundation::ok();
}

foundation::Status InMemoryTokenRepository::revokeToken(
    const TokenDigest& digest, foundation::Instant now)
{
    const std::lock_guard guard{m_impl->mutex};
    if (const auto access = m_impl->access.find(key(digest));
        access != m_impl->access.end()) {
        access->second->revoke(now);
        return foundation::ok();
    }
    if (const auto refresh = m_impl->refresh.find(key(digest));
        refresh != m_impl->refresh.end()) {
        const TokenFamilyId family = refresh->second->family();
        for (auto& [_, record] : m_impl->access) {
            if (record->family() == family) record->revoke(now);
        }
        for (auto& [_, record] : m_impl->refresh) {
            if (record->family() == family) record->revoke(now);
        }
    }
    return foundation::ok();
}

}
