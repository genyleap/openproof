module;

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

module openproof.oauth;

namespace openproof::oauth {
namespace {
[[nodiscard]] std::string digestKey(const CodeDigest& digest)
{
    return foundation::toHex(digest.bytes());
}
}

struct InMemoryAuthorizationCodeStore::Impl final {
    std::mutex mutex;
    std::map<std::string, std::unique_ptr<AuthorizationCode>, std::less<>> codes;
};

InMemoryAuthorizationCodeStore::InMemoryAuthorizationCodeStore()
    : m_impl(std::make_unique<Impl>())
{
}

InMemoryAuthorizationCodeStore::~InMemoryAuthorizationCodeStore() = default;

foundation::Status InMemoryAuthorizationCodeStore::add(AuthorizationCode code)
{
    std::scoped_lock lock{m_impl->mutex};
    const auto key = digestKey(code.digest());
    if (m_impl->codes.contains(key)) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The authorization code already exists.");
    }
    m_impl->codes.emplace(key, std::make_unique<AuthorizationCode>(std::move(code)));
    return foundation::ok();
}

foundation::Result<AuthorizationCode> InMemoryAuthorizationCodeStore::consumeBound(
    const CodeDigest& digest, foundation::Instant now,
    std::string_view expectedClientId, std::string_view expectedRedirectUri,
    std::string_view expectedCodeChallenge)
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->codes.find(digestKey(digest));
    if (found == m_impl->codes.end()) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authorization grant is invalid.");
    }
    if (found->second->expiredAt(now)) {
        m_impl->codes.erase(found);
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authorization grant is invalid.");
    }
    const AuthorizationCode& code = *found->second;
    if (code.clientId().value() != expectedClientId
        || code.redirectUri() != expectedRedirectUri
        || code.codeChallenge().value() != expectedCodeChallenge) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The authorization grant is invalid.");
    }
    AuthorizationCode consumed = std::move(*found->second);
    m_impl->codes.erase(found);
    return consumed;
}

}
