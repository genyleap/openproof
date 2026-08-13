module;

#include <memory>
#include <string_view>

export module openproof.oauth:repository;

import openproof.foundation;
import :model;

export namespace openproof::oauth {

class AuthorizationCodeStore {
public:
    AuthorizationCodeStore(const AuthorizationCodeStore&) = delete;
    AuthorizationCodeStore& operator=(const AuthorizationCodeStore&) = delete;
    virtual ~AuthorizationCodeStore() = default;

    [[nodiscard]] virtual foundation::Status add(AuthorizationCode code) = 0;
    /**
     * @brief Atomically validates the grant binding, then consumes and returns the code.
     *
     * A client/redirect/PKCE mismatch does not consume an otherwise valid code. Expired
     * codes are removed. Unknown, expired, mismatched and replayed codes remain
     * indistinguishable to callers.
     */
    [[nodiscard]] virtual foundation::Result<AuthorizationCode>
    consumeBound(const CodeDigest& digest, foundation::Instant now,
                 std::string_view expectedClientId,
                 std::string_view expectedRedirectUri,
                 std::string_view expectedCodeChallenge) = 0;

protected:
    AuthorizationCodeStore() = default;
};

class InMemoryAuthorizationCodeStore final : public AuthorizationCodeStore {
public:
    InMemoryAuthorizationCodeStore();
    ~InMemoryAuthorizationCodeStore() override;
    InMemoryAuthorizationCodeStore(const InMemoryAuthorizationCodeStore&) = delete;
    InMemoryAuthorizationCodeStore& operator=(const InMemoryAuthorizationCodeStore&) = delete;
    InMemoryAuthorizationCodeStore(InMemoryAuthorizationCodeStore&&) = delete;
    InMemoryAuthorizationCodeStore& operator=(InMemoryAuthorizationCodeStore&&) = delete;

    [[nodiscard]] foundation::Status add(AuthorizationCode code) override;
    [[nodiscard]] foundation::Result<AuthorizationCode>
    consumeBound(const CodeDigest& digest, foundation::Instant now,
                 std::string_view expectedClientId,
                 std::string_view expectedRedirectUri,
                 std::string_view expectedCodeChallenge) override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}
