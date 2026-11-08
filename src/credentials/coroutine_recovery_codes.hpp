#pragma once

// Protocol-neutral coroutine SPI for recovery codes. A repository may use
// PostgreSQL, another database or an in-memory test implementation: the
// credential domain has no dependency on the storage vendor.
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <utility>
#include <vector>

import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;

namespace openproof::credentials {

class CoroutineRecoveryCodeRepository {
public:
    CoroutineRecoveryCodeRepository(const CoroutineRecoveryCodeRepository&) = delete;
    CoroutineRecoveryCodeRepository& operator=(
        const CoroutineRecoveryCodeRepository&) = delete;
    virtual ~CoroutineRecoveryCodeRepository() = default;

    // All parameters are owned by the coroutine frame, never borrowed from
    // a mutable HTTP request or a plaintext secret's transient storage.
    [[nodiscard]] virtual boost::asio::awaitable<foundation::Status>
    replaceAsync(identity::core::IdentityId identity,
                 std::vector<RecoveryCodeDigest> digests) = 0;

    [[nodiscard]] virtual boost::asio::awaitable<foundation::Status>
    consumeAsync(identity::core::IdentityId identity,
                 RecoveryCodeDigest digest) = 0;

    [[nodiscard]] virtual boost::asio::awaitable<foundation::Result<std::size_t>>
    remainingAsync(identity::core::IdentityId identity) = 0;

protected:
    CoroutineRecoveryCodeRepository() = default;
};

class CoroutineRecoveryCodeService final {
public:
    [[nodiscard]] static foundation::Result<CoroutineRecoveryCodeService>
    create(CoroutineRecoveryCodeRepository& repository,
           foundation::SecretString pepper);

    CoroutineRecoveryCodeService(const CoroutineRecoveryCodeService&) = delete;
    CoroutineRecoveryCodeService& operator=(const CoroutineRecoveryCodeService&) = delete;
    CoroutineRecoveryCodeService(CoroutineRecoveryCodeService&&) noexcept = default;
    CoroutineRecoveryCodeService& operator=(CoroutineRecoveryCodeService&&) = delete;

    // The client may display these freshly generated codes exactly once
    // after their digests have been durably replaced by the repository.
    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<std::vector<foundation::SecretString>>>
    issue(identity::core::IdentityId identity, std::size_t count);

    // Constant-time keyed digest is calculated before any SQL read; repository
    // redemption is a single identity-scoped atomic DELETE.
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    consume(identity::core::IdentityId identity,
            foundation::SecretString presented);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    revoke(identity::core::IdentityId identity);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::size_t>>
    remaining(identity::core::IdentityId identity);

private:
    CoroutineRecoveryCodeService(CoroutineRecoveryCodeRepository& repository,
                                 foundation::SecretString pepper)
        : m_repository(&repository), m_pepper(std::move(pepper)) {}

    CoroutineRecoveryCodeRepository* m_repository;
    foundation::SecretString m_pepper;
};

} // namespace openproof::credentials
