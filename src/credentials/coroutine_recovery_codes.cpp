#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <utility>
#include <vector>

#include "coroutine_recovery_codes.hpp"

import openproof.security;

namespace openproof::credentials {
namespace asio = boost::asio;

foundation::Result<CoroutineRecoveryCodeService>
CoroutineRecoveryCodeService::create(
    CoroutineRecoveryCodeRepository& repository,
    foundation::SecretString pepper)
{
    if (pepper.expose().size() < 32U) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "A recovery-code pepper must contain at least 32 bytes.");
    }
    return CoroutineRecoveryCodeService{repository, std::move(pepper)};
}

asio::awaitable<foundation::Result<std::vector<foundation::SecretString>>>
CoroutineRecoveryCodeService::issue(
    identity::core::IdentityId identity, std::size_t count)
{
    if (identity.empty() || count == 0U || count > 32U) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Recovery-code issuance parameters are invalid.");
    }
    std::vector<foundation::SecretString> codes;
    std::vector<RecoveryCodeDigest> digests;
    codes.reserve(count);
    digests.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        auto generated = security::randomTokenBase64Url(20U);
        if (!generated) co_return foundation::fail(generated.error());
        foundation::SecretString code{std::move(generated).value()};
        auto fingerprint = security::hmacSha256(m_pepper, code.expose());
        if (!fingerprint) co_return foundation::fail(fingerprint.error());
        digests.emplace_back(fingerprint.value());
        codes.emplace_back(std::move(code));
    }

    // On any persistence failure none of the plaintext codes escape to HTTP.
    auto saved = co_await m_repository->replaceAsync(
        std::move(identity), std::move(digests));
    if (!saved) co_return foundation::fail(saved.error());
    co_return foundation::Result<std::vector<foundation::SecretString>>{
        std::move(codes)};
}

asio::awaitable<foundation::Status>
CoroutineRecoveryCodeService::consume(
    identity::core::IdentityId identity,
    foundation::SecretString presented)
{
    if (identity.empty() || presented.empty()) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Recovery-code redemption is invalid.");
    }
    auto fingerprint = security::hmacSha256(m_pepper, presented.expose());
    if (!fingerprint) co_return foundation::fail(fingerprint.error());
    // presented is a scoped SecretString: its bytes are scrubbed whether
    // repository redemption succeeds, denies a replay or throws.
    co_return co_await m_repository->consumeAsync(
        std::move(identity), std::move(fingerprint).value());
}

asio::awaitable<foundation::Status>
CoroutineRecoveryCodeService::revoke(identity::core::IdentityId identity)
{
    if (identity.empty()) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Recovery-code revocation requires an identity.");
    }
    co_return co_await m_repository->replaceAsync(std::move(identity), {});
}

asio::awaitable<foundation::Result<std::size_t>>
CoroutineRecoveryCodeService::remaining(identity::core::IdentityId identity)
{
    if (identity.empty()) {
        co_return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Recovery-code enumeration requires an identity.");
    }
    co_return co_await m_repository->remainingAsync(std::move(identity));
}

} // namespace openproof::credentials
