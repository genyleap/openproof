#include "async_pool.hpp"

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_verification_challenge_store.hpp"

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace core = identity::core;
namespace {
using Clock = std::chrono::steady_clock;
using Params = std::vector<std::optional<std::string>>;

foundation::Duration remaining(Clock::time_point deadline)
{
    auto left = std::chrono::duration_cast<foundation::Duration>(deadline - Clock::now());
    if (left <= foundation::Duration::zero())
        throw std::runtime_error{"Verification persistence deadline exceeded"};
    return left;
}

bool supported(account::VerificationPurpose purpose)
{
    return purpose == account::VerificationPurpose::ChangeEmail
        || purpose == account::VerificationPurpose::VerifyPhone;
}

bool exactRow(const async_detail::QueryRows& rows, std::string_view expected)
{
    return rows.rows.size() == 1U && rows.rows.front().size() == 1U
        && rows.rows.front().front() && *rows.rows.front().front() == expected;
}
} // namespace

class CoroutineVerificationChallengeStore::Impl final {
public:
    Impl(asio::any_io_executor executor, foundation::SecretString dsn,
         core::OrganizationId tenantValue, std::size_t capacity,
         foundation::Duration acquireTimeout, foundation::Duration connectTimeout,
         foundation::Duration queryTimeoutValue)
        : pool(std::move(executor), std::string{dsn.expose()}, capacity,
               acquireTimeout, connectTimeout), tenant(std::move(tenantValue)),
          queryTimeout(queryTimeoutValue)
    {
        if (tenant.empty() || queryTimeout <= foundation::Duration::zero())
            throw std::invalid_argument{"Invalid native verification store configuration"};
    }
    async_detail::AsyncConnectionPool pool;
    core::OrganizationId tenant;
    foundation::Duration queryTimeout;
};

CoroutineVerificationChallengeStore::CoroutineVerificationChallengeStore(
    asio::any_io_executor executor, foundation::SecretString connectionString,
    core::OrganizationId tenant, std::size_t capacity,
    foundation::Duration acquireTimeout, foundation::Duration connectTimeout,
    foundation::Duration queryTimeout)
    : m_impl(std::make_unique<Impl>(std::move(executor), std::move(connectionString),
        std::move(tenant), capacity, acquireTimeout, connectTimeout, queryTimeout))
{
}

CoroutineVerificationChallengeStore::~CoroutineVerificationChallengeStore() = default;

asio::awaitable<foundation::Status> CoroutineVerificationChallengeStore::replaceAsync(
    account::VerificationChallenge challenge)
{
    return replaceImpl(std::move(challenge), std::nullopt);
}

asio::awaitable<foundation::Status> CoroutineVerificationChallengeStore::reserveAndReplaceAsync(
    account::VerificationChallenge challenge, identity::provider::ProviderId provider)
{
    return replaceImpl(std::move(challenge), std::move(provider));
}

asio::awaitable<foundation::Status> CoroutineVerificationChallengeStore::replaceImpl(
    account::VerificationChallenge challenge,
    std::optional<identity::provider::ProviderId> provider)
{
    if ((provider && (provider->empty() || provider->value().size() > 200U))
        || !supported(challenge.purpose()) || challenge.attempts() != 0U
        || challenge.id().value().size() > 200U || challenge.identity().value().size() > 200U
        || (challenge.purpose() == account::VerificationPurpose::ChangeEmail
            && challenge.channel() != account::VerificationChannel::Email)
        || (challenge.purpose() == account::VerificationPurpose::VerifyPhone
            && challenge.channel() != account::VerificationChannel::Sms))
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        auto& connection = lease.connection();
        static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",
            {}, remaining(deadline)));
        const std::string owner{challenge.identity().value()};
        const std::string tenant{m_impl->tenant.value()};
        const std::string id{challenge.id().value()};
        const auto purpose = std::to_string(static_cast<unsigned int>(challenge.purpose()));
        // Same canonical identity lock as the synchronous writer. The
        // following DELETE obtains a fresh READ COMMITTED snapshot after
        // waiting for a concurrent replacement, including when none existed.
        Params lockParams{owner, tenant};
        const auto locked = co_await connection.query(
            "SELECT i.id FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND o.state=0 "
            "FOR UPDATE OF i FOR SHARE OF o", std::move(lockParams), remaining(deadline));
        if (locked.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK", {}, remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
        }
        if (!exactRow(locked, owner)) throw std::runtime_error{"Invalid challenge owner"};
        if (provider) {
            if (challenge.purpose() == account::VerificationPurpose::ChangeEmail) {
                Params profileParams{owner};
                const auto profile = co_await connection.query(
                    "SELECT identity_id FROM openproof.identity_profiles WHERE identity_id=$1",
                    std::move(profileParams), remaining(deadline));
                if (profile.rows.empty()) {
                    static_cast<void>(co_await connection.query("ROLLBACK", {}, remaining(deadline)));
                    co_return foundation::fail(foundation::ErrorCode::NotFound);
                }
                if (!exactRow(profile, owner))
                    throw std::runtime_error{"Invalid verification profile"};
            }
            const std::string providerName{provider->value()};
            const std::string destination{challenge.destination()};
            Params externalParams{providerName, destination};
            const auto external = co_await connection.query(
                "SELECT identity_id FROM openproof.external_identities "
                "WHERE provider=$1 AND external_subject=$2",
                std::move(externalParams), remaining(deadline));
            if (!external.rows.empty() && !exactRow(external, owner)) {
                static_cast<void>(co_await connection.query("ROLLBACK", {}, remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
            }
            // The unique subject key arbitrates concurrent reservations
            // even when no reservation existed when the transaction began.
            Params reserveParams{providerName, destination, owner,
                std::to_string(challenge.expiresAt().time_since_epoch().count()),
                std::to_string(challenge.createdAt().time_since_epoch().count())};
            const auto reserved = co_await connection.query(
                "INSERT INTO openproof.pending_external_identity_reservations AS r "
                "(provider,external_subject,identity_id,expires_at_ms) VALUES($1,$2,$3,$4) "
                "ON CONFLICT(provider,external_subject) DO UPDATE SET identity_id=EXCLUDED.identity_id,"
                "expires_at_ms=EXCLUDED.expires_at_ms "
                "WHERE r.identity_id=EXCLUDED.identity_id OR r.expires_at_ms<=$5 "
                "RETURNING identity_id", std::move(reserveParams), remaining(deadline));
            if (reserved.rows.empty()) {
                static_cast<void>(co_await connection.query("ROLLBACK", {}, remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
            }
            if (!exactRow(reserved, owner))
                throw std::runtime_error{"Invalid verification reservation"};
        }
        Params removeParams{owner, purpose};
        static_cast<void>(co_await connection.query(
            "DELETE FROM openproof.account_verification_challenges "
            "WHERE identity_id=$1 AND purpose=$2",
            std::move(removeParams), remaining(deadline)));
        Params insertParams{id, owner, purpose,
            std::to_string(static_cast<unsigned int>(challenge.channel())),
            std::string{challenge.destination()}, foundation::toHex(challenge.digest().bytes()),
            std::to_string(challenge.createdAt().time_since_epoch().count()),
            std::to_string(challenge.expiresAt().time_since_epoch().count())};
        const auto inserted = co_await connection.query(
            "INSERT INTO openproof.account_verification_challenges "
            "(id,identity_id,purpose,channel,destination,secret_digest,attempts,created_at_ms,expires_at_ms) "
            "VALUES($1,$2,$3,$4,$5,decode($6,'hex'),0,$7,$8) RETURNING id",
            std::move(insertParams), remaining(deadline));
        if (!exactRow(inserted, id)) throw std::runtime_error{"Invalid challenge insertion"};
        static_cast<void>(co_await connection.query("COMMIT", {}, remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        // Non-idle or failed leases are discarded by the existing pool.
        // Never retry an ambiguous commit automatically.
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native verification persistence is unavailable.");
    }
}

asio::awaitable<foundation::Status> CoroutineVerificationChallengeStore::discardAsync(
    account::VerificationId id, core::IdentityId owner, account::VerificationPurpose purpose)
{
    if (id.empty() || owner.empty() || !supported(purpose))
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{id.value()}, std::string{owner.value()},
            std::to_string(static_cast<unsigned int>(purpose)),
            std::string{m_impl->tenant.value()}};
        // Do not match solely on identity/purpose: a newer challenge may
        // have replaced this one while delivery was suspended.
        const auto removed = co_await lease.connection().query(
            "DELETE FROM openproof.account_verification_challenges c "
            "USING openproof.identities i WHERE c.id=$1 AND c.identity_id=$2 "
            "AND c.purpose=$3 AND i.id=c.identity_id AND i.organization_id=$4 "
            "RETURNING c.id", std::move(params), remaining(deadline));
        if (!removed.rows.empty() && !exactRow(removed, id.value()))
            throw std::runtime_error{"Invalid challenge compensation result"};
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native verification compensation is unavailable.");
    }
}

} // namespace openproof::storage::postgres
