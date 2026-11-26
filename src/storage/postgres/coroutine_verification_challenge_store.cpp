#include "async_pool.hpp"

#include <chrono>
#include <algorithm>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_verification_challenge_store.hpp"

import openproof.security;

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

bool publicPurpose(account::VerificationPurpose purpose)
{
    return purpose==account::VerificationPurpose::SignupEmail
        || purpose==account::VerificationPurpose::PasswordReset;
}

std::string publicOwnerSql(account::VerificationPurpose purpose,bool locked)
{
    // Only an existing pending signup reservation or active local link is
    // eligible. A contact-change reservation must never become signup proof.
    std::string sql=purpose==account::VerificationPurpose::SignupEmail
        ? "SELECT i.id FROM openproof.pending_external_identity_reservations r "
          "JOIN openproof.identities i ON i.id=r.identity_id "
          "JOIN openproof.organizations o ON o.id=i.organization_id "
          "JOIN openproof.password_credentials p ON p.identity_id=i.id "
          "WHERE r.provider=$1 AND r.external_subject=$2 AND r.expires_at_ms>$3 "
          "AND r.verification_id IS NULL AND i.status IN (0,3) "
          "AND NOT EXISTS (SELECT 1 FROM openproof.external_identities e "
          "WHERE e.provider=$1 AND (e.external_subject=$2 OR e.identity_id=i.id)) "
        : "SELECT i.id FROM openproof.external_identities e "
          "JOIN openproof.identities i ON i.id=e.identity_id "
          "JOIN openproof.organizations o ON o.id=i.organization_id "
          "JOIN openproof.password_credentials p ON p.identity_id=i.id "
          "WHERE e.provider=$1 AND e.external_subject=$2 AND $3::bigint>=0 "
          "AND i.status=0 ";
    sql+="AND i.organization_id=$4 AND o.state=0";
    if (locked) {
        sql+=" AND i.id=$5";
        sql+=purpose==account::VerificationPurpose::SignupEmail
            ? " FOR SHARE OF r,p,o" : " FOR SHARE OF e,p,o";
    }
    return sql;
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

asio::awaitable<foundation::Result<std::optional<core::IdentityId>>>
CoroutineVerificationChallengeStore::findPublicEmailOwnerAsync(
    identity::provider::ProviderId provider,account::VerificationPurpose purpose,
    std::string destination,foundation::Instant now)
{
    if (!publicPurpose(purpose) || provider.empty() || provider.value().size()>200U
        || destination.empty() || destination.size()>320U)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        Params params{std::string{provider.value()},std::move(destination),
            std::to_string(now.time_since_epoch().count()),std::string{m_impl->tenant.value()}};
        const auto rows=co_await lease.connection().query(publicOwnerSql(purpose,false),
            std::move(params),remaining(deadline));
        if (rows.rows.empty()) co_return std::optional<core::IdentityId>{};
        if (rows.rows.size()!=1U || rows.rows.front().size()!=1U || !rows.rows.front().front())
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        co_return std::optional<core::IdentityId>{core::IdentityId{*rows.rows.front().front()}};
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

asio::awaitable<foundation::Status> CoroutineVerificationChallengeStore::replacePublicEmailAsync(
    account::VerificationChallenge challenge,identity::provider::ProviderId provider)
{
    return replaceImpl(std::move(challenge),std::move(provider),true);
}

asio::awaitable<foundation::Result<CoroutineVerificationChallengeStore::PendingSignup>>
CoroutineVerificationChallengeStore::provisionSignupAsync(
    identity::provider::ProviderId provider,std::string email,credentials::PasswordHash passwordHash,
    std::optional<std::string> displayName,const account::VerificationKey& key,
    foundation::Instant now,foundation::Duration lifetime)
{
    auto normalized=account::VerificationPreparation::normalizePublicEmail(std::move(email));
    const auto valid=[](std::string_view value,std::size_t maximum) {
        return !value.empty() && value.size()<=maximum
            && std::ranges::none_of(value,[](char ch){
                const auto byte=static_cast<unsigned char>(ch);
                return byte<0x20U || byte==0x7fU;
            });
    };
    if (!normalized || !valid(normalized.value(),320U)
        || !valid(provider.value(),200U)
        || (displayName && !valid(*displayName,256U))
        || passwordHash.encoded().empty() || passwordHash.encoded().size()>4096U
        || lifetime<=foundation::Duration::zero() || lifetime>std::chrono::hours{48}
        || now.time_since_epoch().count()<0
        || now>foundation::Instant::max()-lifetime)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    const std::string destination=std::move(normalized).value();
    const std::string providerName{provider.value()};
    const std::string tenant{m_impl->tenant.value()};
    const auto observed=std::to_string(now.time_since_epoch().count());
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",{},remaining(deadline)));
        // Same-subject native signups serialize. The global reservation PK
        // remains the final arbiter with compatibility writers.
        Params subjectLock{"openproof/signup/v1:"+std::to_string(providerName.size())+":"+providerName+destination};
        static_cast<void>(co_await connection.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            std::move(subjectLock),remaining(deadline)));
        Params tenantParams{tenant};
        const auto organization=co_await connection.query(
            "SELECT id FROM openproof.organizations WHERE id=$1 AND state=0 FOR SHARE",
            std::move(tenantParams),remaining(deadline));
        if (!exactRow(organization,tenant)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
        }
        Params subjectParams{providerName,destination,observed};
        const auto occupied=co_await connection.query(
            "SELECT identity_id FROM openproof.external_identities WHERE provider=$1 AND external_subject=$2 "
            "UNION ALL SELECT identity_id FROM openproof.pending_external_identity_reservations "
            "WHERE provider=$1 AND external_subject=$2 AND expires_at_ms>$3 LIMIT 1",
            std::move(subjectParams),remaining(deadline));
        if (!occupied.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
        }
        // At most two nonterminal candidates are needed to detect ambiguity.
        // Lock canonical rows before revalidating the selected profile and
        // local link. No caller-selected identity may receive a credential.
        Params matchesParams{tenant,destination};
        const auto matches=co_await connection.query(
            "SELECT i.id,i.status FROM openproof.identities i JOIN openproof.identity_profiles p ON p.identity_id=i.id "
            "WHERE i.organization_id=$1 AND p.email_verified=true AND lower(p.email)=lower($2) "
            "AND i.status NOT IN (4,5) ORDER BY i.status,i.id LIMIT 2 FOR UPDATE OF i",
            std::move(matchesParams),remaining(deadline));
        if (matches.rows.size()>1U) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            // Active candidates sort before blocked candidates. Two blocked
            // matches retain the legacy AlreadyExists response.
            const auto& first=matches.rows.front();
            if (first.size()!=2U || !first[1])
                throw std::runtime_error{"Invalid signup identity row"};
            co_return foundation::fail(*first[1]=="0"?foundation::ErrorCode::Conflict
                :foundation::ErrorCode::AlreadyExists);
        }
        const bool createdIdentity=matches.rows.empty();
        std::string owner;
        if (!createdIdentity) {
            const auto& row=matches.rows.front();
            if (row.size()!=2U || !row[0] || !row[1])
                throw std::runtime_error{"Invalid signup identity row"};
            if (*row[1]!="0") {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
            }
            owner=*row[0];
            Params eligibilityParams{owner,destination,providerName};
            const auto eligible=co_await connection.query(
                "SELECT p.identity_id FROM openproof.identity_profiles p "
                "WHERE p.identity_id=$1 AND p.email_verified=true AND lower(p.email)=lower($2) "
                "AND NOT EXISTS(SELECT 1 FROM openproof.external_identities e "
                "WHERE e.identity_id=$1 AND e.provider=$3) "
                "AND NOT EXISTS(SELECT 1 FROM openproof.password_credentials c WHERE c.identity_id=$1) "
                "FOR SHARE OF p",std::move(eligibilityParams),remaining(deadline));
            if (!exactRow(eligible,owner)) {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
            }
        } else {
            auto random=security::randomTokenBase64Url(24U);
            if (!random) {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(random.error());
            }
            owner="opi_"+std::move(random).value();
            Params identityParams{owner,tenant,observed};
            const auto inserted=co_await connection.query(
                "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) "
                "VALUES($1,$2,0,3,$3) RETURNING id",std::move(identityParams),remaining(deadline));
            if (!exactRow(inserted,owner)) throw std::runtime_error{"Invalid signup identity insert"};
            Params profileParams{owner,std::move(displayName),destination,observed};
            const auto profile=co_await connection.query(
                "INSERT INTO openproof.identity_profiles(identity_id,display_name,email,email_verified,created_at_ms,updated_at_ms) "
                "VALUES($1,$2,$3,false,$4,$4) RETURNING identity_id",
                std::move(profileParams),remaining(deadline));
            if (!exactRow(profile,owner)) throw std::runtime_error{"Invalid signup profile insert"};
        }
        auto prepared=account::VerificationPreparation::prepare(key,core::IdentityId{owner},
            account::VerificationPurpose::SignupEmail,account::VerificationChannel::Email,
            destination,now,lifetime);
        if (!prepared) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(prepared.error());
        }
        const auto& challenge=prepared->first;
        const std::string expires=std::to_string(challenge.expiresAt().time_since_epoch().count());
        const std::string challengeId{challenge.id().value()};
        // Do not tag signup reservations as contact-change generations:
        // existing signup verification and resend require an untagged row.
        Params reserveParams{providerName,destination,owner,expires,observed};
        const auto reserved=co_await connection.query(
            "INSERT INTO openproof.pending_external_identity_reservations AS r "
            "(provider,external_subject,identity_id,expires_at_ms,verification_id) "
            "VALUES($1,$2,$3,$4,NULL) ON CONFLICT(provider,external_subject) DO UPDATE "
            "SET identity_id=EXCLUDED.identity_id,expires_at_ms=EXCLUDED.expires_at_ms,verification_id=NULL "
            "WHERE r.expires_at_ms<=$5 RETURNING identity_id",
            std::move(reserveParams),remaining(deadline));
        if (!exactRow(reserved,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
        }
        // Recheck external ownership after obtaining the reservation. No
        // provisioned credential may overwrite an existing provider link.
        Params linkParams{providerName,destination,owner};
        const auto linked=co_await connection.query(
            "SELECT identity_id FROM openproof.external_identities WHERE provider=$1 "
            "AND (external_subject=$2 OR identity_id=$3) LIMIT 1",
            std::move(linkParams),remaining(deadline));
        if (!linked.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
        }
        Params credentialParams{owner,std::string{passwordHash.encoded()},observed};
        const auto credential=co_await connection.query(
            "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
            "VALUES($1,$2,$3) ON CONFLICT(identity_id) DO NOTHING RETURNING identity_id",
            std::move(credentialParams),remaining(deadline));
        if (!exactRow(credential,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
        }
        // A stale, previously issued signup secret cannot activate this
        // new password generation. Only the newly persisted proof survives.
        Params oldChallengeParams{owner};
        static_cast<void>(co_await connection.query(
            "WITH obsolete AS (DELETE FROM openproof.account_verification_challenges "
            "WHERE identity_id=$1 AND purpose=0 RETURNING id,identity_id) "
            "DELETE FROM openproof.pending_external_identity_reservations r USING obsolete c "
            "WHERE r.verification_id=c.id AND r.identity_id=c.identity_id",
            std::move(oldChallengeParams),remaining(deadline)));
        Params challengeParams{challengeId,owner,destination,foundation::toHex(challenge.digest().bytes()),observed,expires};
        const auto stored=co_await connection.query(
            "INSERT INTO openproof.account_verification_challenges "
            "(id,identity_id,purpose,channel,destination,secret_digest,attempts,created_at_ms,expires_at_ms) "
            "VALUES($1,$2,0,0,$3,decode($4,'hex'),0,$5,$6) RETURNING id",
            std::move(challengeParams),remaining(deadline));
        if (!exactRow(stored,challengeId)) throw std::runtime_error{"Invalid signup challenge insert"};
        static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        // Delivery begins only after the durable transaction has committed.
        co_return PendingSignup{std::move(prepared->second),createdIdentity};
    } catch (const std::exception&) {
        // Pool drops a non-idle lease; an ambiguous commit is never retried.
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native signup persistence is unavailable.");
    }
}

asio::awaitable<foundation::Status> CoroutineVerificationChallengeStore::replaceImpl(
    account::VerificationChallenge challenge,
    std::optional<identity::provider::ProviderId> provider,bool publicEmail)
{
    if ((provider && (provider->empty() || provider->value().size() > 200U))
        || (publicEmail ? (!provider || !publicPurpose(challenge.purpose())
                || challenge.channel()!=account::VerificationChannel::Email)
            : !supported(challenge.purpose())) || challenge.attempts() != 0U
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
            publicEmail && challenge.purpose()==account::VerificationPurpose::SignupEmail
            ? "SELECT i.id FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
              "WHERE i.id=$1 AND i.organization_id=$2 AND i.status IN (0,3) AND o.state=0 FOR UPDATE OF i FOR SHARE OF o"
            : "SELECT i.id FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
              "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND o.state=0 FOR UPDATE OF i FOR SHARE OF o",
            std::move(lockParams), remaining(deadline));
        if (locked.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK", {}, remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
        }
        if (!exactRow(locked, owner)) throw std::runtime_error{"Invalid challenge owner"};
        // Challenge IDs are generation tokens and must never be reused.
        // The PK also arbitrates cross-owner races on a not-yet-existing ID.
        Params generationParams{id};
        const auto existing = co_await connection.query(
            "SELECT id FROM openproof.account_verification_challenges WHERE id=$1 "
            "UNION ALL SELECT verification_id FROM openproof.pending_external_identity_reservations "
            "WHERE verification_id=$1 LIMIT 1",
            std::move(generationParams), remaining(deadline));
        if (!existing.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK", {}, remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::Conflict);
        }
        if (publicEmail) {
            Params publicParams{std::string{provider->value()},std::string{challenge.destination()},
                std::to_string(challenge.createdAt().time_since_epoch().count()),tenant,owner};
            const auto eligible=co_await connection.query(publicOwnerSql(challenge.purpose(),true),
                std::move(publicParams),remaining(deadline));
            if (!exactRow(eligible,owner)) {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::NotFound);
            }
        } else if (provider) {
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
                std::to_string(challenge.createdAt().time_since_epoch().count()), id};
            const auto reserved = co_await connection.query(
                "INSERT INTO openproof.pending_external_identity_reservations AS r "
                "(provider,external_subject,identity_id,expires_at_ms,verification_id) VALUES($1,$2,$3,$4,$6) "
                "ON CONFLICT(provider,external_subject) DO UPDATE SET identity_id=EXCLUDED.identity_id,"
                "expires_at_ms=EXCLUDED.expires_at_ms,verification_id=EXCLUDED.verification_id "
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
            "WITH obsolete AS (DELETE FROM openproof.account_verification_challenges "
            "WHERE identity_id=$1 AND purpose=$2 RETURNING id,identity_id) "
            "DELETE FROM openproof.pending_external_identity_reservations r USING obsolete c "
            "WHERE r.verification_id=c.id AND r.identity_id=c.identity_id",
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
    if (id.empty() || owner.empty() || (!supported(purpose) && !publicPurpose(purpose)))
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
            "WITH removed AS (DELETE FROM openproof.account_verification_challenges c "
            "USING openproof.identities i WHERE c.id=$1 AND c.identity_id=$2 "
            "AND c.purpose=$3 AND i.id=c.identity_id AND i.organization_id=$4 "
            "RETURNING c.id,c.identity_id), released AS ("
            "DELETE FROM openproof.pending_external_identity_reservations r USING removed c "
            "WHERE r.verification_id=c.id AND r.identity_id=c.identity_id RETURNING r.verification_id) "
            "SELECT id FROM removed", std::move(params), remaining(deadline));
        if (!removed.rows.empty() && !exactRow(removed, id.value()))
            throw std::runtime_error{"Invalid challenge compensation result"};
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native verification compensation is unavailable.");
    }
}

} // namespace openproof::storage::postgres
