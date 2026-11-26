#include "async_pool.hpp"

#include <chrono>
#include <algorithm>
#include <charconv>
#include <cstdint>
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

// Fresh native signup uses a reserved ID namespace. Never infer
// provenance from Deactivated status alone or the historical opi_ prefix.
// The 48h grace covers the maximum signup policy and retained resend proofs.
// All other known identity references must be absent before physical removal.
constexpr std::string_view abandonedSignupEligibility=
    " FROM openproof.identities i "
    "JOIN openproof.identity_profiles p ON p.identity_id=i.id "
    "JOIN openproof.password_credentials c ON c.identity_id=i.id "
    "WHERE i.organization_id=$1 AND i.kind=0 AND i.status=3 "
    "AND starts_with(i.id,'opi_signup_') AND length(i.id)=43 "
    "AND i.created_at_ms<=$2 AND p.created_at_ms=i.created_at_ms "
    "AND p.updated_at_ms=i.created_at_ms AND c.changed_at_ms=i.created_at_ms "
    "AND p.email IS NOT NULL AND NOT p.email_verified AND p.phone_number IS NULL "
    "AND NOT p.phone_number_verified AND p.preferred_username IS NULL "
    "AND p.locale IS NULL AND p.picture_url IS NULL AND p.avatar_source='auto' "
    "AND NOT EXISTS(SELECT 1 FROM openproof.pending_external_identity_reservations r "
    "WHERE r.identity_id=i.id AND (r.expires_at_ms>$3 OR r.verification_id IS NOT NULL "
    "OR r.external_subject<>p.email)) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.account_verification_challenges v "
    "WHERE v.identity_id=i.id AND (v.expires_at_ms>$3 OR v.purpose<>0 OR v.channel<>0 "
    "OR v.destination<>p.email)) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.external_identities e WHERE e.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.sessions s WHERE s.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.memberships m WHERE m.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.totp_credentials t WHERE t.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.recovery_codes r WHERE r.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.oauth_authorization_codes a WHERE a.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.oauth_token_families f WHERE f.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.oauth_consents o WHERE o.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.service_identities s WHERE s.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.oauth_device_authorizations d WHERE d.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.passkey_registration_ceremonies a WHERE a.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.passkey_credentials a WHERE a.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.scim_users s WHERE s.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.evidence e WHERE e.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.evidence_verification_challenges e WHERE e.identity_id=i.id) "
    "AND NOT EXISTS(SELECT 1 FROM openproof.audit_events a WHERE a.identity_id=i.id) ";

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

asio::awaitable<foundation::Result<std::size_t>>
CoroutineVerificationChallengeStore::reapExpiredSignupsAsync(foundation::Instant now)
{
    constexpr auto grace=std::chrono::hours{48};
    if (now.time_since_epoch()<grace) co_return std::size_t{0};
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const std::string tenant{m_impl->tenant.value()};
        const std::string cutoff=std::to_string((now-grace).time_since_epoch().count());
        const std::string observed=std::to_string(now.time_since_epoch().count());
        static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",{},remaining(deadline)));
        Params organizationParams{tenant};
        const auto organization=co_await connection.query(
            "SELECT id FROM openproof.organizations WHERE id=$1 AND state=0 FOR SHARE",
            std::move(organizationParams),remaining(deadline));
        if (!exactRow(organization,tenant)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
        }
        // Fail closed if a future migration adds an unfamiliar cascading
        // dependency. It must be explicitly considered by the reaper.
        const auto unknown=co_await connection.query(
            "SELECT 1 FROM pg_catalog.pg_constraint f "
            "WHERE f.contype='f' AND f.confrelid='openproof.identities'::regclass "
            "AND (f.confdeltype IN ('n','d') OR (f.confdeltype='c' AND f.conrelid NOT IN ("
            "'openproof.identity_profiles'::regclass,'openproof.password_credentials'::regclass,"
            "'openproof.totp_credentials'::regclass,'openproof.recovery_codes'::regclass,"
            "'openproof.account_verification_challenges'::regclass,'openproof.pending_external_identity_reservations'::regclass,"
            "'openproof.oauth_authorization_codes'::regclass,'openproof.oauth_token_families'::regclass,"
            "'openproof.oauth_consents'::regclass,'openproof.service_identities'::regclass,"
            "'openproof.passkey_registration_ceremonies'::regclass,'openproof.passkey_credentials'::regclass,"
            "'openproof.scim_users'::regclass,'openproof.evidence'::regclass,"
            "'openproof.evidence_verification_challenges'::regclass))) LIMIT 1",{},remaining(deadline));
        if (!unknown.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::Unavailable,"Unknown signup cleanup dependency.");
        }
        Params candidatesParams{tenant,cutoff,observed};
        const auto candidates=co_await connection.query(
            "SELECT i.id"+std::string{abandonedSignupEligibility}
            +"ORDER BY i.created_at_ms,i.id LIMIT 8 FOR UPDATE OF i,p,c SKIP LOCKED",
            std::move(candidatesParams),remaining(deadline));
        std::size_t removed=0;
        for (const auto& candidate:candidates.rows) {
            if (candidate.size()!=1U || !candidate.front())
                throw std::runtime_error{"Malformed abandoned signup candidate"};
            const std::string& owner=*candidate.front();
            // Lock the dependent reservation/proof rows as well; an old
            // compatibility writer may renew a reservation without i's lock.
            Params reservationParams{owner};
            static_cast<void>(co_await connection.query(
                "SELECT provider,external_subject FROM openproof.pending_external_identity_reservations "
                "WHERE identity_id=$1 FOR UPDATE",std::move(reservationParams),remaining(deadline)));
            Params proofParams{owner};
            static_cast<void>(co_await connection.query(
                "SELECT id FROM openproof.account_verification_challenges WHERE identity_id=$1 FOR UPDATE",
                std::move(proofParams),remaining(deadline)));
            // A new READ COMMITTED snapshot must recheck every condition
            // after locks. FK inserts cannot race an exclusive identity lock.
            Params deleteParams{tenant,cutoff,observed,owner};
            const auto deleted=co_await connection.query(
                "DELETE FROM openproof.identities target WHERE target.id=$4 AND target.id IN (SELECT i.id"
                +std::string{abandonedSignupEligibility}+"AND i.id=$4) RETURNING target.id",
                std::move(deleteParams),remaining(deadline));
            if (deleted.rows.empty()) continue;
            if (!exactRow(deleted,owner)) throw std::runtime_error{"Invalid abandoned signup deletion"};
            ++removed;
        }
        static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return removed;
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,"Native signup cleanup unavailable.");
    }
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
            "SELECT i.id,i.status,i.kind FROM openproof.identities i JOIN openproof.identity_profiles p ON p.identity_id=i.id "
            "WHERE i.organization_id=$1 AND p.email_verified=true AND lower(p.email)=lower($2) "
            "AND i.status NOT IN (4,5) ORDER BY i.status,i.id LIMIT 2 FOR UPDATE OF i",
            std::move(matchesParams),remaining(deadline));
        if (matches.rows.size()>1U) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            // Active candidates sort before blocked candidates. Two blocked
            // matches retain the legacy AlreadyExists response.
            const auto& first=matches.rows.front();
            if (first.size()!=3U || !first[1])
                throw std::runtime_error{"Invalid signup identity row"};
            co_return foundation::fail(*first[1]=="0"?foundation::ErrorCode::Conflict
                :foundation::ErrorCode::AlreadyExists);
        }
        const bool createdIdentity=matches.rows.empty();
        std::string owner;
        std::optional<std::string> expiredCredentialGeneration;
        if (!createdIdentity) {
            const auto& row=matches.rows.front();
            if (row.size()!=3U || !row[0] || !row[1] || !row[2])
                throw std::runtime_error{"Invalid signup identity row"};
            if (*row[1]!="0" || *row[2]!="0") {
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
                "FOR SHARE OF p",std::move(eligibilityParams),remaining(deadline));
            if (!exactRow(eligible,owner)) {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
            }
            // Lock an existing credential before deciding whether it is a
            // replaceable, expired pending enrollment. A password row on
            // its own is never evidence of pending signup.
            Params existingParams{owner};
            const auto existingCredential=co_await connection.query(
                "SELECT changed_at_ms FROM openproof.password_credentials WHERE identity_id=$1 FOR UPDATE",
                std::move(existingParams),remaining(deadline));
            if (!existingCredential.rows.empty()) {
                if (existingCredential.rows.size()!=1U || existingCredential.rows.front().size()!=1U
                    || !existingCredential.rows.front().front())
                    throw std::runtime_error{"Invalid existing signup credential"};
                const auto& generation=*existingCredential.rows.front().front();
                Params expiredParams{providerName,destination,owner,observed,generation};
                const auto expiredEnrollment=co_await connection.query(
                    "SELECT r.identity_id FROM openproof.pending_external_identity_reservations r "
                    "WHERE r.provider=$1 AND r.external_subject=$2 AND r.identity_id=$3 "
                    "AND r.verification_id IS NULL AND r.expires_at_ms<=$4 "
                    "AND $5::bigint>=0 AND $5::bigint<r.expires_at_ms "
                    "AND NOT EXISTS(SELECT 1 FROM openproof.pending_external_identity_reservations other "
                    "WHERE other.identity_id=$3 AND (other.provider<>$1 OR other.external_subject<>$2)) "
                    "AND NOT EXISTS(SELECT 1 FROM openproof.account_verification_challenges v "
                    "WHERE v.identity_id=$3 AND (v.purpose<>0 OR v.channel<>0 "
                    "OR v.destination<>$2 OR v.expires_at_ms>$4)) "
                    "AND NOT EXISTS(SELECT 1 FROM openproof.external_identities e "
                    "WHERE e.provider=$1 AND (e.external_subject=$2 OR e.identity_id=$3)) "
                    "FOR UPDATE OF r",std::move(expiredParams),remaining(deadline));
                if (!exactRow(expiredEnrollment,owner)) {
                    static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                    co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
                }
                expiredCredentialGeneration=generation;
            }
        } else {
            auto random=security::randomTokenBase64Url(24U);
            if (!random) {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(random.error());
            }
            owner="opi_signup_"+std::move(random).value();
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
        if (expiredCredentialGeneration) credentialParams.emplace_back(*expiredCredentialGeneration);
        // Only the exact locked expired enrollment may replace a hash.
        // A normal signup retains insert-only behavior.
        const auto credential=co_await connection.query(
            expiredCredentialGeneration
                ? "UPDATE openproof.password_credentials SET password_hash=$2,changed_at_ms=$3 "
                  "WHERE identity_id=$1 AND changed_at_ms=$4 RETURNING identity_id"
                : "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
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

asio::awaitable<foundation::Result<CoroutineVerificationChallengeStore::ActivatedSignup>>
CoroutineVerificationChallengeStore::activateSignupAsync(
    identity::provider::ProviderId provider,account::VerificationId id,
    account::VerificationDigest presented,foundation::Instant now,std::uint32_t maximumAttempts)
{
    if (provider.empty() || provider.value().size()>200U
        || id.empty() || id.value().size()>200U
        || provider.value().find('\0')!=std::string_view::npos
        || id.value().find('\0')!=std::string_view::npos
        || maximumAttempts==0U || maximumAttempts>20U || now.time_since_epoch().count()<0)
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    const std::string generation{id.value()},providerName{provider.value()},tenant{m_impl->tenant.value()};
    const std::string observed=std::to_string(now.time_since_epoch().count());
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",{},remaining(deadline)));
        // Lock order matches challenge replacement: owner before proof row.
        // The initial read is only a locator, never authorization.
        Params locator{generation,tenant};
        const auto located=co_await connection.query(
            "SELECT c.identity_id FROM openproof.account_verification_challenges c "
            "JOIN openproof.identities i ON i.id=c.identity_id "
            "WHERE c.id=$1 AND c.purpose=0 AND c.channel=0 AND i.organization_id=$2",
            std::move(locator),remaining(deadline));
        if (located.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        if (located.rows.size()!=1U || located.rows.front().size()!=1U || !located.rows.front().front())
            throw std::runtime_error{"Invalid signup proof locator"};
        const std::string owner=*located.rows.front().front();
        Params lockParams{owner,tenant};
        const auto locked=co_await connection.query(
            "SELECT i.id FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.kind=0 AND i.status IN (0,3) AND o.state=0 "
            "FOR UPDATE OF i FOR SHARE OF o",std::move(lockParams),remaining(deadline));
        if (!exactRow(locked,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        Params proofParams{generation,owner};
        const auto proof=co_await connection.query(
            "SELECT destination,encode(secret_digest,'hex'),attempts,created_at_ms,expires_at_ms "
            "FROM openproof.account_verification_challenges "
            "WHERE id=$1 AND identity_id=$2 AND purpose=0 AND channel=0 FOR UPDATE",
            std::move(proofParams),remaining(deadline));
        if (proof.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        if (proof.rows.size()!=1U || proof.rows.front().size()!=5U
            || std::ranges::any_of(proof.rows.front(),[](const auto& v){return !v.has_value();}))
            throw std::runtime_error{"Malformed signup proof"};
        const auto& row=proof.rows.front();
        const auto parse=[](const std::string& text) {
            std::int64_t value{};
            const auto result=std::from_chars(text.data(),text.data()+text.size(),value);
            if (result.ec!=std::errc{} || result.ptr!=text.data()+text.size() || value<0)
                throw std::runtime_error{"Malformed signup proof integer"};
            return value;
        };
        const auto attempts=parse(*row[2]),created=parse(*row[3]),expires=parse(*row[4]);
        const auto time=now.time_since_epoch().count();
        auto digest=foundation::fromHex(*row[1]);
        if (!digest || digest->size()!=32U || expires<=created)
            throw std::runtime_error{"Malformed signup proof digest/window"};
        const std::string destination=*row[0];
        const auto normalized=account::VerificationPreparation::normalizePublicEmail(destination);
        if (!normalized || normalized.value()!=destination || destination.find('\0')!=std::string::npos
            || created>time) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        const bool expired=expires<=time || attempts>=maximumAttempts;
        const bool matches=security::constantTimeEquals(digest.value(),presented.bytes());
        if (expired || !matches) {
            Params mismatch{generation,owner};
            if (expired || attempts+1>=maximumAttempts) {
                static_cast<void>(co_await connection.query(
                    "DELETE FROM openproof.account_verification_challenges WHERE id=$1 AND identity_id=$2 AND purpose=0",
                    std::move(mismatch),remaining(deadline)));
            } else {
                static_cast<void>(co_await connection.query(
                    "UPDATE openproof.account_verification_challenges SET attempts=attempts+1 "
                    "WHERE id=$1 AND identity_id=$2 AND purpose=0",
                    std::move(mismatch),remaining(deadline)));
            }
            static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        // A verified secret does not override a revoked reservation, changed
        // email, existing local link or removed password credential.
        Params eligibleParams{providerName,destination,owner,observed};
        const auto eligible=co_await connection.query(
            "SELECT r.identity_id FROM openproof.pending_external_identity_reservations r "
            "JOIN openproof.identity_profiles p ON p.identity_id=r.identity_id "
            "JOIN openproof.identities i ON i.id=r.identity_id "
            "JOIN openproof.password_credentials c ON c.identity_id=r.identity_id "
            "WHERE r.provider=$1 AND r.external_subject=$2 AND r.identity_id=$3 "
            "AND r.expires_at_ms>$4 AND r.verification_id IS NULL "
            "AND lower(p.email)=lower($2) AND (i.status=3 OR (i.status=0 AND p.email_verified)) "
            "AND NOT EXISTS(SELECT 1 FROM openproof.external_identities e "
            "WHERE e.provider=$1 AND (e.external_subject=$2 OR e.identity_id=$3)) "
            "FOR UPDATE OF r,p FOR SHARE OF c",
            std::move(eligibleParams),remaining(deadline));
        if (!exactRow(eligible,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        Params linkParams{providerName,destination,owner,observed};
        const auto linked=co_await connection.query(
            "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
            "VALUES($1,$2,$3,$4) ON CONFLICT(provider,external_subject) DO NOTHING RETURNING identity_id",
            std::move(linkParams),remaining(deadline));
        if (!exactRow(linked,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        Params profileParams{owner,destination,observed};
        const auto verified=co_await connection.query(
            "UPDATE openproof.identity_profiles SET email=$2,email_verified=true,updated_at_ms=GREATEST(updated_at_ms,$3) "
            "WHERE identity_id=$1 AND lower(email)=lower($2) RETURNING identity_id",
            std::move(profileParams),remaining(deadline));
        if (!exactRow(verified,owner)) throw std::runtime_error{"Signup profile changed"};
        Params activateParams{owner,tenant};
        const auto activated=co_await connection.query(
            "UPDATE openproof.identities SET status=0 WHERE id=$1 AND organization_id=$2 "
            "AND status IN (0,3) RETURNING id",std::move(activateParams),remaining(deadline));
        if (!exactRow(activated,owner)) throw std::runtime_error{"Signup owner changed"};
        Params consumeParams{generation,owner};
        const auto consumed=co_await connection.query(
            "DELETE FROM openproof.account_verification_challenges WHERE id=$1 AND identity_id=$2 AND purpose=0 RETURNING id",
            std::move(consumeParams),remaining(deadline));
        if (!exactRow(consumed,generation)) throw std::runtime_error{"Signup proof changed"};
        Params releaseParams{providerName,destination,owner};
        const auto released=co_await connection.query(
            "DELETE FROM openproof.pending_external_identity_reservations WHERE provider=$1 "
            "AND external_subject=$2 AND identity_id=$3 AND verification_id IS NULL RETURNING identity_id",
            std::move(releaseParams),remaining(deadline));
        if (!exactRow(released,owner)) throw std::runtime_error{"Signup reservation changed"};
        static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return ActivatedSignup{core::ExternalIdentityRef{std::move(provider),
            identity::provider::ExternalSubject{destination}},core::IdentityId{owner}};
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native signup activation is unavailable.");
    }
}

asio::awaitable<foundation::Status>
CoroutineVerificationChallengeStore::resetPasswordAsync(
    identity::provider::ProviderId provider,account::VerificationId id,
    account::VerificationDigest presented,credentials::PasswordHash replacement,
    foundation::Instant now,std::uint32_t maximumAttempts)
{
    if (replacement.encoded().empty() || replacement.encoded().size()>4096U)
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    if (provider.empty() || provider.value().size()>200U
        || id.empty() || id.value().size()>200U
        || provider.value().find('\0')!=std::string_view::npos
        || id.value().find('\0')!=std::string_view::npos
        || maximumAttempts==0U || maximumAttempts>20U || now.time_since_epoch().count()<0)
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    const std::string generation{id.value()},providerName{provider.value()},tenant{m_impl->tenant.value()};
    const std::string observed=std::to_string(now.time_since_epoch().count());
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",{},remaining(deadline)));
        // Lock order matches challenge replacement: owner before proof row.
        // The initial read is only a locator, never authorization.
        Params locator{generation,tenant};
        const auto located=co_await connection.query(
            "SELECT c.identity_id FROM openproof.account_verification_challenges c "
            "JOIN openproof.identities i ON i.id=c.identity_id "
            "WHERE c.id=$1 AND c.purpose=3 AND c.channel=0 AND i.organization_id=$2",
            std::move(locator),remaining(deadline));
        if (located.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        if (located.rows.size()!=1U || located.rows.front().size()!=1U || !located.rows.front().front())
            throw std::runtime_error{"Invalid password reset proof locator"};
        const std::string owner=*located.rows.front().front();
        Params lockParams{owner,tenant};
        const auto locked=co_await connection.query(
            "SELECT i.id FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.kind=0 AND i.status=0 AND o.state=0 "
            "FOR UPDATE OF i FOR SHARE OF o",std::move(lockParams),remaining(deadline));
        if (!exactRow(locked,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        Params proofParams{generation,owner};
        const auto proof=co_await connection.query(
            "SELECT destination,encode(secret_digest,'hex'),attempts,created_at_ms,expires_at_ms "
            "FROM openproof.account_verification_challenges "
            "WHERE id=$1 AND identity_id=$2 AND purpose=3 AND channel=0 FOR UPDATE",
            std::move(proofParams),remaining(deadline));
        if (proof.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        if (proof.rows.size()!=1U || proof.rows.front().size()!=5U
            || std::ranges::any_of(proof.rows.front(),[](const auto& v){return !v.has_value();}))
            throw std::runtime_error{"Malformed password reset proof"};
        const auto& row=proof.rows.front();
        const auto parse=[](const std::string& text) {
            std::int64_t value{};
            const auto result=std::from_chars(text.data(),text.data()+text.size(),value);
            if (result.ec!=std::errc{} || result.ptr!=text.data()+text.size() || value<0)
                throw std::runtime_error{"Malformed password reset proof integer"};
            return value;
        };
        const auto attempts=parse(*row[2]),created=parse(*row[3]),expires=parse(*row[4]);
        const auto time=now.time_since_epoch().count();
        auto digest=foundation::fromHex(*row[1]);
        if (!digest || digest->size()!=32U || expires<=created)
            throw std::runtime_error{"Malformed password reset proof digest/window"};
        const std::string destination=*row[0];
        const auto normalized=account::VerificationPreparation::normalizePublicEmail(destination);
        if (!normalized || normalized.value()!=destination || destination.find('\0')!=std::string::npos
            || created>time) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        const bool expired=expires<=time || attempts>=maximumAttempts;
        const bool matches=security::constantTimeEquals(digest.value(),presented.bytes());
        if (expired || !matches) {
            Params mismatch{generation,owner};
            if (expired || attempts+1>=maximumAttempts) {
                static_cast<void>(co_await connection.query(
                    "DELETE FROM openproof.account_verification_challenges WHERE id=$1 AND identity_id=$2 AND purpose=3",
                    std::move(mismatch),remaining(deadline)));
            } else {
                static_cast<void>(co_await connection.query(
                    "UPDATE openproof.account_verification_challenges SET attempts=attempts+1 "
                    "WHERE id=$1 AND identity_id=$2 AND purpose=3",
                    std::move(mismatch),remaining(deadline)));
            }
            static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        // The verified email subject must still be the exact owner's
        // local link. A reset issued before a subsequent password change
        // is stale, even if its own expiry has not passed.
        Params eligibilityParams{providerName,destination,owner,std::to_string(created),observed};
        const auto eligible=co_await connection.query(
            "SELECT p.identity_id FROM openproof.password_credentials p "
            "JOIN openproof.external_identities e ON e.identity_id=p.identity_id "
            "WHERE e.provider=$1 AND e.external_subject=$2 AND p.identity_id=$3 "
            "AND p.changed_at_ms<=$4 AND p.changed_at_ms<=$5 "
            "FOR UPDATE OF p FOR SHARE OF e",
            std::move(eligibilityParams),remaining(deadline));
        if (!exactRow(eligible,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        Params credentialParams{owner,std::string{replacement.encoded()},observed,std::to_string(created)};
        const auto changed=co_await connection.query(
            "UPDATE openproof.password_credentials SET password_hash=$2,changed_at_ms=GREATEST(changed_at_ms+1,$3::bigint) "
            "WHERE identity_id=$1 AND changed_at_ms<=$4 RETURNING identity_id",
            std::move(credentialParams),remaining(deadline));
        if (!exactRow(changed,owner)) throw std::runtime_error{"Password reset generation changed"};
        // Match legacy revokeAll semantics, but in the same transaction.
        // No unbounded RETURNING row materialization.
        Params revokeParams{owner,observed};
        static_cast<void>(co_await connection.query(
            "UPDATE openproof.sessions SET state=1,revoked_at_ms=$2 WHERE identity_id=$1 AND state=0",
            std::move(revokeParams),remaining(deadline)));
        Params consumeParams{generation,owner};
        const auto consumed=co_await connection.query(
            "DELETE FROM openproof.account_verification_challenges "
            "WHERE id=$1 AND identity_id=$2 AND purpose=3 RETURNING id",
            std::move(consumeParams),remaining(deadline));
        if (!exactRow(consumed,generation)) throw std::runtime_error{"Password reset proof changed"};
        static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native password reset persistence is unavailable.");
    }
}

asio::awaitable<foundation::Status> CoroutineVerificationChallengeStore::verifyPhoneAsync(
    identity::provider::ProviderId provider,core::IdentityId expectedOwner,
    account::VerificationId id,account::VerificationDigest presented,
    foundation::Instant now,std::uint32_t maximumAttempts)
{
    const auto valid=[](std::string_view value) {
        return !value.empty() && value.size()<=200U
            && value.find('\0')==std::string_view::npos;
    };
    if (!valid(provider.value()) || !valid(expectedOwner.value()) || !valid(id.value())
        || maximumAttempts==0U || maximumAttempts>20U || now.time_since_epoch().count()<0)
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    const std::string generation{id.value()},providerName{provider.value()},tenant{m_impl->tenant.value()};
    const std::string owner{expectedOwner.value()};
    const std::string observed=std::to_string(now.time_since_epoch().count());
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",{},remaining(deadline)));
        Params lockParams{owner,tenant};
        const auto locked=co_await connection.query(
            "SELECT i.id FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND o.state=0 "
            "FOR UPDATE OF i FOR SHARE OF o",std::move(lockParams),remaining(deadline));
        if (!exactRow(locked,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        // Wrong-owner/purpose proofs cannot consume another owner's attempts.
        Params proofParams{generation,owner};
        const auto proof=co_await connection.query(
            "SELECT destination,encode(secret_digest,'hex'),attempts,created_at_ms,expires_at_ms "
            "FROM openproof.account_verification_challenges "
            "WHERE id=$1 AND identity_id=$2 AND purpose=2 AND channel=1 FOR UPDATE",
            std::move(proofParams),remaining(deadline));
        if (proof.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        if (proof.rows.size()!=1U || proof.rows.front().size()!=5U
            || std::ranges::any_of(proof.rows.front(),[](const auto& value){return !value.has_value();}))
            throw std::runtime_error{"Malformed phone verification proof"};
        const auto& row=proof.rows.front();
        const auto parse=[](const std::string& text) {
            std::int64_t value{};
            const auto result=std::from_chars(text.data(),text.data()+text.size(),value);
            if (result.ec!=std::errc{} || result.ptr!=text.data()+text.size() || value<0)
                throw std::runtime_error{"Malformed phone verification integer"};
            return value;
        };
        const auto attempts=parse(*row[2]),created=parse(*row[3]),expires=parse(*row[4]);
        const auto time=now.time_since_epoch().count();
        const auto digest=foundation::fromHex(*row[1]);
        const std::string destination=*row[0];
        if (!digest || digest->size()!=32U || expires<=created)
            throw std::runtime_error{"Malformed phone verification digest/window"};
        if (destination.size()<8U || destination.size()>16U || destination.front()!='+'
            || !std::ranges::all_of(std::string_view{destination}.substr(1U),[](char ch){return ch>='0' && ch<='9';})
            || created>time) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        const bool expired=expires<=time || attempts>=maximumAttempts;
        const bool matches=security::constantTimeEquals(digest.value(),presented.bytes());
        if (expired || !matches) {
            Params mismatch{generation,owner};
            if (expired || attempts+1>=maximumAttempts) {
                // Release only this generation's reservation, not a renewal.
                static_cast<void>(co_await connection.query(
                    "WITH obsolete AS (DELETE FROM openproof.account_verification_challenges "
                    "WHERE id=$1 AND identity_id=$2 AND purpose=2 RETURNING id,identity_id) "
                    "DELETE FROM openproof.pending_external_identity_reservations r USING obsolete c "
                    "WHERE r.verification_id=c.id AND r.identity_id=c.identity_id",
                    std::move(mismatch),remaining(deadline)));
            } else {
                static_cast<void>(co_await connection.query(
                    "UPDATE openproof.account_verification_challenges SET attempts=attempts+1 "
                    "WHERE id=$1 AND identity_id=$2 AND purpose=2",
                    std::move(mismatch),remaining(deadline)));
            }
            static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        Params reservationParams{providerName,destination,owner,generation,observed};
        const auto reservation=co_await connection.query(
            "SELECT r.identity_id FROM openproof.pending_external_identity_reservations r "
            "WHERE r.provider=$1 AND r.external_subject=$2 AND r.identity_id=$3 "
            "AND r.verification_id=$4 AND r.expires_at_ms>$5 FOR UPDATE OF r",
            std::move(reservationParams),remaining(deadline));
        if (!exactRow(reservation,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        // Insert only, never reassign an existing subject. A previously
        // verified link to this same owner is idempotent; retain its metadata.
        Params attachParams{providerName,destination,owner,observed};
        static_cast<void>(co_await connection.query(
            "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
            "VALUES($1,$2,$3,$4) ON CONFLICT(provider,external_subject) DO NOTHING",
            std::move(attachParams),remaining(deadline)));
        Params linkParams{providerName,destination,owner};
        const auto linked=co_await connection.query(
            "SELECT identity_id FROM openproof.external_identities WHERE provider=$1 "
            "AND external_subject=$2 AND identity_id=$3 FOR SHARE",
            std::move(linkParams),remaining(deadline));
        if (!exactRow(linked,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
        }
        Params profileParams{owner,destination,observed};
        const auto updated=co_await connection.query(
            "UPDATE openproof.identity_profiles SET phone_number=$2,phone_number_verified=true,"
            "updated_at_ms=GREATEST(updated_at_ms,$3) WHERE identity_id=$1 RETURNING identity_id",
            std::move(profileParams),remaining(deadline));
        if (!exactRow(updated,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::NotFound);
        }
        Params consumeParams{generation,owner};
        const auto consumed=co_await connection.query(
            "DELETE FROM openproof.account_verification_challenges WHERE id=$1 AND identity_id=$2 "
            "AND purpose=2 RETURNING id",std::move(consumeParams),remaining(deadline));
        if (!exactRow(consumed,generation)) throw std::runtime_error{"Phone proof changed"};
        Params releaseParams{providerName,destination,owner,generation};
        const auto released=co_await connection.query(
            "DELETE FROM openproof.pending_external_identity_reservations WHERE provider=$1 AND external_subject=$2 "
            "AND identity_id=$3 AND verification_id=$4 RETURNING identity_id",
            std::move(releaseParams),remaining(deadline));
        if (!exactRow(released,owner)) throw std::runtime_error{"Phone reservation changed"};
        static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,"Native phone verification unavailable.");
    }
}

asio::awaitable<foundation::Status> CoroutineVerificationChallengeStore::changeEmailAsync(
    identity::provider::ProviderId provider,core::IdentityId expectedOwner,
    account::VerificationId id,account::VerificationDigest presented,
    std::optional<credentials::PasswordHash> enrollment,
    foundation::Instant now,std::uint32_t maximumAttempts)
{
    const auto valid=[](std::string_view value) {
        return !value.empty() && value.size()<=200U
            && value.find('\0')==std::string_view::npos;
    };
    if (!valid(provider.value()) || !valid(expectedOwner.value()) || !valid(id.value())
        || maximumAttempts==0U || maximumAttempts>20U || now.time_since_epoch().count()<0)
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    const std::string generation{id.value()},providerName{provider.value()},tenant{m_impl->tenant.value()};
    const std::string owner{expectedOwner.value()};
    const std::string observed=std::to_string(now.time_since_epoch().count());
    try {
        const auto deadline=Clock::now()+m_impl->queryTimeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",{},remaining(deadline)));
        Params lockParams{owner,tenant};
        const auto locked=co_await connection.query(
            "SELECT i.id FROM openproof.identities i JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND o.state=0 "
            "FOR UPDATE OF i FOR SHARE OF o",std::move(lockParams),remaining(deadline));
        if (!exactRow(locked,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        // Wrong-owner/purpose proofs cannot consume another owner's attempts.
        Params proofParams{generation,owner};
        const auto proof=co_await connection.query(
            "SELECT destination,encode(secret_digest,'hex'),attempts,created_at_ms,expires_at_ms "
            "FROM openproof.account_verification_challenges "
            "WHERE id=$1 AND identity_id=$2 AND purpose=1 AND channel=0 FOR UPDATE",
            std::move(proofParams),remaining(deadline));
        if (proof.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        if (proof.rows.size()!=1U || proof.rows.front().size()!=5U
            || std::ranges::any_of(proof.rows.front(),[](const auto& value){return !value.has_value();}))
            throw std::runtime_error{"Malformed email change proof"};
        const auto& row=proof.rows.front();
        const auto parse=[](const std::string& text) {
            std::int64_t value{};
            const auto result=std::from_chars(text.data(),text.data()+text.size(),value);
            if (result.ec!=std::errc{} || result.ptr!=text.data()+text.size() || value<0)
                throw std::runtime_error{"Malformed email change integer"};
            return value;
        };
        const auto attempts=parse(*row[2]),created=parse(*row[3]),expires=parse(*row[4]);
        const auto time=now.time_since_epoch().count();
        const auto digest=foundation::fromHex(*row[1]);
        const std::string destination=*row[0];
        if (!digest || digest->size()!=32U || expires<=created)
            throw std::runtime_error{"Malformed email change digest/window"};
        const auto normalized=account::VerificationPreparation::normalizePublicEmail(destination);
        if (!normalized || normalized.value()!=destination || destination.find('\0')!=std::string::npos
            || created>time) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        const bool expired=expires<=time || attempts>=maximumAttempts;
        const bool matches=security::constantTimeEquals(digest.value(),presented.bytes());
        if (expired || !matches) {
            Params mismatch{generation,owner};
            if (expired || attempts+1>=maximumAttempts) {
                // Release only this generation's reservation, not a renewal.
                static_cast<void>(co_await connection.query(
                    "WITH obsolete AS (DELETE FROM openproof.account_verification_challenges "
                    "WHERE id=$1 AND identity_id=$2 AND purpose=1 RETURNING id,identity_id) "
                    "DELETE FROM openproof.pending_external_identity_reservations r USING obsolete c "
                    "WHERE r.verification_id=c.id AND r.identity_id=c.identity_id",
                    std::move(mismatch),remaining(deadline)));
            } else {
                static_cast<void>(co_await connection.query(
                    "UPDATE openproof.account_verification_challenges SET attempts=attempts+1 "
                    "WHERE id=$1 AND identity_id=$2 AND purpose=1",
                    std::move(mismatch),remaining(deadline)));
            }
            static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        Params reservationParams{providerName,destination,owner,generation,observed};
        const auto reservation=co_await connection.query(
            "SELECT r.identity_id FROM openproof.pending_external_identity_reservations r "
            "WHERE r.provider=$1 AND r.external_subject=$2 AND r.identity_id=$3 "
            "AND r.verification_id=$4 AND r.expires_at_ms>$5 FOR UPDATE OF r",
            std::move(reservationParams),remaining(deadline));
        if (!exactRow(reservation,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        }
        // Passwords belong to the canonical owner, not the email alias.
        // Reject ambiguous local links instead of choosing one arbitrarily.
        Params localParams{providerName,owner};
        const auto local=co_await connection.query(
            "SELECT external_subject FROM openproof.external_identities "
            "WHERE provider=$1 AND identity_id=$2 ORDER BY external_subject LIMIT 2 FOR UPDATE",
            std::move(localParams),remaining(deadline));
        if (local.rows.size()>1U) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::Conflict);
        }
        std::optional<std::string> previous;
        if (!local.rows.empty()) {
            if (local.rows.front().size()!=1U || !local.rows.front().front())
                throw std::runtime_error{"Malformed local subject"};
            previous=*local.rows.front().front();
        }
        if (previous || enrollment) {
            // First enrollment is insert-only. Existing local accounts
            // retain their hash even when a password was supplied.
            if (!previous) {
                if (enrollment->encoded().empty() || enrollment->encoded().size()>4096U)
                    throw std::runtime_error{"Invalid enrollment hash"};
                Params enrollParams{owner,std::string{enrollment->encoded()},observed};
                const auto enrolled=co_await connection.query(
                    "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) "
                    "VALUES($1,$2,$3) ON CONFLICT(identity_id) DO NOTHING RETURNING identity_id",
                    std::move(enrollParams),remaining(deadline));
                if (!exactRow(enrolled,owner)) {
                    static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                    co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
                }
            } else {
                Params credentialParams{owner};
                const auto credential=co_await connection.query(
                    "SELECT identity_id FROM openproof.password_credentials WHERE identity_id=$1 FOR UPDATE",
                    std::move(credentialParams),remaining(deadline));
                if (!exactRow(credential,owner)) {
                    static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                    co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
                }
            }
            Params attachParams{providerName,destination,owner,observed};
            static_cast<void>(co_await connection.query(
                "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) "
                "VALUES($1,$2,$3,$4) ON CONFLICT(provider,external_subject) DO NOTHING",
                std::move(attachParams),remaining(deadline)));
            Params linkParams{providerName,destination,owner};
            const auto linked=co_await connection.query(
                "SELECT identity_id FROM openproof.external_identities WHERE provider=$1 "
                "AND external_subject=$2 AND identity_id=$3 FOR SHARE",
                std::move(linkParams),remaining(deadline));
            if (!exactRow(linked,owner)) {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
            }
            if (previous && *previous!=destination) {
                Params detachParams{providerName,*previous,owner};
                const auto detached=co_await connection.query(
                    "DELETE FROM openproof.external_identities WHERE provider=$1 AND external_subject=$2 "
                    "AND identity_id=$3 RETURNING identity_id",std::move(detachParams),remaining(deadline));
                if (!exactRow(detached,owner)) throw std::runtime_error{"Local subject changed"};
                // Fence old local login proofs even if the alias is later
                // changed back (ABA). Keep the existing hash unchanged.
                Params advanceParams{owner,observed};
                const auto advanced=co_await connection.query(
                    "UPDATE openproof.password_credentials SET changed_at_ms=GREATEST(changed_at_ms+1,$2::bigint) "
                    "WHERE identity_id=$1 RETURNING identity_id",std::move(advanceParams),remaining(deadline));
                if (!exactRow(advanced,owner)) throw std::runtime_error{"Local credential disappeared"};
            }
        } else {
            // Profile-only verification must also reject a subject now
            // owned by somebody else, without creating a local credential.
            Params subjectParams{providerName,destination};
            const auto occupied=co_await connection.query(
                "SELECT identity_id FROM openproof.external_identities WHERE provider=$1 AND external_subject=$2 FOR SHARE",
                std::move(subjectParams),remaining(deadline));
            if (!occupied.rows.empty()) {
                static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
                co_return foundation::fail(foundation::ErrorCode::AlreadyExists);
            }
        }
        Params profileParams{owner,destination,observed};
        const auto updated=co_await connection.query(
            "UPDATE openproof.identity_profiles SET email=$2,email_verified=true,"
            "updated_at_ms=GREATEST(updated_at_ms,$3) WHERE identity_id=$1 RETURNING identity_id",
            std::move(profileParams),remaining(deadline));
        if (!exactRow(updated,owner)) {
            static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::NotFound);
        }
        Params consumeParams{generation,owner};
        const auto consumed=co_await connection.query(
            "DELETE FROM openproof.account_verification_challenges WHERE id=$1 AND identity_id=$2 "
            "AND purpose=1 RETURNING id",std::move(consumeParams),remaining(deadline));
        if (!exactRow(consumed,generation)) throw std::runtime_error{"Email proof changed"};
        Params releaseParams{providerName,destination,owner,generation};
        const auto released=co_await connection.query(
            "DELETE FROM openproof.pending_external_identity_reservations WHERE provider=$1 AND external_subject=$2 "
            "AND identity_id=$3 AND verification_id=$4 RETURNING identity_id",
            std::move(releaseParams),remaining(deadline));
        if (!exactRow(released,owner)) throw std::runtime_error{"Email reservation changed"};
        static_cast<void>(co_await connection.query("COMMIT",{},remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,"Native email change unavailable.");
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
                "WHERE (r.identity_id=EXCLUDED.identity_id AND r.verification_id IS NOT NULL) OR r.expires_at_ms<=$5 "
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
