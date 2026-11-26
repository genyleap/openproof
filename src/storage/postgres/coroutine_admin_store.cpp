#include "async_pool.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>
#include "bounded_password_executor.hpp"
#include "coroutine_admin_store.hpp"

import openproof.credentials;
import openproof.organization;

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace adm = administration;
namespace core = identity::core;
namespace idp = identity::provider;
namespace {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
using Params = std::vector<std::optional<std::string>>;
template<class... T> Params params(T&&... values) {
    Params result;
    result.reserve(sizeof...(T));
    (result.emplace_back(std::forward<T>(values)), ...);
    return result;
}
foundation::Duration remaining(Deadline deadline) {
    const auto budget=std::chrono::duration_cast<foundation::Duration>(deadline-Clock::now());
    if (budget<=foundation::Duration::zero()) throw std::runtime_error{"Administration deadline expired"};
    return budget;
}
std::string single(const async_detail::QueryRows& result) {
    if (result.rows.size()!=1U || result.rows.front().size()!=1U || !result.rows.front().front())
        throw std::runtime_error{"Malformed administration result"};
    return *result.rows.front().front();
}
std::uint64_t number(const std::string& value) {
    std::uint64_t parsed{};
    const auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),parsed);
    if (error!=std::errc{} || end!=value.data()+value.size())
        throw std::runtime_error{"Malformed administration number"};
    return parsed;
}
asio::awaitable<foundation::Status> rollback(async_detail::AsyncConnection& connection,
    Deadline deadline, foundation::ErrorCode code) {
    static_cast<void>(co_await connection.query("ROLLBACK",{},remaining(deadline)));
    co_return foundation::fail(code);
}
// The caller owns the transaction; this helper acquires the shared audit
// writer lock. No success is returned until the head, seal and outbox agree.
asio::awaitable<foundation::Status> appendRecords(async_detail::AsyncConnection& connection,
    Deadline deadline, const audit::AuditEvent& event, const audit::AuditKey& key,
    std::string securityType, std::string actor) {
    static_cast<void>(co_await connection.query(
        "SELECT pg_advisory_xact_lock(7299730475761673314)",{},remaining(deadline)));
    const auto head=co_await connection.query(
        "SELECT encode(event_hash,'hex') FROM openproof.audit_events ORDER BY sequence DESC LIMIT 1",
        {},remaining(deadline));
    std::optional<security::Sha256Digest> previousHash;
    std::string previousHex;
    if (!head.rows.empty()) {
        previousHex=single(head);
        auto decoded=foundation::fromHex(previousHex);
        if (!decoded || decoded->size()!=security::Sha256Digest{}.size())
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        security::Sha256Digest digest{};
        std::copy(decoded->begin(),decoded->end(),digest.begin());
        previousHash=digest;
    }
    foundation::JsonObjectWriter detail;
    for (const auto& [name,value]:event.fields()) detail.add(name,value);
    const std::string eventId{event.id().value()};
    const std::string tenant{event.organization()->value()};
    const std::string target{event.identity()->value()};
    const auto occurred=std::to_string(event.occurredAt().time_since_epoch().count());
    auto arguments=params(eventId,occurred,std::string{event.correlation().value()},tenant,target,
        std::string{event.category()},std::string{event.action()},std::string{event.outcome()},
        detail.build(),previousHex,std::string(64U,'0'));
    const auto inserted=co_await connection.query(
        "INSERT INTO openproof.audit_events "
        "(event_id,occurred_at_ms,correlation_id,organization_id,identity_id,category,action,outcome,detail,previous_hash,event_hash) "
        "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,CASE WHEN $10='' THEN NULL ELSE decode($10,'hex') END,decode($11,'hex')) RETURNING sequence",
        std::move(arguments),remaining(deadline));
    const auto sequence=number(single(inserted));
    if (sequence==0U) co_return foundation::fail(foundation::ErrorCode::Unavailable);
    auto hash=audit::computeAuditRecordHash(event,sequence,previousHash,key);
    if (!hash) co_return foundation::fail(hash.error());
    auto seal=params(std::to_string(sequence),foundation::toHex(hash.value()));
    const auto sealed=co_await connection.query(
        "UPDATE openproof.audit_events SET event_hash=decode($2,'hex') WHERE sequence=$1 RETURNING sequence",
        std::move(seal),remaining(deadline));
    if (number(single(sealed))!=sequence) co_return foundation::fail(foundation::ErrorCode::Unavailable);
    foundation::JsonObjectWriter payload;
    payload.add("event_id",eventId).add("type",securityType).add("organization_id",tenant)
        .add("identity_id",target).add("actor_identity_id",actor).add("severity","critical");
    auto outboxArgs=params(eventId,occurred,payload.build());
    const auto outbox=co_await connection.query(
        "INSERT INTO openproof.security_event_outbox (event_id,occurred_at_ms,payload) VALUES($1,$2,$3::jsonb) RETURNING event_id",
        std::move(outboxArgs),remaining(deadline));
    if (single(outbox)!=eventId) co_return foundation::fail(foundation::ErrorCode::Unavailable);
    co_return foundation::ok();
}
}
namespace {
using E=foundation::ErrorCode;
asio::awaitable<foundation::Status> initializeAdministratorAsync(
    foundation::SecretString dsn,const adm::InitialAdministrator& administrator,
    const credentials::PasswordHasher& hasher,const security::AeadKey& totpKey,
    std::uint32_t keyVersion,const idp::ProviderId& provider,const audit::AuditKey& auditKey)
{
    const auto& tenant=administrator.organization();
    const auto& identityValue=administrator.identity();
    const auto& link=administrator.link();
    const auto& membership=administrator.membership();
    if (keyVersion==0U || provider.empty() || !tenant.isUsable() || !identityValue.canAuthenticate()
        || identityValue.kind()!=core::SubjectKind::Human || link.state()!=core::LinkState::Linked
        || link.external().providerId()!=provider || link.owner()!=identityValue.id()
        || membership.organization()!=tenant.id() || membership.identity()!=identityValue.id()
        || membership.state()!=organization::MembershipState::Active || !membership.hasRole(organization::Role{"owner"}))
        co_return foundation::fail(E::FailedPrecondition);
    auto passwordHash=hasher.hash(administrator.password());
    if (!passwordHash) co_return foundation::fail(passwordHash.error());
    const std::string identityId{identityValue.id().value()},tenantId{tenant.id().value()};
    auto encrypted=security::sealAes256Gcm(totpKey,administrator.totp().bytes(),"openproof/totp/v1:"+identityId);
    if (!encrypted) co_return foundation::fail(encrypted.error());
    auto randomId=security::randomTokenBase64Url(24U);
    if (!randomId) co_return foundation::fail(randomId.error());
    const std::string eventId="bootstrap-"+randomId.value();
    auto event=audit::AuditEvent::create(audit::AuditEventId{eventId},identityValue.createdAt(),
        foundation::CorrelationId{eventId},std::optional<core::OrganizationId>{tenant.id()},
        std::optional<core::IdentityId>{identityValue.id()},"administration","bootstrap.initial-owner",
        "success",audit::AuditFields{{"provider",std::string{provider.value()}},{"role","owner"}});
    if (!event) co_return foundation::fail(event.error());
    try {
        const auto deadline=Clock::now()+std::chrono::minutes{5};
        auto connection=co_await async_detail::AsyncConnection::connect(std::string{dsn.expose()},remaining(deadline));
        const auto execute=[&](std::string sql,Params args){
            return connection->query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL SERIALIZABLE",{}));
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673313)",{}));
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673315)",{}));
        if (number(single(co_await execute("SELECT count(*) FROM openproof.organizations",{})))!=0U)
            co_return foundation::fail(E::AlreadyExists);
        const auto created=std::to_string(identityValue.createdAt().time_since_epoch().count());
        static_cast<void>(co_await execute("INSERT INTO openproof.organizations(id,name,state,created_at_ms) VALUES($1,$2,$3,$4)",
            params(tenantId,std::string{tenant.displayName()},std::to_string(static_cast<unsigned int>(tenant.status())),
                std::to_string(tenant.createdAt().time_since_epoch().count()))));
        static_cast<void>(co_await execute("INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) VALUES($1,$2,$3,$4,$5)",
            params(identityId,tenantId,std::to_string(static_cast<unsigned int>(identityValue.kind())),
                std::to_string(static_cast<unsigned int>(identityValue.status())),created)));
        static_cast<void>(co_await execute("INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) VALUES($1,$2,$3,$4)",
            params(std::string{provider.value()},std::string{link.external().subject().value()},identityId,
                std::to_string(link.requestedAt().time_since_epoch().count()))));
        static_cast<void>(co_await execute("INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) VALUES($1,$2,$3,$4)",
            params(tenantId,identityId,std::to_string(static_cast<unsigned int>(membership.state())),
                std::to_string(membership.invitedAt().time_since_epoch().count()))));
        for (const auto& role:membership.roles())
            static_cast<void>(co_await execute("INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,$3)",
                params(tenantId,identityId,std::string{role.value()})));
        static_cast<void>(co_await execute("INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) VALUES($1,$2,$3)",
            params(identityId,std::string{passwordHash->encoded()},created)));
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) "
            "VALUES($1,decode($2,'hex'),$3,NULL,$4)",
            params(identityId,foundation::toHex(encrypted.value()),std::to_string(keyVersion),created)));
        auto auditStatus=co_await appendRecords(*connection,deadline,event.value(),auditKey,"bootstrap.initial-owner",identityId);
        if (!auditStatus) co_return foundation::fail(auditStatus.error());
        const auto committed=co_await execute("COMMIT",{});
        if (committed.commandTag!="COMMIT" || !connection->reusable()) co_return foundation::fail(E::Unavailable);
        co_return foundation::ok();
    } catch (const std::exception&) {co_return foundation::fail(E::Unavailable,"Native bootstrap failed.");}
}
asio::awaitable<foundation::Status> repairInitialOwnerAsync(
    foundation::SecretString dsn,const core::OrganizationId& organizationId,const core::IdentityId& identityId,
    const idp::ProviderId& provider,foundation::Instant now,const audit::AuditKey& auditKey)
{
    if (organizationId.empty() || identityId.empty() || provider.empty()) co_return foundation::fail(E::InvalidArgument);
    auto randomId=security::randomTokenBase64Url(24U);
    if (!randomId) co_return foundation::fail(randomId.error());
    const std::string eventId="admin-"+randomId.value(),tenant{organizationId.value()},target{identityId.value()};
    auto event=audit::AuditEvent::create(audit::AuditEventId{eventId},now,foundation::CorrelationId{eventId},
        std::optional<core::OrganizationId>{organizationId},std::optional<core::IdentityId>{identityId},
        "administration","bootstrap.initial-owner.repair","success",
        audit::AuditFields{{"role","owner"},{"recovery_mode","empty-membership-bootstrap"},{"actor_identity_id",target}});
    if (!event) co_return foundation::fail(event.error());
    try {
        const auto deadline=Clock::now()+std::chrono::minutes{5};
        auto connection=co_await async_detail::AsyncConnection::connect(std::string{dsn.expose()},remaining(deadline));
        const auto execute=[&](std::string sql,Params args){
            return connection->query(std::move(sql),std::move(args),remaining(deadline));
        };
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL SERIALIZABLE",{}));
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673313)",{}));
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673315)",{}));
        // Block concurrent membership/bootstrap writes and session revocation
        // until the eligibility checks and audit event commit.
        static_cast<void>(co_await execute("LOCK TABLE openproof.organizations,openproof.identities,"
            "openproof.external_identities,openproof.password_credentials,openproof.totp_credentials,"
            "openproof.memberships,openproof.membership_roles,openproof.sessions IN SHARE ROW EXCLUSIVE MODE",{}));
        if (number(single(co_await execute("SELECT count(*) FROM openproof.organizations",{})))!=1U
            || number(single(co_await execute("SELECT count(*) FROM openproof.organizations WHERE id=$1 AND state=0",params(tenant))))!=1U
            || number(single(co_await execute("SELECT count(*) FROM openproof.memberships",{})))!=0U
            || number(single(co_await execute("SELECT count(*) FROM openproof.membership_roles WHERE role='owner'",{})))!=0U
            || number(single(co_await execute("SELECT count(*) FROM openproof.audit_events WHERE action IN "
                "('bootstrap.initial-owner','bootstrap.initial-owner.repair') AND outcome='success'",{})))!=0U)
            co_return foundation::fail(E::FailedPrecondition);
        const auto eligible=co_await execute(
            "SELECT count(*) FROM openproof.identities i JOIN openproof.external_identities e ON e.identity_id=i.id AND e.provider=$3 "
            "JOIN openproof.password_credentials p ON p.identity_id=i.id JOIN openproof.totp_credentials t ON t.identity_id=i.id "
            "WHERE i.organization_id=$1 AND i.id=$2 AND i.kind=0 AND i.status=0",
            params(tenant,target,std::string{provider.value()}));
        if (number(single(eligible))!=1U) co_return foundation::fail(E::FailedPrecondition);
        const auto timestamp=std::to_string(now.time_since_epoch().count());
        const auto sessions=co_await execute(
            "SELECT count(*) FROM openproof.sessions WHERE identity_id=$1 AND state=0 AND assurance>=2 "
            "AND issued_at_ms<=$2::bigint AND absolute_expires_at_ms>$2::bigint AND last_seen_at_ms+idle_timeout_ms>$2::bigint",
            params(target,timestamp));
        if (number(single(sessions))==0U) co_return foundation::fail(E::AssuranceInsufficient);
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) VALUES($1,$2,1,$3)",
            params(tenant,target,timestamp)));
        static_cast<void>(co_await execute(
            "INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,'owner')",
            params(tenant,target)));
        auto auditStatus=co_await appendRecords(*connection,deadline,event.value(),auditKey,"bootstrap.initial-owner.repaired",target);
        if (!auditStatus) co_return foundation::fail(auditStatus.error());
        const auto committed=co_await execute("COMMIT",{});
        if (committed.commandTag!="COMMIT" || !connection->reusable()) co_return foundation::fail(E::Unavailable);
        co_return foundation::ok();
    } catch (const std::exception&) {co_return foundation::fail(E::Unavailable,"Native initial-owner repair failed.");}
}
}
foundation::Status initializeAdministratorOffline(
    foundation::SecretString dsn,const adm::InitialAdministrator& administrator,
    const credentials::PasswordHasher& hasher,const security::AeadKey& totpKey,
    std::uint32_t keyVersion,const idp::ProviderId& provider,const audit::AuditKey& auditKey)
{
    try {
        asio::io_context io;
        auto result=asio::co_spawn(io,initializeAdministratorAsync(std::move(dsn),administrator,hasher,totpKey,keyVersion,provider,auditKey),asio::use_future);
        io.run();return result.get();
    } catch (const std::exception&) {return foundation::fail(E::Unavailable);}
}
foundation::Status repairInitialOwnerOffline(
    foundation::SecretString dsn,const core::OrganizationId& organizationId,const core::IdentityId& identityId,
    const idp::ProviderId& provider,foundation::Instant now,const audit::AuditKey& auditKey)
{
    try {
        asio::io_context io;
        auto result=asio::co_spawn(io,repairInitialOwnerAsync(std::move(dsn),organizationId,identityId,provider,now,auditKey),asio::use_future);
        io.run();return result.get();
    } catch (const std::exception&) {return foundation::fail(E::Unavailable);}
}

class CoroutineAdminStore::Impl final {
public:
    Impl(asio::any_io_executor executor,foundation::SecretString dsn,core::OrganizationId org,
         idp::ProviderId local,credentials::BoundedPasswordExecutor& kdf,security::AeadKey encryption,
         std::uint32_t version,audit::AuditKey key,std::size_t capacity,foundation::Duration acquireTimeout,
         foundation::Duration connectTimeout,foundation::Duration queryTimeout)
        : pool(std::move(executor),std::string{dsn.expose()},capacity,acquireTimeout,connectTimeout),
          organization(std::move(org)),provider(std::move(local)),passwords(&kdf),
          totpKey(std::move(encryption)),keyVersion(version),auditKey(std::move(key)),timeout(queryTimeout) {
        if (organization.empty() || provider.empty() || keyVersion==0U || timeout<=foundation::Duration::zero())
            throw std::invalid_argument{"Invalid native administration configuration"};
    }
    async_detail::AsyncConnectionPool pool;
    core::OrganizationId organization;
    idp::ProviderId provider;
    credentials::BoundedPasswordExecutor* passwords;
    security::AeadKey totpKey;
    std::uint32_t keyVersion;
    audit::AuditKey auditKey;
    foundation::Duration timeout;
};
CoroutineAdminStore::CoroutineAdminStore(asio::any_io_executor executor,foundation::SecretString dsn,
    core::OrganizationId organization,idp::ProviderId provider,credentials::BoundedPasswordExecutor& passwords,
    security::AeadKey totpKey,std::uint32_t keyVersion,audit::AuditKey auditKey,std::size_t capacity,
    foundation::Duration acquireTimeout,foundation::Duration connectTimeout,foundation::Duration queryTimeout)
    : m_impl(std::make_unique<Impl>(std::move(executor),std::move(dsn),std::move(organization),std::move(provider),
          passwords,std::move(totpKey),keyVersion,std::move(auditKey),capacity,acquireTimeout,connectTimeout,queryTimeout)) {}
CoroutineAdminStore::~CoroutineAdminStore()=default;

asio::awaitable<foundation::Status> CoroutineAdminStore::mutateAsync(core::IdentityId actor,const Command& command) {
    using E=foundation::ErrorCode;
    using State=organization::MembershipState;
    if (actor.empty() || actor.value().size()>200U) co_return foundation::fail(E::InvalidArgument);
    try {
        const auto* enrollment=std::get_if<adm::LocalMemberEnrollment>(&command);
        const auto* replacement=std::get_if<adm::MemberRoleReplacement>(&command);
        const auto* change=std::get_if<adm::MemberLifecycleChange>(&command);
        const auto* reset=std::get_if<adm::LocalCredentialReset>(&command);
        if (!enrollment && !replacement && !change && !reset)
            co_return foundation::fail(E::InvalidArgument);
        const auto& tenantId=enrollment ? enrollment->organizationId()
            : replacement ? replacement->organizationId() : change ? change->organizationId() : reset->organizationId();
        if (tenantId!=m_impl->organization) co_return foundation::fail(E::PermissionDenied);
        const auto& identity=enrollment ? enrollment->identity().id()
            : replacement ? replacement->identityId() : change ? change->identityId() : reset->identityId();
        const auto now=enrollment ? enrollment->identity().createdAt()
            : replacement ? replacement->occurredAt() : change ? change->occurredAt() : reset->occurredAt();
        const std::string tenant{tenantId.value()},target{identity.value()},actorId{actor.value()};
        const auto occurred=std::to_string(now.time_since_epoch().count());
        const std::string provider{m_impl->provider.value()};
        std::string action,securityType;
        audit::AuditFields fields{{"actor_identity_id",actorId}};
        const std::vector<organization::Role>* roles=nullptr;
        if (enrollment) {
            const auto& value=enrollment->identity();
            const auto& link=enrollment->link();
            const auto& member=enrollment->membership();
            if (!value.canAuthenticate() || value.kind()!=core::SubjectKind::Human
                || link.state()!=core::LinkState::Linked || link.owner()!=identity
                || link.external().providerId()!=m_impl->provider || member.organization()!=tenantId
                || member.identity()!=identity || member.state()!=State::Active)
                co_return foundation::fail(E::FailedPrecondition);
            action="local-member.create"; securityType="administration.local-member.created";
            fields.emplace("provider",provider);
            roles=&member.roles();
        } else if (replacement) {
            action="local-member.roles.replace"; securityType="administration.local-member.roles-replaced";
            roles=&replacement->roles();
        } else if (change) {
            const std::string name{adm::memberLifecycleActionName(change->action())};
            action="local-member."+name; securityType="administration.local-member."+name;
        } else {
            action="local-member.credentials.reset"; securityType="administration.local-member.credentials-reset";
            fields.emplace("provider",provider);
        }
        if (roles) {
            std::string joined;
            for (const auto& role:*roles) {
                if (!joined.empty()) joined.push_back(',');
                joined.append(role.value());
            }
            fields.emplace("roles",std::move(joined));
        }
        auto random=security::randomTokenBase64Url(24U);
        if (!random) co_return foundation::fail(random.error());
        const auto eventId=std::string{enrollment?"admin-member-":"admin-"}+random.value();
        auto event=audit::AuditEvent::create(audit::AuditEventId{eventId},now,
            foundation::CorrelationId{eventId},std::optional<core::OrganizationId>{tenantId},
            std::optional<core::IdentityId>{identity},"administration",std::move(action),"success",std::move(fields));
        if (!event) co_return foundation::fail(event.error());

        // Authorize before expensive KDF, and reauthorize under the write
        // transaction lock after hashing. Never hold a SQL lease across KDF.
        const auto ownerSql=
            "SELECT 1 FROM openproof.organizations o "
            "JOIN openproof.identities i ON i.organization_id=o.id AND i.id=$2 "
            "JOIN openproof.memberships m ON m.organization_id=o.id AND m.identity_id=i.id "
            "JOIN openproof.membership_roles r ON r.organization_id=m.organization_id AND r.identity_id=m.identity_id AND r.role='owner' "
            "WHERE o.id=$1 AND o.state=0 AND i.status=0 AND m.state=1";
        std::string passwordHash,encryptedSeed;
        if (enrollment || reset) {
            {
                const auto deadline=Clock::now()+m_impl->timeout;
                auto lease=co_await m_impl->pool.acquire(deadline);
                auto ownerArgs=params(tenant,actorId);
                const auto authorized=co_await lease.connection().query(ownerSql,std::move(ownerArgs),remaining(deadline));
                if (authorized.rows.size()!=1U) co_return foundation::fail(E::PermissionDenied);
            }
            const auto& password=enrollment?enrollment->generatedPassword():reset->generatedPassword();
            const auto& seed=enrollment?enrollment->generatedTotp():reset->generatedTotp();
            auto hash=co_await m_impl->passwords->hashAsync(password.clone());
            if (!hash) co_return foundation::fail(hash.error());
            passwordHash=std::string{hash->encoded()};
            auto encrypted=security::sealAes256Gcm(m_impl->totpKey,seed.bytes(),"openproof/totp/v1:"+target);
            if (!encrypted) co_return foundation::fail(encrypted.error());
            encryptedSeed=foundation::toHex(encrypted.value());
        }
        const auto deadline=Clock::now()+m_impl->timeout;
        auto lease=co_await m_impl->pool.acquire(deadline);
        auto& connection=lease.connection();
        const auto execute=[&](std::string sql,Params arguments) {
            return connection.query(std::move(sql),std::move(arguments),remaining(deadline));
        };
        // Shared legacy administration lock + row locks serialize owner
        // mutations. READ COMMITTED takes fresh snapshots after lock admission
        // (including the global audit head), avoiding a stale chain head.
        static_cast<void>(co_await execute("BEGIN ISOLATION LEVEL READ COMMITTED",{}));
        static_cast<void>(co_await execute("SELECT pg_advisory_xact_lock(7299730475761673315)",{}));
        const auto authorized=co_await execute(std::string{ownerSql}+" FOR UPDATE OF o,i,m,r",params(tenant,actorId));
        if (authorized.rows.size()!=1U)
            co_return co_await rollback(connection,deadline,E::PermissionDenied);
        if (enrollment) {
            const auto& value=enrollment->identity();
            const auto& link=enrollment->link();
            const auto& member=enrollment->membership();
            const auto inserted=co_await execute(
                "INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id",
                params(target,tenant,std::to_string(static_cast<unsigned int>(value.kind())),
                    std::to_string(static_cast<unsigned int>(value.status())),occurred));
            if (inserted.rows.empty()) co_return co_await rollback(connection,deadline,E::AlreadyExists);
            if (single(inserted)!=target) throw std::runtime_error{"Managed identity mismatch"};
            const auto linked=co_await execute(
                "INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING identity_id",
                params(provider,std::string{link.external().subject().value()},target,
                    std::to_string(link.requestedAt().time_since_epoch().count())));
            if (linked.rows.empty()) co_return co_await rollback(connection,deadline,E::AlreadyExists);
            if (single(linked)!=target) throw std::runtime_error{"Managed identity link mismatch"};
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms) VALUES($1,$2,$3,$4)",
                params(tenant,target,std::to_string(static_cast<unsigned int>(member.state())),
                    std::to_string(member.invitedAt().time_since_epoch().count()))));
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.password_credentials(identity_id,password_hash,changed_at_ms) VALUES($1,$2,$3)",
                params(target,passwordHash,occurred)));
            static_cast<void>(co_await execute(
                "INSERT INTO openproof.totp_credentials(identity_id,encrypted_seed,key_version,last_accepted_step,enrolled_at_ms) VALUES($1,decode($2,'hex'),$3,NULL,$4)",
                params(target,encryptedSeed,std::to_string(m_impl->keyVersion),occurred)));
        } else {
            const auto member=co_await execute(
                "SELECT m.state,EXISTS(SELECT 1 FROM openproof.membership_roles r WHERE r.organization_id=m.organization_id AND r.identity_id=m.identity_id AND r.role='owner') "
                "FROM openproof.organizations o JOIN openproof.identities i ON i.organization_id=o.id AND i.id=$2 "
                "JOIN openproof.memberships m ON m.organization_id=o.id AND m.identity_id=i.id "
                "WHERE o.id=$1 AND o.state=0 AND i.status=0 AND EXISTS(SELECT 1 FROM openproof.external_identities e WHERE e.identity_id=i.id AND e.provider=$3) FOR UPDATE OF o,i,m",
                params(tenant,target,provider));
            if (member.rows.empty()) co_return co_await rollback(connection,deadline,E::NotFound);
            if (member.rows.size()!=1U || member.rows.front().size()!=2U || !member.rows.front()[0] || !member.rows.front()[1])
                throw std::runtime_error{"Malformed local membership"};
            const auto stateNumber=number(*member.rows.front()[0]);
            const auto ownerValue=*member.rows.front()[1];
            if (stateNumber>3U || (ownerValue!="t" && ownerValue!="f"))
                throw std::runtime_error{"Invalid local membership state"};
            const auto state=static_cast<State>(stateNumber);
            const bool owner=ownerValue=="t";
            bool removesOwner=false;
            std::optional<State> next;
            if (replacement) {
                if (state==State::Removed) co_return co_await rollback(connection,deadline,E::FailedPrecondition);
                removesOwner=std::none_of(roles->begin(),roles->end(),[](const auto& role){return role.value()=="owner";});
            } else if (change) {
                switch (change->action()) {
                case adm::MemberLifecycleAction::Suspend:
                    if (state!=State::Active) co_return co_await rollback(connection,deadline,E::FailedPrecondition);
                    next=State::Suspended; removesOwner=true; break;
                case adm::MemberLifecycleAction::Reinstate:
                    if (state!=State::Suspended) co_return co_await rollback(connection,deadline,E::FailedPrecondition);
                    next=State::Active; break;
                case adm::MemberLifecycleAction::Remove:
                    if (state==State::Removed) co_return co_await rollback(connection,deadline,E::FailedPrecondition);
                    next=State::Removed; removesOwner=true; break;
                }
            } else if (state!=State::Active) {
                co_return co_await rollback(connection,deadline,E::FailedPrecondition);
            }
            if (state==State::Active && owner && removesOwner) {
                // Lock a surviving active owner, not just an aggregate count.
                const auto survivors=co_await execute(
                    "SELECT m.identity_id FROM openproof.memberships m JOIN openproof.identities i ON i.id=m.identity_id AND i.organization_id=m.organization_id "
                    "JOIN openproof.membership_roles r ON r.organization_id=m.organization_id AND r.identity_id=m.identity_id AND r.role='owner' "
                    "WHERE m.organization_id=$1 AND m.identity_id<>$2 AND m.state=1 AND i.status=0 ORDER BY m.identity_id LIMIT 1 FOR UPDATE OF m,i,r",
                    params(tenant,target));
                if (survivors.rows.empty()) co_return co_await rollback(connection,deadline,E::FailedPrecondition);
                if (single(survivors)==target) throw std::runtime_error{"Invalid surviving owner"};
            }
            if (replacement || next==State::Removed)
                static_cast<void>(co_await execute("DELETE FROM openproof.membership_roles WHERE organization_id=$1 AND identity_id=$2",params(tenant,target)));
            if (next) {
                const auto updated=co_await execute(
                    "UPDATE openproof.memberships SET state=$3 WHERE organization_id=$1 AND identity_id=$2 RETURNING identity_id",
                    params(tenant,target,std::to_string(static_cast<unsigned int>(*next))));
                if (single(updated)!=target) throw std::runtime_error{"Membership mutation mismatch"};
            }
            if (reset) {
                const auto password=co_await execute(
                    "UPDATE openproof.password_credentials SET password_hash=$2,changed_at_ms=GREATEST(changed_at_ms+1,$3::bigint) WHERE identity_id=$1 RETURNING identity_id",
                    params(target,passwordHash,occurred));
                const auto totp=co_await execute(
                    "UPDATE openproof.totp_credentials SET encrypted_seed=decode($2,'hex'),key_version=$3,last_accepted_step=NULL,enrolled_at_ms=$4 WHERE identity_id=$1 RETURNING identity_id",
                    params(target,encryptedSeed,std::to_string(m_impl->keyVersion),occurred));
                if (password.rows.empty() || totp.rows.empty()) co_return co_await rollback(connection,deadline,E::FailedPrecondition);
                if (single(password)!=target || single(totp)!=target) throw std::runtime_error{"Credential mutation mismatch"};
                static_cast<void>(co_await execute("DELETE FROM openproof.recovery_codes WHERE identity_id=$1",params(target)));
            }
            static_cast<void>(co_await execute("UPDATE openproof.sessions SET state=1,revoked_at_ms=$2 WHERE identity_id=$1 AND state=0",params(target,occurred)));
        }
        if (roles) {
            for (const auto& role:*roles)
                static_cast<void>(co_await execute("INSERT INTO openproof.membership_roles(organization_id,identity_id,role) VALUES($1,$2,$3)",
                    params(tenant,target,std::string{role.value()})));
        }
        const auto recorded=co_await appendRecords(connection,deadline,event.value(),m_impl->auditKey,std::move(securityType),actorId);
        if (!recorded) co_return foundation::fail(recorded.error());
        static_cast<void>(co_await execute("COMMIT",{}));
        co_return foundation::ok();
    } catch (const std::exception&) {
        // An incomplete transaction is not reusable; the lease discards
        // its connection and PostgreSQL rolls it back. Never retry COMMIT.
        co_return foundation::fail(foundation::ErrorCode::Unavailable,"Native administration is unavailable.");
    }
}
}
