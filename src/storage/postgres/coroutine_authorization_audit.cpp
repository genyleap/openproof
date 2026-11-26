#include "async_pool.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "coroutine_authorization_audit.hpp"

import openproof.identity.provider;
import openproof.security;

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
using Params = std::vector<std::optional<std::string>>;

[[nodiscard]] foundation::Duration remaining(Deadline deadline)
{
    auto budget = std::chrono::duration_cast<foundation::Duration>(
        deadline - Clock::now());
    if (budget <= foundation::Duration::zero())
        throw std::runtime_error{"Authorization audit deadline expired"};
    return budget;
}

[[nodiscard]] std::string required(const std::optional<std::string>& field)
{
    if (!field) throw std::runtime_error{"Malformed authorization audit row"};
    return *field;
}

[[nodiscard]] std::string singleField(const async_detail::QueryRows& rows)
{
    if (rows.rows.size() != 1U || rows.rows.front().size() != 1U)
        throw std::runtime_error{"Invalid authorization audit cardinality"};
    return required(rows.rows.front().front());
}

[[nodiscard]] std::uint64_t sequenceNumber(const std::string& field)
{
    std::uint64_t sequence{};
    const auto [end, error] = std::from_chars(
        field.data(), field.data() + field.size(), sequence);
    if (error != std::errc{} || end != field.data() + field.size() || sequence == 0U)
        throw std::runtime_error{"Invalid authorization audit sequence"};
    return sequence;
}
} // namespace

class CoroutineAuthorizationDecisionSink::Impl final {
public:
    Impl(asio::any_io_executor executor, foundation::SecretString dsn,
         audit::AuditKey keyValue, const foundation::ClockSource& clockValue,
         std::size_t capacity, foundation::Duration acquireTimeout,
         foundation::Duration connectTimeout, foundation::Duration queryTimeoutValue)
        : pool(std::move(executor), std::string{dsn.expose()}, capacity,
               acquireTimeout, connectTimeout), key(std::move(keyValue)),
          clock(&clockValue), queryTimeout(queryTimeoutValue)
    {
        if (queryTimeout <= foundation::Duration::zero())
            throw std::invalid_argument{"Invalid authorization audit timeout"};
    }
    async_detail::AsyncConnectionPool pool;
    audit::AuditKey key;
    const foundation::ClockSource* clock;
    foundation::Duration queryTimeout;
};

CoroutineAuthorizationDecisionSink::CoroutineAuthorizationDecisionSink(
    asio::any_io_executor executor, foundation::SecretString connectionString,
    audit::AuditKey key, const foundation::ClockSource& clock,
    std::size_t maxConnections, foundation::Duration acquireTimeout,
    foundation::Duration connectTimeout, foundation::Duration queryTimeout)
    : m_impl(std::make_unique<Impl>(std::move(executor),
        std::move(connectionString), std::move(key), clock,
        maxConnections, acquireTimeout, connectTimeout, queryTimeout))
{
}

CoroutineAuthorizationDecisionSink::~CoroutineAuthorizationDecisionSink() = default;

asio::awaitable<foundation::Status> CoroutineAuthorizationDecisionSink::recordAsync(
    session::AuthenticatedSession authenticated, identity::core::OrganizationId tenant,
    policy::Action action, policy::Resource resource,
    policy::AuthorizationDecision decision, foundation::CorrelationId correlation)
{
    // This sink is exclusively for rejected protected-route decisions.
    if (decision.isPermitted() || tenant.empty() || action.empty() || resource.empty())
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const Deadline deadline = Clock::now() + m_impl->queryTimeout;
        auto randomId = security::randomTokenBase64Url(24U);
        if (!randomId) co_return foundation::fail(randomId.error());
        auto event = audit::AuditEvent::create(
            audit::AuditEventId{"authorization-" + randomId.value()},
            m_impl->clock->now(), std::move(correlation),
            std::optional<identity::core::OrganizationId>{tenant},
            std::optional<identity::core::IdentityId>{authenticated.session().identity()},
            "authorization", "protected-route.evaluate",
            std::string{policy::decisionKindName(decision.kind())},
            audit::AuditFields{
                {"action", std::string{action.value()}},
                {"assurance", std::string{identity::provider::assuranceLevelName(
                    authenticated.session().assurance())}},
                {"provider", std::string{authenticated.session().provider().value()}},
                {"reason", std::string{decision.reason()}},
                {"resource", std::string{resource.value()}}});
        if (!event) co_return foundation::fail(event.error());

        auto lease = co_await m_impl->pool.acquire(deadline);
        auto& connection = lease.connection();
        static_cast<void>(co_await connection.query("BEGIN", {}, remaining(deadline)));
        // Match the legacy appendAuditRecord lock exactly. READ COMMITTED
        // takes a fresh snapshot after admission to this global writer lock.
        static_cast<void>(co_await connection.query(
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED", {}, remaining(deadline)));
        static_cast<void>(co_await connection.query(
            "SELECT pg_advisory_xact_lock(7299730475761673314)", {}, remaining(deadline)));
        const auto head = co_await connection.query(
            "SELECT encode(event_hash,'hex') FROM openproof.audit_events "
            "ORDER BY sequence DESC LIMIT 1", {}, remaining(deadline));
        std::optional<security::Sha256Digest> previousHash;
        std::string previousHex;
        if (!head.rows.empty()) {
            previousHex = singleField(head);
            auto parsed = foundation::fromHex(previousHex);
            if (!parsed || parsed->size() != security::Sha256Digest{}.size())
                throw std::runtime_error{"Invalid audit head hash"};
            security::Sha256Digest digest{};
            std::copy(parsed->begin(), parsed->end(), digest.begin());
            previousHash = digest;
        }
        foundation::JsonObjectWriter detail;
        for (const auto& [name, value] : event->fields()) detail.add(name, value);
        const std::string eventId{event->id().value()};
        const std::string occurredAt = std::to_string(event->occurredAt().time_since_epoch().count());
        const std::string subject{authenticated.session().identity().value()};
        Params insertParams{eventId, occurredAt, std::string{event->correlation().value()},
            std::string{tenant.value()}, subject, std::string{event->category()},
            std::string{event->action()}, std::string{event->outcome()}, detail.build(),
            previousHex, std::string(64U, '0')};
        const auto inserted = co_await connection.query(
            "INSERT INTO openproof.audit_events "
            "(event_id,occurred_at_ms,correlation_id,organization_id,identity_id,"
            "category,action,outcome,detail,previous_hash,event_hash) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,"
            "CASE WHEN $10='' THEN NULL ELSE decode($10,'hex') END,decode($11,'hex')) "
            "RETURNING sequence", std::move(insertParams), remaining(deadline));
        const auto sequence = sequenceNumber(singleField(inserted));
        auto hash = audit::computeAuditRecordHash(event.value(), sequence,
                                                  previousHash, m_impl->key);
        if (!hash) co_return foundation::fail(hash.error());
        Params sealParams{std::to_string(sequence), foundation::toHex(hash.value())};
        const auto sealed = co_await connection.query(
            "UPDATE openproof.audit_events SET event_hash=decode($2,'hex') "
            "WHERE sequence=$1 RETURNING sequence",
            std::move(sealParams), remaining(deadline));
        if (sequenceNumber(singleField(sealed)) != sequence)
            throw std::runtime_error{"Authorization audit seal mismatch"};

        foundation::JsonObjectWriter payload;
        payload.add("event_id", eventId)
            .add("type", "authorization.protected-route.denied")
            .add("organization_id", tenant.value())
            .add("identity_id", subject)
            .add("actor_identity_id", subject)
            .add("severity", "warning");
        Params outboxParams{eventId, occurredAt, payload.build()};
        const auto outbox = co_await connection.query(
            "INSERT INTO openproof.security_event_outbox "
            "(event_id,occurred_at_ms,payload) VALUES($1,$2,$3::jsonb) RETURNING event_id",
            std::move(outboxParams), remaining(deadline));
        if (singleField(outbox) != eventId)
            throw std::runtime_error{"Authorization outbox mismatch"};
        static_cast<void>(co_await connection.query("COMMIT", {}, remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        // The lease rejects every non-idle PGconn. Destroying the connection
        // rolls back an incomplete transaction and releases its advisory lock.
        // Do not retry an ambiguous commit or claim a denial was audited.
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native authorization audit persistence is unavailable.");
    }
}

} // namespace openproof::storage::postgres
