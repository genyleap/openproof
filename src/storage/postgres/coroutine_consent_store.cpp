#include "async_pool.hpp"

#include <charconv>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "coroutine_consent_store.hpp"

import openproof.client;

namespace openproof::storage::postgres {
namespace asio = boost::asio;
namespace core = identity::core;
namespace {
using Clock = std::chrono::steady_clock;
using Params = std::vector<std::optional<std::string>>;
using Row = Params;

constexpr std::size_t kMaximumGrants = 256U;
constexpr std::size_t kMaximumScopes = 256U;
constexpr std::size_t kMaximumRows = 4096U;

foundation::Duration remaining(Clock::time_point deadline)
{
    const auto left = std::chrono::duration_cast<foundation::Duration>(deadline - Clock::now());
    if (left <= foundation::Duration::zero())
        throw std::runtime_error{"Consent SQL deadline exceeded"};
    return left;
}

const std::string& required(const std::optional<std::string>& value)
{
    if (!value) throw std::runtime_error{"Malformed consent row"};
    return *value;
}

foundation::Instant instant(const std::optional<std::string>& field)
{
    const auto& value = required(field);
    std::int64_t parsed{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size() || parsed < 0)
        throw std::runtime_error{"Malformed consent timestamp"};
    return foundation::Instant{foundation::Duration{parsed}};
}

std::optional<foundation::Instant> optionalInstant(const std::optional<std::string>& field)
{
    return field ? std::optional{instant(field)} : std::nullopt;
}

bool validId(std::string_view value, std::size_t maximum = 200U)
{
    if (value.empty() || value.size() > maximum) return false;
    for (const unsigned char character : value)
        if (character < 32U || character == 127U) return false;
    return true;
}

bool exactRow(const async_detail::QueryRows& result, std::string_view value)
{
    return result.rows.size() == 1U && result.rows.front().size() == 1U
        && result.rows.front().front() && *result.rows.front().front() == value;
}
} // namespace

class CoroutineConsentStore::Impl final {
public:
    Impl(asio::any_io_executor executor, foundation::SecretString dsn,
         core::OrganizationId tenantValue, std::size_t capacity,
         foundation::Duration acquireTimeout, foundation::Duration connectTimeout,
         foundation::Duration queryTimeoutValue)
        : pool(std::move(executor), std::string{dsn.expose()}, capacity, acquireTimeout,
               connectTimeout), tenant(std::move(tenantValue)), queryTimeout(queryTimeoutValue)
    {
        if (!validId(tenant.value()) || queryTimeout <= foundation::Duration::zero())
            throw std::invalid_argument{"Invalid native consent store configuration"};
    }
    async_detail::AsyncConnectionPool pool;
    core::OrganizationId tenant;
    foundation::Duration queryTimeout;
};

CoroutineConsentStore::CoroutineConsentStore(asio::any_io_executor executor,
    foundation::SecretString connectionString, core::OrganizationId tenant,
    std::size_t capacity, foundation::Duration acquireTimeout,
    foundation::Duration connectTimeout, foundation::Duration queryTimeout)
    : m_impl(std::make_unique<Impl>(std::move(executor), std::move(connectionString),
        std::move(tenant), capacity, acquireTimeout, connectTimeout, queryTimeout))
{
}
CoroutineConsentStore::~CoroutineConsentStore() = default;

asio::awaitable<foundation::Result<CoroutineConsentStore::Listing>>
CoroutineConsentStore::listAsync(core::IdentityId owner)
{
    if (!validId(owner.value()))
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        Params params{std::string{owner.value()}, std::string{m_impl->tenant.value()}};
        // A single statement owns the lifecycle check and all grant/scope
        // reads. The left joins distinguish an empty list from denied access.
        // An application from another tenant is malformed and rejected below,
        // not silently omitted. Bound both the joined SQL result and groups.
        const auto result = co_await lease.connection().query(
            "WITH actor AS (SELECT i.id FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND o.state=0) "
            "SELECT a.id,c.id,c.client_id,c.audience,c.granted_at_ms,"
            "c.expires_at_ms,c.revoked_at_ms,c.organization_id,s.scope "
            "FROM actor a LEFT JOIN LATERAL ("
            "SELECT g.id,g.client_id,g.audience,g.granted_at_ms,g.expires_at_ms,"
            "g.revoked_at_ms,app.organization_id FROM openproof.oauth_consents g "
            "JOIN openproof.oauth_clients cl ON cl.id=g.client_id "
            "JOIN openproof.applications app ON app.id=cl.application_id "
            "WHERE g.identity_id=a.id ORDER BY g.granted_at_ms DESC,g.id COLLATE \"C\" LIMIT 257"
            ") c ON true LEFT JOIN LATERAL ("
            "SELECT scope FROM openproof.oauth_consent_scopes WHERE consent_id=c.id "
            "ORDER BY scope COLLATE \"C\" LIMIT 257) s ON true "
            "ORDER BY c.granted_at_ms DESC,c.id COLLATE \"C\",s.scope COLLATE \"C\" LIMIT 4097",
            std::move(params), remaining(deadline));
        const auto& rows = result.rows;
        if (rows.empty())
            co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
        if (rows.size() > kMaximumRows)
            co_return foundation::fail(foundation::ErrorCode::Unavailable);
        Listing grants;
        for (std::size_t first = 0; first < rows.size();) {
            const auto& row = rows[first];
            if (row.size() != 9U || required(row[0]) != owner.value())
                throw std::runtime_error{"Malformed consent owner"};
            if (!row[1]) {
                if (rows.size() != 1U)
                    throw std::runtime_error{"Unexpected empty consent row"};
                for (std::size_t column = 1; column < row.size(); ++column)
                    if (row[column]) throw std::runtime_error{"Malformed empty consent row"};
                co_return grants;
            }
            if (grants.size() == kMaximumGrants || !validId(required(row[1]))
                || !validId(required(row[2]), 256U) || required(row[7]) != m_impl->tenant.value())
                throw std::runtime_error{"Invalid consent grant"};
            std::vector<std::string> scopes;
            std::size_t next = first;
            for (; next < rows.size(); ++next) {
                const auto& scopeRow = rows[next];
                if (scopeRow.size() != 9U)
                    throw std::runtime_error{"Malformed consent scope row"};
                if (scopeRow[1] != row[1]) break;
                for (std::size_t column = 0; column < 8U; ++column)
                    if (scopeRow[column] != row[column])
                        throw std::runtime_error{"Inconsistent consent projection"};
                const auto& scope = required(scopeRow[8]);
                if (scopes.size() == kMaximumScopes || !validId(scope, 128U)
                    || (!scopes.empty() && scopes.back() >= scope))
                    throw std::runtime_error{"Invalid consent scope"};
                scopes.push_back(scope);
            }
            auto grant = consent::ConsentGrant::restore(consent::ConsentId{required(row[1])},
                owner, client::ClientId{required(row[2])}, required(row[3]), std::move(scopes),
                instant(row[4]), optionalInstant(row[5]), optionalInstant(row[6]));
            if (!grant) throw std::runtime_error{"Malformed consent grant"};
            grants.push_back(std::move(grant).value());
            first = next;
        }
        co_return grants;
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native consent listing is unavailable.");
    }
}

asio::awaitable<foundation::Status> CoroutineConsentStore::revokeAsync(
    consent::ConsentId id, core::IdentityId owner, foundation::Instant now)
{
    if (!validId(id.value()) || !validId(owner.value()))
        co_return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        const auto deadline = Clock::now() + m_impl->queryTimeout;
        auto lease = co_await m_impl->pool.acquire(deadline);
        auto& connection = lease.connection();
        static_cast<void>(co_await connection.query("BEGIN ISOLATION LEVEL READ COMMITTED",
            {}, remaining(deadline)));
        Params params{std::string{owner.value()}, std::string{m_impl->tenant.value()}};
        const auto locked = co_await connection.query(
            "SELECT i.id FROM openproof.identities i "
            "JOIN openproof.organizations o ON o.id=i.organization_id "
            "WHERE i.id=$1 AND i.organization_id=$2 AND i.status=0 AND o.state=0 "
            "FOR UPDATE OF i FOR SHARE OF o", std::move(params), remaining(deadline));
        if (locked.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK", {}, remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::PermissionDenied);
        }
        if (!exactRow(locked, owner.value())) throw std::runtime_error{"Invalid consent owner"};
        Params revokeParams{std::string{id.value()}, std::string{owner.value()},
            std::to_string(now.time_since_epoch().count()), std::string{m_impl->tenant.value()}};
        const auto revoked = co_await connection.query(
            "UPDATE openproof.oauth_consents c SET revoked_at_ms=COALESCE(c.revoked_at_ms,$3) "
            "FROM openproof.oauth_clients cl JOIN openproof.applications app "
            "ON app.id=cl.application_id WHERE c.id=$1 AND c.identity_id=$2 "
            "AND c.client_id=cl.id AND app.organization_id=$4 RETURNING c.id",
            std::move(revokeParams), remaining(deadline));
        if (revoked.rows.empty()) {
            static_cast<void>(co_await connection.query("ROLLBACK", {}, remaining(deadline)));
            co_return foundation::fail(foundation::ErrorCode::NotFound);
        }
        if (!exactRow(revoked, id.value())) throw std::runtime_error{"Invalid consent revocation"};
        static_cast<void>(co_await connection.query("COMMIT", {}, remaining(deadline)));
        co_return foundation::ok();
    } catch (const std::exception&) {
        // Existing pool discards non-idle transactions; never retry an
        // ambiguous commit on a new connection.
        co_return foundation::fail(foundation::ErrorCode::Unavailable,
            "Native consent revocation is unavailable.");
    }
}

} // namespace openproof::storage::postgres
