#include "async_session.hpp"
#include "coroutine_session_repository.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

import openproof.storage.postgres;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.security;
import openproof.session;

namespace openproof::storage::postgres {

foundation::Result<session::Session> PostgresSessionDomainAdapter::restore(
    const std::vector<std::optional<std::string>>& fields)
{
    // This adapter is the one-way trust boundary from a libpq result to a
    // security-relevant Session domain entity. Do not leak the contents of an
    // invalid row, SQL text or credentials into the returned error.
    try {
        auto row = async_detail::AsyncSessionSql::decodeRow(fields);
        auto binary = foundation::fromHex(row.tokenDigestHex);
        security::Sha256Digest digest{};
        if (!binary || binary->size() != digest.size()) {
            return foundation::fail(foundation::ErrorCode::Internal,
                                    "PostgreSQL session digest is invalid.");
        }
        std::ranges::copy(*binary, digest.begin());
        std::optional<foundation::Instant> revokedAt;
        if (row.revokedAtMs.has_value()) {
            revokedAt = foundation::Instant{
                foundation::Duration{*row.revokedAtMs}};
        }
        auto restored = session::Session::restore(
            session::SessionId{std::move(row.id)},
            identity::core::IdentityId{std::move(row.identityId)},
            identity::provider::ProviderId{std::move(row.provider)},
            static_cast<identity::provider::AssuranceLevel>(row.assurance),
            identity::provider::AuthenticationStrength{
                static_cast<identity::provider::AuthenticationFactor>(row.factors),
                row.phishingResistant},
            static_cast<session::SessionState>(row.state),
            foundation::Instant{foundation::Duration{row.authenticatedAtMs}},
            session::TokenDigest{digest},
            foundation::Instant{foundation::Duration{row.issuedAtMs}},
            foundation::Instant{foundation::Duration{row.lastSeenAtMs}},
            foundation::Instant{foundation::Duration{row.absoluteExpiresAtMs}},
            foundation::Duration{row.idleTimeoutMs}, revokedAt,
            std::move(row.userAgent), std::move(row.remoteAddress));
        if (!restored) {
            // The row came from storage, not from the caller. Never leak
            // domain validation details or misclassify corruption as a
            // client's InvalidArgument / AuthenticationFailed response.
            return foundation::fail(foundation::ErrorCode::Internal,
                                    "PostgreSQL session row could not be restored.");
        }
        return restored;
    } catch (const std::exception&) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "PostgreSQL session row could not be restored.");
    }
}

} // namespace openproof::storage::postgres
