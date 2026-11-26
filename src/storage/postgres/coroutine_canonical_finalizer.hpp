#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

import openproof.administration;
import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.identity.profile;
import openproof.organization;
import openproof.policy;
import openproof.session;

namespace openproof::storage::postgres {

/**
 * Native PostgreSQL canonical identity finalizer.
 *
 * This opt-in adapter handles existing, explicitly linked identities only.
 * It denies self-provisioning rather than implicitly creating new identities.
 * A tenant is mandatory and every authorization is scoped to that tenant.
 * The caller must outlive all in-flight coroutines; none of these operations
 * uses a synchronous PostgreSQL repository on the Asio reactor.
 */
class CoroutinePostgresCanonicalFinalizer final
    : public authentication::CoroutineCanonicalIdentityFinalizer,
      private policy::AuthorizationContextSource {
public:
    CoroutinePostgresCanonicalFinalizer(
        boost::asio::any_io_executor executor,
        foundation::SecretString connectionString,
        identity::core::OrganizationId organization,
        std::size_t maxConnections,
        foundation::Duration acquireTimeout,
        foundation::Duration connectTimeout,
        foundation::Duration queryTimeout);
    CoroutinePostgresCanonicalFinalizer(
        const CoroutinePostgresCanonicalFinalizer&) = delete;
    CoroutinePostgresCanonicalFinalizer& operator=(
        const CoroutinePostgresCanonicalFinalizer&) = delete;
    ~CoroutinePostgresCanonicalFinalizer() override;

    [[nodiscard]] bool nativeConnectionsEnabled() const noexcept override {
        return true;
    }

    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<identity::core::IdentityId>>
    finishLoginAsync(const identity::provider::AuthenticationOutcome& outcome,
                     foundation::Instant completedAt) override;

    /** Tenant-scoped, read-only native account profile lookup.
     * Caller must authenticate the session first. Never creates a profile
     * or identity, and refuses inactive identities/organizations.
     */
    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<identity::profile::IdentityProfile>>
    readProfileAsync(identity::core::IdentityId owner);
    // Existing-profile mutation only. Contact verification and ownership
    // remain unchanged; lifecycle and avatar eligibility share a transaction.
    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<identity::profile::IdentityProfile>>
    updateProfileAsync(identity::core::IdentityId owner,
        std::optional<std::string> displayName, std::optional<std::string> username,
        std::optional<std::string> locale, std::optional<std::string> picture,
        std::optional<std::string> avatarSource, foundation::Instant now);

    /** Read-only, tenant-scoped external account enumeration. Returns the
     * verified owner with bounded rows for HTTP defense in depth. No
     * implicit creation, linking, or mutation is permitted.
     */
    [[nodiscard]] boost::asio::awaitable<foundation::Result<
        std::pair<identity::core::IdentityId,
                  std::vector<identity::core::ExternalIdentityRef>>>>
    readConnectionsAsync(identity::core::IdentityId owner);

    /** Read-only TOTP status. nullopt means no configured local-provider link;
     * false means linked but no usable password/TOTP pair. Never read secrets.
     */
    [[nodiscard]] boost::asio::awaitable<foundation::Result<
        std::pair<identity::core::IdentityId, std::optional<bool>>>>
    readTotpStatusAsync(identity::core::IdentityId owner,
                        identity::provider::ProviderId localProvider);

    /** Read the authoritative active membership and its roles in one SQL
     * snapshot. The caller must supply a server-authenticated identity and
     * the route's organization; a mismatched tenant is denied. This is a
     * repository read, not a standalone authorization decision.
     */
    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<organization::Membership>>
    readAuthorizationMembershipAsync(identity::core::IdentityId subject,
                                     identity::core::OrganizationId tenant);

    /** Owner-only administration projection. Authorization and listing share
     * one SQL snapshot, bound to the configured tenant. No credential reads.
     */
    [[nodiscard]] boost::asio::awaitable<foundation::Result<administration::MemberListing>>
    readMembersAsync(identity::core::IdentityId actor);

    /** Trusted context for native protected-route policy evaluation.
     * All values are owned across suspension; authorization itself is still
     * performed by the existing policy engine, not by this repository.
     */
    [[nodiscard]] boost::asio::awaitable<foundation::Result<policy::AuthorizationRequest>>
    readAuthorizationContextAsync(session::AuthenticatedSession authenticated,
                                  identity::core::OrganizationId tenant,
                                  policy::Action action, policy::Resource resource);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    authorizeConnectionTargetAsync(identity::core::IdentityId target) override;

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    authorizeHandoffOwnerAsync(identity::core::IdentityId owner,
        identity::core::ExternalIdentityRef external) override;
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    updatePresentationAsync(identity::core::IdentityId owner,
        identity::core::ExternalIdentityRef external,foundation::Instant now) override;

    [[nodiscard]] boost::asio::awaitable<
        foundation::Result<identity::core::ExternalIdentityRef>>
    finishConnectionAsync(
        const identity::provider::AuthenticationOutcome& outcome,
        identity::core::IdentityId target,
        foundation::Instant completedAt) override;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres
