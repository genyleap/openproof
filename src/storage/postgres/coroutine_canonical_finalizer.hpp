#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <string>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

import openproof.administration;
import openproof.application;
import openproof.client;
import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.identity.profile;
import openproof.organization;
import openproof.policy;
import openproof.session;
import openproof.oauth;
import openproof.resource;
import openproof.provider.passkey;
import openproof.enterprise.scim;
import openproof.evidence;
import openproof.evidence.verifiers;

namespace openproof::storage::postgres {
namespace async_detail { class AsyncConnection; }

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

    // Owner and exact first-party IAL2 session are rechecked in the same
    // read-only snapshot as the bounded public management projection.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::string>>
    readApplicationManagementAsync(application::ManagementRead operation,
        identity::core::IdentityId actor,session::SessionId sessionId,
        std::optional<std::string> filter,foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<application::Application>>
    mutateApplicationAsync(application::ApplicationMutationCommand command,
        identity::core::IdentityId actor,session::SessionId sessionId,foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<client::Client>>
    mutateOAuthClientAsync(client::ManagementMutationCommand command,
        identity::core::IdentityId actor,session::SessionId sessionId,foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    mutateOAuthJarKeyAsync(client::ClientId id,std::optional<std::string> keyId,
        std::optional<std::string> publicKeyPem,identity::core::IdentityId actor,
        session::SessionId sessionId,foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<resource::ResourceServer>>
    mutateOAuthResourceAsync(resource::ResourceMutationCommand command,
        identity::core::IdentityId actor,session::SessionId sessionId,foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<resource::ServiceIdentity>>
    mutateServiceIdentityAsync(resource::ServiceMutationCommand command,
        identity::core::IdentityId actor,session::SessionId sessionId,foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::vector<provider::passkey::CredentialSummary>>>
    readPasskeyAccountAsync(identity::core::IdentityId actor,session::SessionId sessionId,foundation::Instant now,
        std::optional<provider::passkey::RegistrationCeremony> ceremony=std::nullopt);

    // A verified registration or a credential removal, never both.
    [[nodiscard]] boost::asio::awaitable<foundation::Status> mutatePasskeyAccountAsync(
        identity::core::IdentityId actor,session::SessionId sessionId,foundation::Instant now,
        std::string credentialId,std::optional<identity::provider::ChallengeId> ceremony,
        std::optional<provider::passkey::PasskeyCredential> verified);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<identity::core::IdentityId>>
    verifyPasskeyAssertionAsync(const provider::passkey::PasskeyConfig& config,
        identity::provider::ChallengeId challenge,provider::passkey::AssertionResponse assertion,
        foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<enterprise::scim::ReadResult>>
    readScimAsync(enterprise::scim::ReadRequest request);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<enterprise::scim::ReadResult>>
    mutateScimAsync(enterprise::scim::MutationRequest request,foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::vector<evidence::Evidence>>>
    evidenceAccountAsync(identity::core::IdentityId actor,session::SessionId sessionId,
        foundation::Instant now,evidence::verification::AccountCommand command);

    // Probe the real native pool, including queue admission and reconnect.
    [[nodiscard]] boost::asio::awaitable<foundation::Status> healthCheckAsync();

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
    // Unbound bearer only: read live access first, then authorized profile
    // on the same exclusive lease. Sender-bound grants never prefetch profile.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::pair<session::DelegatedAccess,std::optional<identity::profile::IdentityProfile>>>>
    readBearerUserInfoAsync(std::string digestHex,foundation::Instant now);
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

    // Atomically detach an owned, registered authentication connection only
    // when another registered sign-in method survives. Reset avatar selection
    // in the same transaction; the provider catalog is an immutable snapshot.
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    disconnectAsync(identity::core::IdentityId owner,
        identity::core::ExternalIdentityRef external,
        std::vector<identity::provider::ProviderId> authenticationProviders,
        foundation::Instant now);

    // Read-only account-scope authorization of an already HMAC-digested
    // OAuth access credential. Never persists a synthetic session.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<session::Session>>
    authorizeDelegatedAccountAsync(std::string digestHex,foundation::Instant now);

    // Read the token's complete bounded authorization context in one snapshot.
    // A returned sender constraint MUST still be verified against the request
    // before the access context is accepted. No session is persisted.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<session::DelegatedAccess>>
    readDelegatedAccessAsync(std::string digestHex,foundation::Instant now,
        foundation::Instant* issuedAt=nullptr);

    // Confidential client authentication for native introspection. Only
    // a server-keyed digest crosses the asynchronous SQL boundary.
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    authenticateConfidentialClientAsync(std::string clientId,
        std::string digestHex);

    // Authenticate first, then read the live token on the same exclusive SQL
    // lease. An empty successful result means inactive; caller denial is an error.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::optional<session::DelegatedAccess>>>
    introspectAccessAsync(std::string clientId,std::string clientDigest,
        std::string tokenDigest,const foundation::ClockSource& clock,foundation::Instant* issuedAt);

    // RFC 7009: authenticate public or confidential client inside the same
    // transaction as its token revocation. Unknown/foreign tokens are no-ops.
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    revokeOAuthTokenAsync(std::string clientId,std::optional<std::string> clientDigest,
        std::string tokenDigest,foundation::Instant now);

    // Rotate one refresh credential under the family lock. Return its
    // immutable scopes only after commit. Reuse/expiry revokes the family.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::vector<std::string>>>
    rotateOAuthRefreshAsync(std::string clientId,std::optional<std::string> clientDigest,
        std::string presentedDigest,std::string accessDigest,std::string refreshDigest,
        std::optional<session::DelegatedSenderConstraint> sender,foundation::Instant now,
        foundation::Duration accessLifetime);

    // No refresh token for machine grants. A subject digest selects RFC 8693;
    // otherwise the grant is restricted to the client's service identity.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<oauth::NativeMachineGrantResult>>
    issueOAuthMachineGrantAsync(std::string clientId,std::optional<std::string> clientDigest,
        std::optional<std::string> subjectDigest,std::string audience,
        std::vector<std::string> requestedScopes,std::string family,std::string accessDigest,
        std::optional<session::DelegatedSenderConstraint> sender,foundation::Instant now,
        foundation::Duration accessLifetime);

    using SignAuthorizationResponse=std::function<foundation::Result<std::string>(const oauth::AuthorizationRequest&,bool)>;
    // Browser-only completion. Revalidate the session, registry and consent
    // under locks; PAR is consumed only with a committed terminal decision.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<oauth::NativeAuthorizationResult>>
    completeOAuthAuthorizationAsync(std::string clientId,std::optional<std::string> parDigest,
        std::optional<oauth::AuthorizationRequest> direct,identity::core::IdentityId owner,
        session::SessionId sessionId,oauth::NativeAuthorizationDecision decision,
        std::string consentId,std::string codeDigest,foundation::Instant now,
        foundation::Duration lifetime,SignAuthorizationResponse signResponse);

    using VerifyJar=std::function<foundation::Result<oauth::NativeJarAuthorization>(
        std::string_view,std::string_view,foundation::Instant)>;
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    pushOAuthAuthorizationAsync(std::string clientId,std::optional<std::string> clientDigest,
        std::string requestDigest,std::optional<oauth::AuthorizationRequest> direct,
        VerifyJar verifyJar,foundation::Instant now,foundation::Duration lifetime,
        bool signedFrontChannel=false);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<oauth::NativeDeviceApproval>>
    readOAuthDeviceApprovalAsync(std::string userDigest,identity::core::IdentityId owner,
        foundation::Instant now);
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    decideOAuthDeviceAsync(std::string userDigest,identity::core::IdentityId owner,
        session::SessionId sessionId,bool approve,std::string consentId,foundation::Instant now);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    beginOAuthDeviceAsync(std::string clientId,std::optional<std::string> clientDigest,
        std::string deviceDigest,std::string userDigest,std::vector<std::string> scopes,
        std::optional<std::string> resource,foundation::Instant now,
        foundation::Duration lifetime,foundation::Duration interval);

    [[nodiscard]] boost::asio::awaitable<foundation::Result<oauth::NativeDevicePollResult>>
    pollOAuthDeviceAsync(std::string clientId,std::optional<std::string> clientDigest,
        std::string deviceDigest,std::string family,std::string accessDigest,std::string refreshDigest,
        std::optional<session::DelegatedSenderConstraint> sender,foundation::Instant now,
        foundation::Duration accessLifetime,foundation::Duration refreshLifetime);

    using SignCodeIdToken=std::function<foundation::Result<std::string>(const oauth::AuthorizationCode&)>;
    [[nodiscard]] boost::asio::awaitable<foundation::Result<oauth::NativeCodeExchangeResult>>
    exchangeOAuthCodeAsync(std::string clientId,std::optional<std::string> clientDigest,
        std::string codeDigest,std::string redirectUri,std::string challenge,
        std::string family,std::string accessDigest,std::string refreshDigest,
        std::optional<session::DelegatedSenderConstraint> sender,foundation::Instant now,
        foundation::Duration accessLifetime,foundation::Duration refreshLifetime,
        SignCodeIdToken signIdToken);

    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    consumeSenderReplayAsync(session::DelegatedSenderConstraintKind kind,
        std::string thumbprint,std::string identifier,foundation::Instant expiresAt,
        foundation::Instant now);

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
    [[nodiscard]] boost::asio::awaitable<foundation::Result<identity::profile::IdentityProfile>>
    readProfileOnLease(async_detail::AsyncConnection& connection,identity::core::IdentityId owner,
        std::chrono::steady_clock::time_point deadline);
    [[nodiscard]] boost::asio::awaitable<foundation::Result<session::DelegatedAccess>>
    readDelegatedAccessOnLease(async_detail::AsyncConnection& connection,
        std::string digestHex,foundation::Instant now,foundation::Instant* issuedAt,
        std::chrono::steady_clock::time_point deadline,
        std::optional<identity::profile::IdentityProfile>* selectedProfile=nullptr);
    [[nodiscard]] boost::asio::awaitable<foundation::Status>
    authenticateConfidentialClientOnLease(async_detail::AsyncConnection& connection,
        std::string clientId,std::string digestHex,std::chrono::steady_clock::time_point deadline);
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openproof::storage::postgres
