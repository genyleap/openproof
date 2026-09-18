module;

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.identity.core;

namespace openproof::identity::core {

ExternalIdentityRef::ExternalIdentityRef(provider::ProviderId providerId,
                                         provider::ExternalSubject subject)
    : m_providerId(std::move(providerId))
    , m_subject(std::move(subject))
{
}

const provider::ProviderId& ExternalIdentityRef::providerId() const noexcept
{
    return m_providerId;
}

const provider::ExternalSubject& ExternalIdentityRef::subject() const noexcept
{
    return m_subject;
}

std::string_view linkStateName(LinkState state) noexcept
{
    switch (state) {
    case LinkState::LinkRequested:
        return "link_requested";
    case LinkState::VerificationRequired:
        return "verification_required";
    case LinkState::Verified:
        return "verified";
    case LinkState::Linked:
        return "linked";
    case LinkState::Rejected:
        return "rejected";
    case LinkState::Expired:
        return "expired";
    case LinkState::Revoked:
        return "revoked";
    }
    return "rejected";
}

bool isTerminalLinkState(LinkState state) noexcept
{
    switch (state) {
    case LinkState::Rejected:
    case LinkState::Expired:
    case LinkState::Revoked:
        return true;
    case LinkState::LinkRequested:
    case LinkState::VerificationRequired:
    case LinkState::Verified:
    case LinkState::Linked:
        return false;
    }
    return true;
}

namespace {

/**
 * The complete transition table. Written in one place so that the reachable
 * paths can be read and reviewed as a whole; a transition scattered across
 * methods is a transition nobody audits.
 */
[[nodiscard]] bool isPermittedTransition(LinkState from, LinkState to) noexcept
{
    switch (from) {
    case LinkState::LinkRequested:
        return to == LinkState::VerificationRequired || to == LinkState::Rejected
               || to == LinkState::Expired;
    case LinkState::VerificationRequired:
        return to == LinkState::Verified || to == LinkState::Rejected
               || to == LinkState::Expired;
    case LinkState::Verified:
        // The only edge into Linked. Nothing else may create an association.
        return to == LinkState::Linked || to == LinkState::Rejected
               || to == LinkState::Expired;
    case LinkState::Linked:
        return to == LinkState::Revoked;
    case LinkState::Rejected:
    case LinkState::Expired:
    case LinkState::Revoked:
        return false;
    }
    return false;
}

}

IdentityLink::IdentityLink(IdentityId owner, ExternalIdentityRef external,
                           foundation::Instant requestedAt, foundation::Instant expiresAt)
    : m_owner(std::move(owner))
    , m_external(std::move(external))
    , m_requestedAt(requestedAt)
    , m_expiresAt(expiresAt)
{
}

foundation::Result<IdentityLink> IdentityLink::request(IdentityId owner,
                                                       ExternalIdentityRef external,
                                                       foundation::Instant requestedAt,
                                                       foundation::Duration lifetime)
{
    if (owner.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A link request must name the identity it would attach to.");
    }
    if (external.providerId().empty() || external.subject().empty()) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "A link request must name a provider and an external subject.",
            "An external identity is only meaningful as a (provider, subject) pair; a "
            "subject without its issuer would match unrelated subjects elsewhere.");
    }
    if (lifetime <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A link request must have a positive lifetime.");
    }

    return IdentityLink{std::move(owner), std::move(external), requestedAt,
                        requestedAt + lifetime};
}

const IdentityId& IdentityLink::owner() const noexcept
{
    return m_owner;
}

const ExternalIdentityRef& IdentityLink::external() const noexcept
{
    return m_external;
}

LinkState IdentityLink::state() const noexcept
{
    return m_state;
}

foundation::Instant IdentityLink::requestedAt() const noexcept
{
    return m_requestedAt;
}

foundation::Instant IdentityLink::expiresAt() const noexcept
{
    return m_expiresAt;
}

bool IdentityLink::isExpiredAt(foundation::Instant now) const noexcept
{
    return now >= m_expiresAt;
}

foundation::Status IdentityLink::transitionTo(LinkState next, foundation::Instant now,
                                              bool honourExpiry)
{
    if (!isPermittedTransition(m_state, next)) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This account link cannot be advanced.",
            std::string{"Refused link transition "} + std::string{linkStateName(m_state)}
                + " -> " + std::string{linkStateName(next)} + ".");
    }

    // An expired request may still be marked expired or rejected, but it must not
    // be advanced toward Linked. Checking here rather than in each caller means a
    // future transition cannot forget it.
    if (honourExpiry && isExpiredAt(now)) {
        m_state = LinkState::Expired;
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This account link request has expired.",
                                "Link transition refused: request deadline passed.");
    }

    m_state = next;
    return foundation::ok();
}

foundation::Status IdentityLink::requireVerification(foundation::Instant now)
{
    return transitionTo(LinkState::VerificationRequired, now, true);
}

foundation::Status IdentityLink::markVerified(foundation::Instant now)
{
    return transitionTo(LinkState::Verified, now, true);
}

foundation::Status IdentityLink::complete(foundation::Instant now)
{
    return transitionTo(LinkState::Linked, now, true);
}

foundation::Status IdentityLink::reject(foundation::Instant now)
{
    return transitionTo(LinkState::Rejected, now, false);
}

foundation::Status IdentityLink::revoke(foundation::Instant now)
{
    return transitionTo(LinkState::Revoked, now, false);
}

foundation::Status IdentityLink::expire(foundation::Instant now)
{
    return transitionTo(LinkState::Expired, now, false);
}

foundation::Status InMemoryExternalIdentityDirectory::attach(const IdentityLink& link)
{
    if (link.state() != LinkState::Linked) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This account link is not complete.",
            std::string{"Refused to attach an external identity from a link in state "}
                + std::string{linkStateName(link.state())}
                + "; only a Linked request may create an association.");
    }

    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto existing = m_owners.find(link.external());
    if (existing != m_owners.end()) {
        if (existing->second == link.owner()) {
            return foundation::ok();
        }

        // Refuse, never transfer. Silent transfer here is account takeover: an
        // attacker who can complete a link for an external identity that already
        // belongs to a victim would otherwise inherit the victim's account.
        return foundation::fail(
            foundation::ErrorCode::Conflict,
            "That account is already connected to a different OpenProof identity.",
            "Refused to transfer an external identity between canonical identities. "
            "Reassignment requires an explicit, separately authorised merge or recovery "
            "operation.");
    }

    m_owners.emplace(link.external(), link.owner());
    return foundation::ok();
}

foundation::Result<std::optional<IdentityId>>
InMemoryExternalIdentityDirectory::ownerOf(const ExternalIdentityRef& external) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_owners.find(external);
    if (position == m_owners.end()) {
        return std::optional<IdentityId>{};
    }
    return std::optional<IdentityId>{position->second};
}

foundation::Status
InMemoryExternalIdentityDirectory::detach(const ExternalIdentityRef& external,
                                          const IdentityId& expectedOwner)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_owners.find(external);
    if (position == m_owners.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "That connected account was not found.");
    }
    if (position->second != expectedOwner) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            "The request was denied.",
            "Refused to detach an external identity owned by a different canonical "
            "identity.");
    }

    m_owners.erase(position);
    return foundation::ok();
}

foundation::Status
InMemoryExternalIdentityDirectory::detachIfAnotherAuthenticationMethod(
    const ExternalIdentityRef& external, const IdentityId& expectedOwner,
    const std::vector<provider::ProviderId>& authenticationProviders)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto position = m_owners.find(external);
    if (position == m_owners.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "That connected account was not found.");
    }
    if (position->second != expectedOwner) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied,
                                "The request was denied.");
    }
    const auto isAuthenticationProvider = [&](const provider::ProviderId& providerId) {
        return std::ranges::find(authenticationProviders, providerId)
            != authenticationProviders.end();
    };
    const auto methods = std::ranges::count_if(m_owners, [&](const auto& entry) {
        return entry.second == expectedOwner
            && isAuthenticationProvider(entry.first.providerId());
    });
    if (methods <= 1) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "The last available sign-in method cannot be disconnected.");
    }
    m_owners.erase(position);
    return foundation::ok();
}

foundation::Status
InMemoryExternalIdentityDirectory::reassign(const ExternalIdentityRef& external,
                                            const IdentityId& expectedCurrentOwner,
                                            const IdentityId& newOwner)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_owners.find(external);
    if (position == m_owners.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "That connected account was not found.");
    }
    if (position->second != expectedCurrentOwner) {
        return foundation::fail(
            foundation::ErrorCode::PermissionDenied,
            "The request was denied.",
            "Refused to reassign an external identity owned by a different canonical "
            "identity. Naming an association is not evidence of controlling it.");
    }

    // A single in-place write, under the same lock that guards ownership. The
    // association is never briefly unowned, which a detach-then-attach pair
    // could not guarantee.
    position->second = newOwner;
    foundation::requireInvariant(m_owners.at(external) == newOwner, "external identity reassignment did not persist new owner");
    return foundation::ok();
}

foundation::Result<std::vector<ExternalIdentityRef>>
InMemoryExternalIdentityDirectory::externalIdentitiesOf(const IdentityId& owner) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    std::vector<ExternalIdentityRef> out;
    for (const auto& entry : m_owners) {
        if (entry.second == owner) {
            out.push_back(entry.first);
        }
    }
    return out;
}

std::size_t InMemoryExternalIdentityDirectory::size() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_owners.size();
}

}
