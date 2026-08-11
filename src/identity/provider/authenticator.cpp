module;

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

module openproof.identity.provider;

namespace openproof::identity::provider {

std::string_view interactionModelName(InteractionModel model) noexcept
{
    switch (model) {
    case InteractionModel::Redirect:
        return "redirect";
    case InteractionModel::ChallengeResponse:
        return "challenge_response";
    case InteractionModel::OutOfBand:
        return "out_of_band";
    case InteractionModel::Assertion:
        return "assertion";
    case InteractionModel::Delegated:
        return "delegated";
    }
    return "assertion";
}

void ClientContext::setRemoteAddress(std::string value)
{
    m_remoteAddress = std::move(value);
}

void ClientContext::setUserAgent(std::string value)
{
    m_userAgent = std::move(value);
}

std::string_view ClientContext::remoteAddress() const noexcept
{
    return m_remoteAddress;
}

std::string_view ClientContext::userAgent() const noexcept
{
    return m_userAgent;
}

AuthenticationRequest::AuthenticationRequest(ProviderId provider, ClientContext client)
    : m_provider(std::move(provider))
    , m_client(std::move(client))
{
}

const ProviderId& AuthenticationRequest::provider() const noexcept
{
    return m_provider;
}

const ClientContext& AuthenticationRequest::client() const noexcept
{
    return m_client;
}

const std::optional<AssuranceLevel>& AuthenticationRequest::requestedAssurance() const noexcept
{
    return m_requestedAssurance;
}

void AuthenticationRequest::setRequestedAssurance(AssuranceLevel level)
{
    m_requestedAssurance = level;
}

const AttributeMap& AuthenticationRequest::parameters() const noexcept
{
    return m_parameters;
}

void AuthenticationRequest::setParameter(std::string key, std::string value)
{
    m_parameters.insert_or_assign(std::move(key), std::move(value));
}

AuthenticationChallenge::AuthenticationChallenge(ChallengeId id, foundation::Instant expiresAt)
    : m_id(std::move(id))
    , m_expiresAt(expiresAt)
{
}

const ChallengeId& AuthenticationChallenge::id() const noexcept
{
    return m_id;
}

foundation::Instant AuthenticationChallenge::expiresAt() const noexcept
{
    return m_expiresAt;
}

bool AuthenticationChallenge::isExpiredAt(foundation::Instant now) const noexcept
{
    // Expiry is inclusive: a challenge presented exactly at its expiry instant is
    // rejected. The boundary is chosen deliberately in the safe direction.
    return now >= m_expiresAt;
}

const AttributeMap& AuthenticationChallenge::parameters() const noexcept
{
    return m_parameters;
}

void AuthenticationChallenge::setParameter(std::string key, std::string value)
{
    m_parameters.insert_or_assign(std::move(key), std::move(value));
}

AuthenticationResponse::AuthenticationResponse(ChallengeId challengeId, ClientContext client)
    : m_challengeId(std::move(challengeId))
    , m_client(std::move(client))
{
}

const ChallengeId& AuthenticationResponse::challengeId() const noexcept
{
    return m_challengeId;
}

const ClientContext& AuthenticationResponse::client() const noexcept
{
    return m_client;
}

const SecretAttributeMap& AuthenticationResponse::parameters() const noexcept
{
    return m_parameters;
}

void AuthenticationResponse::setParameter(std::string key, foundation::SecretString value)
{
    m_parameters.insert_or_assign(std::move(key), std::move(value));
}

}
