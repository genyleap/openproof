module;

#include <chrono>
#include <string_view>

module openproof.oauth;

namespace openproof::oauth {

DpopService::DpopService(DpopReplayStore& replays, const foundation::ClockSource& clock,
                         foundation::Duration proofLifetime)
    : m_replays(&replays), m_clock(&clock), m_proofLifetime(proofLifetime)
{
}

foundation::Status DpopService::consume(
    std::string_view jwkThumbprint, std::string_view jwtId,
    foundation::Instant issuedAt)
{
    const auto now = m_clock->now();
    constexpr auto clockSkew = std::chrono::seconds{60};
    if (m_proofLifetime <= foundation::Duration::zero()
        || m_proofLifetime > std::chrono::minutes{10}
        || jwkThumbprint.empty() || jwkThumbprint.size() > 128U
        || jwtId.empty() || jwtId.size() > 256U
        || issuedAt > now + clockSkew || issuedAt + m_proofLifetime < now) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP proof is outside the accepted time window.");
    }
    return m_replays->consumeDpopReplay(
        jwkThumbprint, jwtId, issuedAt + m_proofLifetime + clockSkew, now);
}

}
