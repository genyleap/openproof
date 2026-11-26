module;

#include <chrono>
#include <algorithm>
#include <limits>
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
    auto window=replayWindow(jwkThumbprint,jwtId,issuedAt);
    if (!window) return foundation::fail(window.error());
    return m_replays->consumeDpopReplay(jwkThumbprint,jwtId,window->first,window->second);
}

foundation::Result<std::pair<foundation::Instant,foundation::Instant>>
DpopService::replayWindow(std::string_view jwkThumbprint,std::string_view jwtId,
    foundation::Instant issuedAt) const
{
    const auto now = m_clock->now();
    constexpr auto clockSkew = std::chrono::seconds{60};
    constexpr auto maximum=std::numeric_limits<foundation::Duration::rep>::max()
        -std::chrono::duration_cast<foundation::Duration>(std::chrono::minutes{12}).count();
    if (issuedAt.time_since_epoch().count()<0 || issuedAt.time_since_epoch().count()>maximum
        || now.time_since_epoch().count()<0 || now.time_since_epoch().count()>maximum
        || m_proofLifetime <= foundation::Duration::zero()
        || m_proofLifetime > std::chrono::minutes{10}
        || jwkThumbprint.empty() || jwkThumbprint.size() > 128U
        || jwtId.empty() || jwtId.size() > 256U
        || std::any_of(jwtId.begin(),jwtId.end(),[](char ch){
            const auto byte=static_cast<unsigned char>(ch);
            return byte<0x20U || byte==0x7fU;
        })
        || issuedAt > now + clockSkew || issuedAt + m_proofLifetime < now) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The DPoP proof is outside the accepted time window.");
    }
    return std::pair{issuedAt + m_proofLifetime + clockSkew,now};
}

}
