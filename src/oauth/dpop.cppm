module;

#include <string_view>

export module openproof.oauth:dpop;

import openproof.foundation;

export namespace openproof::oauth {

/** @brief Durable replay boundary for RFC 9449 DPoP proof identifiers. */
class DpopReplayStore {
public:
    DpopReplayStore(const DpopReplayStore&) = delete;
    DpopReplayStore& operator=(const DpopReplayStore&) = delete;
    virtual ~DpopReplayStore() = default;

    /** Atomically consumes one (JWK thumbprint, jti) proof tuple. */
    [[nodiscard]] virtual foundation::Status consumeDpopReplay(
        std::string_view jwkThumbprint, std::string_view jwtId,
        foundation::Instant expiresAt, foundation::Instant now) = 0;

protected:
    DpopReplayStore() = default;
};

/** @brief Durable replay boundary for authenticated mTLS forwarding assertions. */
class MtlsForwardingReplayStore {
public:
    MtlsForwardingReplayStore(const MtlsForwardingReplayStore&) = delete;
    MtlsForwardingReplayStore& operator=(const MtlsForwardingReplayStore&) = delete;
    virtual ~MtlsForwardingReplayStore() = default;

    [[nodiscard]] virtual foundation::Status consumeMtlsForwardingReplay(
        std::string_view certificateThumbprint, std::string_view nonce,
        foundation::Instant expiresAt, foundation::Instant now) = 0;

protected:
    MtlsForwardingReplayStore() = default;
};

/** @brief Temporal and replay policy for a cryptographically verified DPoP proof. */
class DpopService final {
public:
    DpopService(DpopReplayStore& replays, const foundation::ClockSource& clock,
                foundation::Duration proofLifetime);

    /**
     * @brief Accepts one already-signature-verified proof and consumes its replay identifier.
     * @param jwkThumbprint RFC 7638 thumbprint of the proof key.
     * @param jwtId DPoP jti claim.
     * @param issuedAt DPoP iat claim.
     */
    [[nodiscard]] foundation::Status consume(
        std::string_view jwkThumbprint, std::string_view jwtId,
        foundation::Instant issuedAt);

private:
    DpopReplayStore* m_replays;
    const foundation::ClockSource* m_clock;
    foundation::Duration m_proofLifetime{};
};

}
