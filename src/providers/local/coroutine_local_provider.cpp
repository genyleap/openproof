#include <boost/asio/awaitable.hpp>
#include <optional>
#include <string>
#include <utility>
#include "coroutine_local_provider.hpp"
import openproof.security;

namespace openproof::provider::local {
namespace asio = boost::asio;
CoroutineLocalAuthenticationProvider::CoroutineLocalAuthenticationProvider(
    idp::ProviderId id, CoroutineLocalProofVerifier& verifier,
    const foundation::ClockSource& clock, foundation::Duration lifetime)
    : m_id(std::move(id)), m_verifier(verifier), m_clock(clock), m_lifetime(lifetime) {}
idp::ProviderId CoroutineLocalAuthenticationProvider::id() const { return m_id; }
idp::InteractionModel CoroutineLocalAuthenticationProvider::interactionModel() const noexcept
{ return idp::InteractionModel::ChallengeResponse; }
idp::AssuranceLevel CoroutineLocalAuthenticationProvider::maximumClaimableAssurance() const noexcept
{ return idp::AssuranceLevel::Ial2; }
foundation::Result<idp::AuthenticationChallenge>
CoroutineLocalAuthenticationProvider::beginAuthentication(const idp::AuthenticationRequest& request)
{
    const auto found = request.parameters().find("subject");
    if (m_id.empty() || request.provider() != m_id || m_lifetime <= foundation::Duration::zero()
        || found == request.parameters().end()
        || !LocalAccountDirectory::isValidSubject(idp::ExternalSubject{found->second}))
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    auto nonce = security::randomTokenBase64Url(32U);
    if (!nonce) return foundation::fail(nonce.error());
    idp::AuthenticationChallenge challenge{idp::ChallengeId{std::move(nonce).value()},
        m_clock.now() + m_lifetime};
    challenge.setParameter("method", "password_totp");
    return challenge;
}
foundation::Result<idp::AuthenticationOutcome>
CoroutineLocalAuthenticationProvider::completeAuthentication(const idp::AuthenticationResponse&)
{
    return foundation::fail(foundation::ErrorCode::Unavailable);
}
asio::awaitable<foundation::Result<idp::AuthenticationChallenge>>
CoroutineLocalAuthenticationProvider::beginAuthenticationAsync(idp::AuthenticationRequest request)
{
    co_return beginAuthentication(request);
}
asio::awaitable<foundation::Result<idp::AuthenticationOutcome>>
CoroutineLocalAuthenticationProvider::completeAuthenticationAsync(idp::AuthenticationResponse response)
{
    const auto& params = response.parameters();
    const auto subjectIt = params.find("subject");
    const auto passwordIt = params.find("password");
    const auto totpIt = params.find("totp");
    const auto recoveryIt = params.find("recovery_code");
    if (m_id.empty() || subjectIt == params.end() || passwordIt == params.end()
        || passwordIt->second.empty() || passwordIt->second.expose().size() > 1024U
        || (totpIt != params.end() && recoveryIt != params.end())
        || (totpIt != params.end() && totpIt->second.expose().size() > 8U)
        || (recoveryIt != params.end() && recoveryIt->second.expose().size() > 128U))
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    idp::ExternalSubject subject{subjectIt->second.expose()};
    if (!LocalAccountDirectory::isValidSubject(subject))
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    foundation::SecretString password{passwordIt->second.expose()};
    std::optional<foundation::SecretString> totp, recovery;
    if (totpIt != params.end()) totp.emplace(totpIt->second.expose());
    if (recoveryIt != params.end()) recovery.emplace(recoveryIt->second.expose());
    const bool usesRecovery = recovery.has_value();
    const bool usesTotp = totp.has_value();
    const auto now = m_clock.now();
    auto proof = co_await m_verifier.verifyAsync(subject, std::move(password),
        std::move(totp), std::move(recovery), now);
    if (!proof) co_return foundation::fail(proof.error());
    // A verifier may not turn a failed or absent second factor into IAL2.
    if (proof->canonicalOwner.empty() || (proof->verification != LocalVerification::Password
        && proof->verification != LocalVerification::PasswordAndTotp
        && proof->verification != LocalVerification::PasswordAndRecoveryCode)
        || (proof->verification == LocalVerification::PasswordAndRecoveryCode && !usesRecovery)
        || (proof->verification == LocalVerification::PasswordAndTotp && !usesTotp)
        || (usesRecovery && proof->verification != LocalVerification::PasswordAndRecoveryCode))
        co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    idp::ProviderEvidence evidence;
    evidence.add("method", proof->verification == LocalVerification::Password ? "password"
        : proof->verification == LocalVerification::PasswordAndTotp ? "password_totp" : "password_recovery_code");
    const bool multiFactor = proof->verification != LocalVerification::Password;
    co_return idp::AuthenticationOutcome::create(m_id, std::move(subject),
        idp::VerifiedClaims{}, multiFactor ? idp::AssuranceLevel::Ial2 : idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{multiFactor
            ? idp::AuthenticationFactor::Knowledge | idp::AuthenticationFactor::Possession
            : idp::AuthenticationFactor::Knowledge, false}, std::move(evidence), now,
        std::move(proof->canonicalOwner),proof->passwordGeneration);
}
}
