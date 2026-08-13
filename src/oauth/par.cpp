module;

#include <array>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

module openproof.oauth;

import openproof.security;

namespace openproof::oauth {
namespace {
[[nodiscard]] std::string key(const PushedRequestDigest& digest)
{
    return foundation::toHex(digest.bytes());
}
}

PushedRequestDigest::PushedRequestDigest(std::array<std::byte, 32> value) noexcept
    : m_value(value) {}
const std::array<std::byte, 32>& PushedRequestDigest::bytes() const noexcept { return m_value; }

struct PushedAuthorizationRequest::State final {
    PushedRequestDigest digest;
    AuthorizationRequest request;
    foundation::Instant issuedAt{};
    foundation::Instant expiresAt{};
};

PushedAuthorizationRequest::PushedAuthorizationRequest(std::shared_ptr<const State> state)
    : m_state(std::move(state)) {}

foundation::Result<PushedAuthorizationRequest> PushedAuthorizationRequest::create(
    PushedRequestDigest digest, AuthorizationRequest request,
    foundation::Instant issuedAt, foundation::Duration lifetime)
{
    if (lifetime <= foundation::Duration::zero()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "PAR lifetime must be positive.");
    }
    return restore(std::move(digest), std::move(request), issuedAt, issuedAt + lifetime);
}

foundation::Result<PushedAuthorizationRequest> PushedAuthorizationRequest::restore(
    PushedRequestDigest digest, AuthorizationRequest request,
    foundation::Instant issuedAt, foundation::Instant expiresAt)
{
    if (expiresAt <= issuedAt) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "PAR timestamps are invalid.");
    }
    return PushedAuthorizationRequest{std::make_shared<State>(State{
        .digest = std::move(digest), .request = std::move(request),
        .issuedAt = issuedAt, .expiresAt = expiresAt})};
}
const PushedRequestDigest& PushedAuthorizationRequest::digest() const noexcept { return m_state->digest; }
const AuthorizationRequest& PushedAuthorizationRequest::request() const noexcept { return m_state->request; }
foundation::Instant PushedAuthorizationRequest::issuedAt() const noexcept { return m_state->issuedAt; }
foundation::Instant PushedAuthorizationRequest::expiresAt() const noexcept { return m_state->expiresAt; }
bool PushedAuthorizationRequest::expiredAt(foundation::Instant now) const noexcept { return now >= m_state->expiresAt; }

struct InMemoryPushedAuthorizationRequestStore::Impl final {
    mutable std::mutex mutex;
    std::map<std::string, PushedAuthorizationRequest, std::less<>> requests;
};
InMemoryPushedAuthorizationRequestStore::InMemoryPushedAuthorizationRequestStore()
    : m_impl(std::make_unique<Impl>()) {}
InMemoryPushedAuthorizationRequestStore::~InMemoryPushedAuthorizationRequestStore() = default;
foundation::Status InMemoryPushedAuthorizationRequestStore::add(PushedAuthorizationRequest request)
{
    std::scoped_lock lock{m_impl->mutex};
    if (!m_impl->requests.emplace(key(request.digest()), std::move(request)).second) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists);
    }
    return foundation::ok();
}
foundation::Result<PushedAuthorizationRequest> InMemoryPushedAuthorizationRequestStore::find(
    const PushedRequestDigest& digest, foundation::Instant now) const
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->requests.find(key(digest));
    if (found == m_impl->requests.end() || found->second.expiredAt(now)) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    return found->second;
}
foundation::Result<PushedAuthorizationRequest> InMemoryPushedAuthorizationRequestStore::consume(
    const PushedRequestDigest& digest, const client::ClientId& expectedClient,
    foundation::Instant now)
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->requests.find(key(digest));
    if (found == m_impl->requests.end() || found->second.expiredAt(now)
        || found->second.request().clientId() != expectedClient) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The pushed authorization request is invalid.");
    }
    auto value = found->second;
    m_impl->requests.erase(found);
    return value;
}

PushedAuthorizationGrant::PushedAuthorizationGrant(
    std::string requestUri, foundation::Duration expiresIn)
    : m_requestUri(std::move(requestUri)), m_expiresIn(expiresIn) {}
std::string_view PushedAuthorizationGrant::requestUri() const noexcept { return m_requestUri; }
foundation::Duration PushedAuthorizationGrant::expiresIn() const noexcept { return m_expiresIn; }

PushedAuthorizationService::PushedAuthorizationService(
    PushedAuthorizationRequestStore& store, const foundation::ClockSource& clock,
    foundation::Duration lifetime)
    : m_store(&store), m_clock(&clock), m_lifetime(lifetime)
{
    foundation::requireInvariant(lifetime > foundation::Duration::zero(),
                                 "PAR lifetime must be positive");
}
foundation::Result<PushedRequestDigest> PushedAuthorizationService::digest(std::string_view requestUri)
{
    auto hashed = security::sha256(requestUri);
    if (!hashed) return foundation::fail(hashed.error());
    return PushedRequestDigest{hashed.value()};
}
foundation::Result<PushedAuthorizationGrant> PushedAuthorizationService::push(
    AuthorizationRequest request)
{
    auto random = security::randomTokenBase64Url(32U);
    if (!random) return foundation::fail(random.error());
    const std::string requestUri =
        "urn:ietf:params:oauth:request_uri:opar_" + random.value();
    auto fingerprint = digest(requestUri);
    if (!fingerprint) return foundation::fail(fingerprint.error());
    auto state = PushedAuthorizationRequest::create(
        fingerprint.value(), std::move(request), m_clock->now(), m_lifetime);
    if (!state) return foundation::fail(state.error());
    auto stored = m_store->add(std::move(state).value());
    if (!stored) return foundation::fail(stored.error());
    return PushedAuthorizationGrant{requestUri, m_lifetime};
}
foundation::Result<AuthorizationRequest> PushedAuthorizationService::find(
    std::string_view requestUri, const client::ClientId& expectedClient) const
{
    auto fingerprint = digest(requestUri);
    if (!fingerprint) return foundation::fail(fingerprint.error());
    auto found = m_store->find(fingerprint.value(), m_clock->now());
    if (!found || found->request().clientId() != expectedClient) {
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "The pushed authorization request is invalid.");
    }
    return found->request();
}
foundation::Result<AuthorizationRequest> PushedAuthorizationService::consume(
    std::string_view requestUri, const client::ClientId& expectedClient)
{
    auto fingerprint = digest(requestUri);
    if (!fingerprint) return foundation::fail(fingerprint.error());
    auto consumed = m_store->consume(fingerprint.value(), expectedClient, m_clock->now());
    if (!consumed) return foundation::fail(consumed.error());
    return consumed->request();
}

}
