module;

#include <array>
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <string_view>

export module openproof.oauth:par;

import openproof.client;
import openproof.foundation;
import :model;

export namespace openproof::oauth {

/** @brief SHA-256 fingerprint of a high-entropy PAR request URI. */
class PushedRequestDigest final {
public:
    explicit PushedRequestDigest(std::array<std::byte, 32> value) noexcept;
    [[nodiscard]] const std::array<std::byte, 32>& bytes() const noexcept;
    friend bool operator==(const PushedRequestDigest&, const PushedRequestDigest&) noexcept = default;
private:
    std::array<std::byte, 32> m_value{};
};

/** @brief Durable server-side authorization request referenced by a PAR request_uri. */
class PushedAuthorizationRequest final {
public:
    [[nodiscard]] static foundation::Result<PushedAuthorizationRequest> create(
        PushedRequestDigest digest, AuthorizationRequest request,
        foundation::Instant issuedAt, foundation::Duration lifetime);
    [[nodiscard]] static foundation::Result<PushedAuthorizationRequest> restore(
        PushedRequestDigest digest, AuthorizationRequest request,
        foundation::Instant issuedAt, foundation::Instant expiresAt);

    [[nodiscard]] const PushedRequestDigest& digest() const noexcept;
    [[nodiscard]] const AuthorizationRequest& request() const noexcept;
    [[nodiscard]] foundation::Instant issuedAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;
    [[nodiscard]] bool expiredAt(foundation::Instant now) const noexcept;
private:
    struct State;
    explicit PushedAuthorizationRequest(std::shared_ptr<const State> state);
    std::shared_ptr<const State> m_state;
};

/** @brief Atomic persistence boundary for one-time PAR request URIs. */
class PushedAuthorizationRequestStore {
public:
    PushedAuthorizationRequestStore(const PushedAuthorizationRequestStore&) = delete;
    PushedAuthorizationRequestStore& operator=(const PushedAuthorizationRequestStore&) = delete;
    virtual ~PushedAuthorizationRequestStore() = default;
    [[nodiscard]] virtual foundation::Status add(PushedAuthorizationRequest request) = 0;
    [[nodiscard]] virtual foundation::Result<PushedAuthorizationRequest> find(
        const PushedRequestDigest& digest, foundation::Instant now) const = 0;
    [[nodiscard]] virtual foundation::Result<PushedAuthorizationRequest> consume(
        const PushedRequestDigest& digest, const client::ClientId& expectedClient,
        foundation::Instant now) = 0;
protected:
    PushedAuthorizationRequestStore() = default;
};

/** @brief Thread-safe test implementation of PAR storage. */
class InMemoryPushedAuthorizationRequestStore final : public PushedAuthorizationRequestStore {
public:
    InMemoryPushedAuthorizationRequestStore();
    ~InMemoryPushedAuthorizationRequestStore() override;
    [[nodiscard]] foundation::Status add(PushedAuthorizationRequest request) override;
    [[nodiscard]] foundation::Result<PushedAuthorizationRequest> find(
        const PushedRequestDigest& digest, foundation::Instant now) const override;
    [[nodiscard]] foundation::Result<PushedAuthorizationRequest> consume(
        const PushedRequestDigest& digest, const client::ClientId& expectedClient,
        foundation::Instant now) override;
private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

/** @brief Raw request_uri returned once by the PAR endpoint. */
class PushedAuthorizationGrant final {
public:
    PushedAuthorizationGrant(std::string requestUri, foundation::Duration expiresIn);
    [[nodiscard]] std::string_view requestUri() const noexcept;
    [[nodiscard]] foundation::Duration expiresIn() const noexcept;
private:
    std::string m_requestUri;
    foundation::Duration m_expiresIn{};
};

/** @brief RFC 9126 pushed authorization request orchestration. */
class PushedAuthorizationService final {
public:
    PushedAuthorizationService(PushedAuthorizationRequestStore& store,
                               const foundation::ClockSource& clock,
                               foundation::Duration lifetime);
    [[nodiscard]] foundation::Result<PushedAuthorizationGrant> push(
        AuthorizationRequest request);
    [[nodiscard]] foundation::Result<AuthorizationRequest> find(
        std::string_view requestUri, const client::ClientId& expectedClient) const;
    [[nodiscard]] foundation::Result<AuthorizationRequest> consume(
        std::string_view requestUri, const client::ClientId& expectedClient);
private:
    [[nodiscard]] static foundation::Result<PushedRequestDigest> digest(std::string_view requestUri);
    PushedAuthorizationRequestStore* m_store;
    const foundation::ClockSource* m_clock;
    foundation::Duration m_lifetime{};
};

}
