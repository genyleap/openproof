module;

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.consent:model;

import openproof.client;
import openproof.foundation;
import openproof.identity.core;

export namespace openproof::consent {

struct ConsentIdTag {};
using ConsentId = foundation::StrongId<ConsentIdTag>;

/** @brief Remembered end-user authorization grant for one client/resource pair. */
class ConsentGrant final {
public:
    [[nodiscard]] static foundation::Result<ConsentGrant> create(
        ConsentId id, identity::core::IdentityId identity, client::ClientId client,
        std::string audience, std::vector<std::string> scopes,
        foundation::Instant grantedAt, std::optional<foundation::Instant> expiresAt = std::nullopt);
    [[nodiscard]] static foundation::Result<ConsentGrant> restore(
        ConsentId id, identity::core::IdentityId identity, client::ClientId client,
        std::string audience, std::vector<std::string> scopes,
        foundation::Instant grantedAt, std::optional<foundation::Instant> expiresAt,
        std::optional<foundation::Instant> revokedAt);

    [[nodiscard]] const ConsentId& id() const noexcept;
    [[nodiscard]] const identity::core::IdentityId& identity() const noexcept;
    [[nodiscard]] const client::ClientId& client() const noexcept;
    [[nodiscard]] std::string_view audience() const noexcept;
    [[nodiscard]] const std::vector<std::string>& scopes() const noexcept;
    [[nodiscard]] foundation::Instant grantedAt() const noexcept;
    [[nodiscard]] const std::optional<foundation::Instant>& expiresAt() const noexcept;
    [[nodiscard]] const std::optional<foundation::Instant>& revokedAt() const noexcept;
    [[nodiscard]] bool activeAt(foundation::Instant now) const noexcept;
    [[nodiscard]] bool covers(const std::vector<std::string>& scopes) const noexcept;
    void revoke(foundation::Instant now);

private:
    struct State;
    explicit ConsentGrant(std::shared_ptr<State> state);
    std::shared_ptr<State> m_state;
    void detach();
};

}
