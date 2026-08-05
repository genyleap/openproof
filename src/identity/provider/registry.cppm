module;

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <shared_mutex>
#include <vector>

export module openproof.identity.provider:registry;

import openproof.foundation;

import :authenticator;
import :outcome;

export namespace openproof::identity::provider {

/**
 * @brief The set of authentication providers this deployment offers.
 *
 * Providers are registered once during composition and then only read, which is
 * why lookup takes a shared lock. The registry owns each provider for the
 * lifetime of the process.
 *
 * Registration rejects a duplicate identifier rather than replacing the existing
 * provider. Silent replacement would let a later, possibly misconfigured,
 * registration take over an identifier that sessions and audit records already
 * refer to.
 *
 * @note Thread-safe.
 */
class ProviderRegistry final {
public:
    ProviderRegistry() = default;

    ProviderRegistry(const ProviderRegistry&) = delete;
    ProviderRegistry& operator=(const ProviderRegistry&) = delete;
    ProviderRegistry(ProviderRegistry&&) = delete;
    ProviderRegistry& operator=(ProviderRegistry&&) = delete;

    ~ProviderRegistry() = default;

    /**
     * @brief Takes ownership of @p provider and registers it under its own identifier.
     * @return ErrorCode::InvalidArgument when @p provider is null or its
     *         identifier is empty; ErrorCode::AlreadyExists when the identifier
     *         is already registered.
     */
    [[nodiscard]] foundation::Status
    registerProvider(std::unique_ptr<AuthenticationProvider> provider);

    /**
     * @brief Looks up a registered provider.
     * @return A non-owning observer pointer, or nullptr when @p id is unknown.
     *         The registry retains ownership; the pointer stays valid as long as
     *         the registry does.
     */
    [[nodiscard]] AuthenticationProvider* find(const ProviderId& id) const;

    /** @brief Returns whether @p id is registered. */
    [[nodiscard]] bool contains(const ProviderId& id) const;

    /** @brief Returns every registered identifier, in identifier order. */
    [[nodiscard]] std::vector<ProviderId> ids() const;

    [[nodiscard]] std::size_t size() const;

private:
    mutable std::shared_mutex m_mutex;
    std::map<ProviderId, std::unique_ptr<AuthenticationProvider>> m_providers;
};

}
