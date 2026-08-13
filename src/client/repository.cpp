module;

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

module openproof.client;

namespace openproof::client {

struct InMemoryClientRepository::Impl final {
    mutable std::mutex mutex;
    std::map<ClientId, std::unique_ptr<Client>> clients;
};

InMemoryClientRepository::InMemoryClientRepository()
    : m_impl(std::make_unique<Impl>())
{
}

InMemoryClientRepository::~InMemoryClientRepository() = default;

foundation::Status InMemoryClientRepository::add(Client client)
{
    std::scoped_lock lock{m_impl->mutex};
    if (m_impl->clients.contains(client.id())) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "The OAuth client already exists.");
    }
    const ClientId id = client.id();
    m_impl->clients.emplace(id, std::make_unique<Client>(std::move(client)));
    return foundation::ok();
}

foundation::Status InMemoryClientRepository::save(const Client& client)
{
    std::scoped_lock lock{m_impl->mutex};
    auto found = m_impl->clients.find(client.id());
    if (found == m_impl->clients.end()) {
        return foundation::fail(foundation::ErrorCode::NotFound);
    }
    if (found->second->applicationId() != client.applicationId()
        || found->second->kind() != client.kind()) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "Immutable client registration fields changed.");
    }
    found->second = std::make_unique<Client>(client);
    return foundation::ok();
}

foundation::Result<std::optional<Client>>
InMemoryClientRepository::findById(const ClientId& id) const
{
    std::scoped_lock lock{m_impl->mutex};
    const auto found = m_impl->clients.find(id);
    if (found == m_impl->clients.end()) return std::optional<Client>{};
    return std::optional<Client>{*found->second};
}

foundation::Result<std::vector<Client>> InMemoryClientRepository::clientsOf(
    const application::ApplicationId& applicationId) const
{
    std::scoped_lock lock{m_impl->mutex};
    std::vector<Client> output;
    for (const auto& [id, client] : m_impl->clients) {
        static_cast<void>(id);
        if (client->applicationId() == applicationId) output.push_back(*client);
    }
    return output;
}

}
