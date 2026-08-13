module;

#include <memory>
#include <optional>
#include <vector>

export module openproof.client:repository;

import openproof.application;
import openproof.foundation;
import :model;

export namespace openproof::client {

class ClientRepository {
public:
    ClientRepository(const ClientRepository&) = delete;
    ClientRepository& operator=(const ClientRepository&) = delete;
    virtual ~ClientRepository() = default;

    [[nodiscard]] virtual foundation::Status add(Client client) = 0;
    [[nodiscard]] virtual foundation::Status save(const Client& client) = 0;
    [[nodiscard]] virtual foundation::Result<std::optional<Client>>
    findById(const ClientId& id) const = 0;
    [[nodiscard]] virtual foundation::Result<std::vector<Client>>
    clientsOf(const application::ApplicationId& applicationId) const = 0;

protected:
    ClientRepository() = default;
};

class InMemoryClientRepository final : public ClientRepository {
public:
    InMemoryClientRepository();
    ~InMemoryClientRepository() override;
    InMemoryClientRepository(const InMemoryClientRepository&) = delete;
    InMemoryClientRepository& operator=(const InMemoryClientRepository&) = delete;
    InMemoryClientRepository(InMemoryClientRepository&&) = delete;
    InMemoryClientRepository& operator=(InMemoryClientRepository&&) = delete;

    [[nodiscard]] foundation::Status add(Client client) override;
    [[nodiscard]] foundation::Status save(const Client& client) override;
    [[nodiscard]] foundation::Result<std::optional<Client>>
    findById(const ClientId& id) const override;
    [[nodiscard]] foundation::Result<std::vector<Client>>
    clientsOf(const application::ApplicationId& applicationId) const override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}
