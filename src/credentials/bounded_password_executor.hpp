#pragma once
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <memory>
#include <optional>

import openproof.credentials;
import openproof.foundation;

namespace openproof::credentials {

// Password KDFs are CPU/memory-bound, not network I/O. Admit at most two
// operations and execute them on dedicated workers, never the I/O reactor.
// No unbounded queue of passwords. Callers must quiesce before destruction.
class BoundedPasswordExecutor final {
public:
    [[nodiscard]] static foundation::Result<std::unique_ptr<BoundedPasswordExecutor>>
    create(PasswordHasher hasher, std::size_t workers);
    ~BoundedPasswordExecutor();
    BoundedPasswordExecutor(const BoundedPasswordExecutor&) = delete;
    BoundedPasswordExecutor& operator=(const BoundedPasswordExecutor&) = delete;

    // Metadata-only policy inspection: no KDF, no password, no worker admission.
    [[nodiscard]] bool prefersArgon2id() const noexcept;
    [[nodiscard]] foundation::Result<bool> upgradeNeeded(const PasswordHash& hash) const;

    // Unknown accounts use a startup-generated dummy hash and always deny.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<bool>>
    verifyAsync(foundation::SecretString password, std::optional<PasswordHash> expected);
    // Invoke only after full factor validation. Reverify the old password
    // before generating a replacement. Persistence uses a separate CAS.
    [[nodiscard]] boost::asio::awaitable<foundation::Result<std::optional<PasswordHash>>>
    rehashAsync(foundation::SecretString password, PasswordHash verified);
private:
    class Impl;
    explicit BoundedPasswordExecutor(std::unique_ptr<Impl> implementation);
    std::unique_ptr<Impl> m_impl;
};

}
