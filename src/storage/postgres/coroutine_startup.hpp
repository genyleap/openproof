#pragma once
#include <cstddef>
#include <filesystem>
#include <boost/asio/awaitable.hpp>

import openproof.foundation;
import openproof.security;
import openproof.identity.core;

namespace openproof::storage::postgres {
struct NativeMigrationReport final {
    std::size_t applied{};
    std::size_t alreadyApplied{};
    bool usedBaseline{};
};
[[nodiscard]] boost::asio::awaitable<foundation::Result<NativeMigrationReport>>
migrateSchemaAsync(foundation::SecretString dsn,std::filesystem::path directory,
    foundation::Duration timeout);
// Finite startup boundary; no listener or request worker exists yet.
[[nodiscard]] foundation::Result<NativeMigrationReport> migrateSchemaBeforeListener(
    foundation::SecretString dsn,std::filesystem::path directory);
[[nodiscard]] foundation::Status nativeDatabasePreflight(foundation::SecretString dsn,
    std::filesystem::path directory,identity::core::OrganizationId tenant,
    unsigned int masterVersion,security::Sha256Digest fingerprint);
}
