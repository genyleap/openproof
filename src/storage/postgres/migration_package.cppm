module;
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

export module openproof.storage.migration_package;
import openproof.foundation;

export namespace openproof::storage::postgres::migration {
struct Migration final {
    std::string version;
    std::string sql;
    std::string checksum;
    bool archived{};
    bool recorded{};
};
struct Package final {
    std::vector<Migration> migrations;
    std::optional<std::string> baselineSql;
};
[[nodiscard]] foundation::Result<Package> loadPackage(const std::filesystem::path& directory);
}
