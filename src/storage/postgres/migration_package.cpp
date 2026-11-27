module;
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

module openproof.storage.migration_package;
import openproof.security;
import openproof.foundation;

namespace openproof::storage::postgres::migration {
foundation::Result<Package> loadPackage(const std::filesystem::path& directory)
{
    std::error_code filesystemError;
    if (!std::filesystem::is_directory(directory, filesystemError) || filesystemError) {
        return foundation::fail(foundation::ErrorCode::NotFound,
                                "The migration directory was not found.");
    }
    std::vector<Migration> migrations;
    // Read and hash each file once. Execute the same bytes that were validated.
    const auto load = [&](const std::filesystem::path& source, bool archived)
        -> foundation::Status {
        if (!std::filesystem::is_directory(source, filesystemError) || filesystemError
            || std::filesystem::is_symlink(source, filesystemError) || filesystemError) {
            return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                    "A migration directory is invalid.");
        }
        std::vector<std::filesystem::path> files;
        for (std::filesystem::directory_iterator iterator{source, filesystemError};
             !filesystemError && iterator != std::filesystem::directory_iterator{};
             iterator.increment(filesystemError)) {
            if (iterator->path().extension() != ".sql") continue;
            if (iterator->is_symlink(filesystemError) || filesystemError
                || !iterator->is_regular_file(filesystemError) || filesystemError) {
                return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                        "A migration artifact is invalid.");
            }
            files.push_back(iterator->path());
        }
        if (filesystemError || files.empty()) {
            return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                    "A migration directory is incomplete.");
        }
        std::ranges::sort(files);
        for (const auto& path : files) {
            std::ifstream stream{path, std::ios::binary};
            std::string sql{std::istreambuf_iterator<char>{stream},
                            std::istreambuf_iterator<char>{}};
            if (!stream.is_open() || stream.bad() || sql.empty()
                || sql.find('\0') != std::string::npos) {
                return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                        "A migration file could not be read.");
            }
            auto checksum = security::sha256(sql);
            if (!checksum) return foundation::fail(checksum.error());
            const auto version = path.filename().string();
            const auto hex = foundation::toHex(checksum.value());
            const auto existing = std::ranges::find_if(migrations,
                [&version](const auto& entry) { return entry.version == version; });
            if (existing != migrations.end()) {
                // In-place upgrades can leave exact historical seeds in root.
                // Never execute them, even if not yet recorded.
                if (!existing->archived || archived || existing->checksum != hex) {
                    return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                            "A historical migration file has changed.");
                }
                continue;
            }
            migrations.push_back(Migration{version, std::move(sql), hex, archived, false});
        }
        return foundation::ok();
    };
    auto archive = load(directory / "legacy", true);
    if (!archive) return foundation::fail(archive.error());
    auto active = load(directory, false);
    if (!active) return foundation::fail(active.error());
    if (std::ranges::none_of(migrations, [](const auto& entry) { return !entry.archived; })) {
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "No executable schema migrations were found.");
    }

    // Optional development baseline. All numbered migrations remain
    // available for upgrades; a baseline must cover their exact current bytes.
    const auto baselineDirectory = directory / "baseline";
    std::optional<std::string> baselineSql;
    const auto baselineStatus = std::filesystem::symlink_status(baselineDirectory, filesystemError);
    if (filesystemError && filesystemError != std::errc::no_such_file_or_directory)
        return foundation::fail(foundation::ErrorCode::FailedPrecondition, "Cannot inspect schema baseline.");
    filesystemError.clear();
    if (baselineStatus.type() != std::filesystem::file_type::not_found) {
        if (!std::filesystem::is_directory(baselineStatus))
            return foundation::fail(foundation::ErrorCode::FailedPrecondition, "Invalid schema baseline directory.");
        const auto readBaseline = [&](const std::filesystem::path& path) -> foundation::Result<std::string> {
            const auto status = std::filesystem::symlink_status(path, filesystemError);
            if (filesystemError || !std::filesystem::is_regular_file(status))
                return foundation::fail(foundation::ErrorCode::FailedPrecondition, "Invalid baseline artifact.");
            std::ifstream stream{path, std::ios::binary};
            std::string bytes{std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
            if (!stream.is_open() || stream.bad() || bytes.empty() || bytes.find('\0') != std::string::npos)
                return foundation::fail(foundation::ErrorCode::FailedPrecondition, "Unreadable baseline artifact.");
            return bytes;
        };
        auto sql = readBaseline(baselineDirectory / "schema.sql");
        auto manifest = readBaseline(baselineDirectory / "checksums.txt");
        if (!sql) return foundation::fail(sql.error());
        if (!manifest) return foundation::fail(manifest.error());
        auto digest = security::sha256(sql.value());
        if (!digest) return foundation::fail(digest.error());
        std::string expected = foundation::toHex(digest.value()) + " schema.sql\n";
        for (const auto& migration : migrations) {
            if (!migration.archived)
                expected += migration.checksum + " " + migration.version + "\n";
        }
        if (manifest.value() != expected)
            return foundation::fail(foundation::ErrorCode::FailedPrecondition, "Schema baseline checksum mismatch.");
        baselineSql.emplace(std::move(sql).value());
    }

    return Package{std::move(migrations),std::move(baselineSql)};
}
}
