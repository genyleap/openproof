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
[[nodiscard]] foundation::Status verifyMasterKeyBeforeListener(foundation::SecretString dsn,
    unsigned int masterVersion,security::Sha256Digest fingerprint);
struct NativeMasterRotationReport final {
    std::size_t authenticationTransactions{},sessions{},accountChallenges{},passkeyRegistrations{},
        authorizationCodes{},tokenFamilies{},deviceAuthorizations{},pushedRequests{};
    bool dryRun{};
    [[nodiscard]] std::size_t invalidated() const noexcept {
        return authenticationTransactions+sessions+accountChallenges+passkeyRegistrations+
            authorizationCodes+tokenFamilies+deviceAuthorizations+pushedRequests;
    }
};
[[nodiscard]] foundation::Result<NativeMasterRotationReport> rotateMasterKeyOffline(
    foundation::SecretString dsn,unsigned int currentVersion,security::Sha256Digest currentFingerprint,
    unsigned int replacementVersion,security::Sha256Digest replacementFingerprint,bool dryRun);
struct NativeCredentialRekeyReport final {
    std::size_t rekeyed{},alreadyCurrent{};
    bool dryRun{};
};
[[nodiscard]] foundation::Result<NativeCredentialRekeyReport> rekeyTotpOffline(
    foundation::SecretString dsn,const security::AeadKey& currentKey,unsigned int currentVersion,
    const security::AeadKey& replacementKey,unsigned int replacementVersion,bool dryRun);
[[nodiscard]] foundation::Status nativeDatabasePreflight(foundation::SecretString dsn,
    std::filesystem::path directory,identity::core::OrganizationId tenant,
    unsigned int masterVersion,security::Sha256Digest fingerprint);
}
