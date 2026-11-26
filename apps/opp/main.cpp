// Composition root of the OpenProof Protocol server.
//
// This translation unit is the only place allowed to know how the platform is
// assembled: it reads configuration, constructs the logger, builds the provider
// registry and wires the layers together. Every other unit receives what it
// needs and never reaches for a global.
//
// The `server` subcommand composes and runs the bounded HTTP reverse gateway.

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <charconv>
#include <cctype>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <version>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// Native LDAP's bounded libpq connection channels use a dedicated executor.
// Keep Asio's TLS instantiation in its existing non-module translation unit.
#include <boost/asio/detail/call_stack.hpp>
#include "../../src/gateway/asio_thread_context_extern.hpp"
#include <boost/asio/thread_pool.hpp>
#include <boost/json.hpp>
#include "../../src/storage/postgres/coroutine_auth_transaction_store.hpp"
#include "../../src/storage/postgres/coroutine_canonical_finalizer.hpp"
#include "../../src/storage/postgres/coroutine_session_authenticator.hpp"
#include "../../src/storage/postgres/coroutine_authorization_audit.hpp"
#include "../../src/storage/postgres/coroutine_session_repository.hpp"
#include "../../src/storage/postgres/coroutine_session_service.hpp"
#include "../../src/storage/postgres/coroutine_session_listener.hpp"
#include "../../src/account/http/coroutine_session_http.hpp"
#include "../../src/oauth/http/coroutine_discovery_http.hpp"
#include "../../src/oauth/http/coroutine_consent_http.hpp"
#include "../../src/storage/postgres/coroutine_consent_store.hpp"
#include "../../src/authentication/http/coroutine_provider_catalog_http.hpp"
#include "../../src/authentication/http/coroutine_federated_start_http.hpp"
#include "../../src/authentication/http/coroutine_federated_callback_http.hpp"
#include "../../src/authentication/http/coroutine_admin_read_http.hpp"
#ifdef OPENPROOF_HAS_NATIVE_RECOVERY_HTTP
#include "../../src/authentication/http/coroutine_recovery_code_http.hpp"
#include "../../src/storage/postgres/coroutine_recovery_code_repository.hpp"
#endif

import openproof.account;
import openproof.account.delivery;
import openproof.account.http;
import openproof.administration;
import openproof.administration.http;
import openproof.application;
import openproof.application.http;
import openproof.client;
import openproof.consent;
import openproof.resource;
import openproof.audit;
import openproof.config;
import openproof.authentication;
import openproof.authentication.federated.http;
import openproof.authentication.http;
import openproof.authentication.passkey.http;
import openproof.authentication.web3.http;
import openproof.authentication.enterprise.http;
import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.enterprise.scim;
import openproof.enterprise.scim.http;
import openproof.evidence;
import openproof.evidence.verifiers;
import openproof.evidence.http;
import openproof.trust;
import openproof.identity.provider;
import openproof.observability;
import openproof.oauth;
import openproof.oauth.http;
import openproof.operations.http;
import openproof.oidc;
import openproof.gateway;
import openproof.gateway.http;
import openproof.policy;
import openproof.provider.github;
import openproof.provider.x;
import openproof.provider.local;
import openproof.provider.oidc;
import openproof.provider.passkey;
import openproof.provider.web3;
import openproof.provider.enterprise;
import openproof.security;
import openproof.session;
import openproof.storage.postgres;
import openproof.telemetry;
import openproof.token;

namespace {

namespace fnd = openproof::foundation;
namespace account = openproof::account;
namespace accountDelivery = openproof::account::delivery;
namespace accountHttp = openproof::account::http;
namespace administration = openproof::administration;
namespace adminHttp = openproof::administration::http;
namespace application = openproof::application;
namespace applicationHttp = openproof::application::http;
namespace client = openproof::client;
namespace consent = openproof::consent;
namespace resource = openproof::resource;
namespace audit = openproof::audit;
namespace cfg = openproof::config;
namespace auth = openproof::authentication;
namespace authHttp = openproof::authentication::http;
namespace credentials = openproof::credentials;
namespace obs = openproof::observability;
namespace oauth = openproof::oauth;
namespace oauthHttp = openproof::oauth::http;
namespace operationsHttp = openproof::operations::http;
namespace oidc = openproof::oidc;
namespace identity = openproof::identity::core;
namespace scim = openproof::enterprise::scim;
namespace scimHttp = openproof::enterprise::scim::http;
namespace evidence = openproof::evidence;
namespace evidenceVerification = openproof::evidence::verification;
namespace evidenceHttp = openproof::evidence::http;
namespace trustModel = openproof::trust;
namespace gateway = openproof::gateway;
namespace gatewayHttp = openproof::gateway::http;
namespace policy = openproof::policy;
namespace github = openproof::provider::github;
namespace xProvider = openproof::provider::x;
namespace local = openproof::provider::local;
namespace externalOidc = openproof::provider::oidc;
namespace passkey = openproof::provider::passkey;
namespace web3 = openproof::provider::web3;
namespace enterprise = openproof::provider::enterprise;
namespace security = openproof::security;
namespace session = openproof::session;
namespace postgres = openproof::storage::postgres;
namespace telemetry = openproof::telemetry;
namespace token = openproof::token;
namespace idp = openproof::identity::provider;

// OPENPROOF_VERSION is injected by the build system, which is the only thing that
// knows it. It is bound to a real constant here so that no other code depends
// on a macro (SYN-011).
constexpr std::string_view kVersion = OPENPROOF_VERSION;
constexpr std::string_view kProgramName = "opp";

#if defined(__cpp_pp_embed) && __cpp_pp_embed >= 202502

// C++26 #embed. The default configuration is compiled into the binary, so
// `--print-default-config` emits exactly the defaults this build was made with.
// The alternative -- a copy pasted into documentation, or a file installed
// alongside the binary -- drifts, and a stale "default configuration" for a
// security product is worse than none.
// Embedded as char rather than unsigned char so the view can be constexpr:
// reinterpret_cast is not a constant expression, so an unsigned char array
// would force the conversion to run at startup instead.
//
// This makes default_config.toml ASCII-only by construction. A byte above 0x7f
// becomes a narrowing error in this initializer, which is the right outcome --
// the embedded defaults are parsed as TOML and should stay in the portable
// subset.
constexpr char kDefaultConfigBytes[] = {
#embed "default_config.toml"
};

constexpr std::string_view kDefaultConfig{kDefaultConfigBytes, sizeof(kDefaultConfigBytes)};
constexpr bool kDefaultConfigEmbedded = true;

#else

constexpr std::string_view kDefaultConfig{};
constexpr bool kDefaultConfigEmbedded = false;

#endif

/** @brief Exit codes distinguishing why the process stopped. */
enum class ExitCode : int {
    Success = 0,
    UsageError = 2,
    ConfigurationError = 3,
    InternalError = 70,
};

void reportStartupFailure(const fnd::Error& failure);

[[nodiscard]] int toInt(ExitCode code) noexcept
{
    return static_cast<int>(code);
}

/** @brief Parsed command line. */
class CommandLine final {
public:
    [[nodiscard]] static fnd::Result<CommandLine> parse(std::span<const std::string_view> arguments);

    [[nodiscard]] bool showHelp() const noexcept
    {
        return m_showHelp;
    }

    [[nodiscard]] bool showVersion() const noexcept
    {
        return m_showVersion;
    }

    [[nodiscard]] bool printDefaultConfig() const noexcept
    {
        return m_printDefaultConfig;
    }

    [[nodiscard]] bool runServer() const noexcept { return m_runServer; }
    [[nodiscard]] bool bootstrapAdmin() const noexcept { return m_bootstrapAdmin; }
    [[nodiscard]] bool repairInitialOwner() const noexcept { return m_repairInitialOwner; }
    [[nodiscard]] bool checkConfig() const noexcept { return m_checkConfig; }
    [[nodiscard]] bool rekeyTotp() const noexcept { return m_rekeyTotp; }
    [[nodiscard]] bool rotateMasterKey() const noexcept { return m_rotateMasterKey; }
    [[nodiscard]] bool materializePersistentKeys() const noexcept
    { return m_materializePersistentKeys; }
    [[nodiscard]] bool dryRun() const noexcept { return m_dryRun; }
    [[nodiscard]] bool acknowledgedOffline() const noexcept
    { return m_acknowledgedOffline; }
    [[nodiscard]] bool acknowledgedSecretExport() const noexcept
    { return m_acknowledgedSecretExport; }

    [[nodiscard]] const std::string& newKeyReference() const noexcept
    { return *m_newKeyReference; }
    [[nodiscard]] unsigned int newKeyVersion() const noexcept
    { return *m_newKeyVersion; }
    [[nodiscard]] const std::filesystem::path& outputDirectory() const noexcept
    { return *m_outputDirectory; }

    [[nodiscard]] const std::string& organizationName() const noexcept
    { return *m_organizationName; }
    [[nodiscard]] const std::string& identityId() const noexcept
    { return *m_identityId; }
    [[nodiscard]] const std::string& externalSubject() const noexcept
    { return *m_externalSubject; }

    [[nodiscard]] const std::optional<std::filesystem::path>& configPath() const noexcept
    {
        return m_configPath;
    }

private:
    bool m_showHelp{false};
    bool m_showVersion{false};
    bool m_printDefaultConfig{false};
    bool m_runServer{false};
    bool m_bootstrapAdmin{false};
    bool m_repairInitialOwner{false};
    bool m_checkConfig{false};
    bool m_rekeyTotp{false};
    bool m_rotateMasterKey{false};
    bool m_materializePersistentKeys{false};
    bool m_dryRun{false};
    bool m_acknowledgedOffline{false};
    bool m_acknowledgedSecretExport{false};
    std::optional<std::filesystem::path> m_configPath;
    std::optional<std::string> m_organizationName;
    std::optional<std::string> m_identityId;
    std::optional<std::string> m_externalSubject;
    std::optional<std::string> m_newKeyReference;
    std::optional<unsigned int> m_newKeyVersion;
    std::optional<std::filesystem::path> m_outputDirectory;
};

fnd::Result<CommandLine> CommandLine::parse(std::span<const std::string_view> arguments)
{
    CommandLine parsed;

    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const std::string_view argument = arguments[index];

        if (argument == "server") {
            if (parsed.m_runServer) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "The 'server' subcommand was specified more than once.");
            }
            parsed.m_runServer = true;
        } else if (argument == "bootstrap-admin") {
            if (parsed.m_bootstrapAdmin) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "The 'bootstrap-admin' subcommand was specified more than once.");
            }
            parsed.m_bootstrapAdmin = true;
        } else if (argument == "repair-initial-owner") {
            if (parsed.m_repairInitialOwner) {
                return fnd::fail(
                    fnd::ErrorCode::InvalidArgument,
                    "The 'repair-initial-owner' subcommand was specified more than once.");
            }
            parsed.m_repairInitialOwner = true;
        } else if (argument == "check-config") {
            if (parsed.m_checkConfig) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "The 'check-config' subcommand was specified more than once.");
            }
            parsed.m_checkConfig = true;
        } else if (argument == "rekey-totp") {
            if (parsed.m_rekeyTotp) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "The 'rekey-totp' subcommand was specified more than once.");
            }
            parsed.m_rekeyTotp = true;
        } else if (argument == "rotate-master-key") {
            if (parsed.m_rotateMasterKey) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "The 'rotate-master-key' subcommand was specified more than once.");
            }
            parsed.m_rotateMasterKey = true;
        } else if (argument == "materialize-persistent-keys") {
            if (parsed.m_materializePersistentKeys) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "The 'materialize-persistent-keys' subcommand was specified more than once.");
            }
            parsed.m_materializePersistentKeys = true;
        } else if (argument == "--help" || argument == "-h") {
            parsed.m_showHelp = true;
        } else if (argument == "--version" || argument == "-V") {
            parsed.m_showVersion = true;
        } else if (argument == "--print-default-config") {
            parsed.m_printDefaultConfig = true;
        } else if (argument == "--config" || argument == "-c") {
            if ((index + 1U) >= arguments.size()) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--config' requires a file path.");
            }
            ++index;
            if (parsed.m_configPath.has_value()) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--config' was specified more than once.");
            }
            parsed.m_configPath = std::filesystem::path{arguments[index]};
        } else if (argument == "--organization-name") {
            if ((index + 1U) >= arguments.size() || parsed.m_organizationName.has_value()) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--organization-name' requires one unique value.");
            }
            parsed.m_organizationName = std::string{arguments[++index]};
        } else if (argument == "--identity-id") {
            if ((index + 1U) >= arguments.size() || parsed.m_identityId.has_value()) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--identity-id' requires one unique value.");
            }
            parsed.m_identityId = std::string{arguments[++index]};
        } else if (argument == "--subject") {
            if ((index + 1U) >= arguments.size() || parsed.m_externalSubject.has_value()) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--subject' requires one unique value.");
            }
            parsed.m_externalSubject = std::string{arguments[++index]};
        } else if (argument == "--new-key-ref") {
            if ((index + 1U) >= arguments.size() || parsed.m_newKeyReference.has_value()) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--new-key-ref' requires one unique value.");
            }
            parsed.m_newKeyReference = std::string{arguments[++index]};
        } else if (argument == "--new-key-version") {
            if ((index + 1U) >= arguments.size() || parsed.m_newKeyVersion.has_value()) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--new-key-version' requires one unique value.");
            }
            const std::string_view raw = arguments[++index];
            unsigned int version{};
            const auto converted = std::from_chars(
                raw.data(), raw.data() + raw.size(), version);
            if (converted.ec != std::errc{}
                || converted.ptr != raw.data() + raw.size() || version == 0U) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--new-key-version' must be a positive integer.");
            }
            parsed.m_newKeyVersion = version;
        } else if (argument == "--dry-run") {
            if (parsed.m_dryRun) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--dry-run' was specified more than once.");
            }
            parsed.m_dryRun = true;
        } else if (argument == "--acknowledge-offline") {
            if (parsed.m_acknowledgedOffline) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--acknowledge-offline' was specified more than once.");
            }
            parsed.m_acknowledgedOffline = true;
        } else if (argument == "--output-directory") {
            if ((index + 1U) >= arguments.size() || parsed.m_outputDirectory.has_value()) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--output-directory' requires one unique path.");
            }
            parsed.m_outputDirectory = std::filesystem::path{arguments[++index]};
        } else if (argument == "--acknowledge-secret-export") {
            if (parsed.m_acknowledgedSecretExport) {
                return fnd::fail(fnd::ErrorCode::InvalidArgument,
                                 "Option '--acknowledge-secret-export' was specified more than once.");
            }
            parsed.m_acknowledgedSecretExport = true;
        } else {
            return fnd::fail(fnd::ErrorCode::InvalidArgument,
                             std::string{"Unrecognized option: "} + std::string{argument});
        }
    }

    if (parsed.m_showHelp) return parsed;
    const unsigned subcommandCount = static_cast<unsigned>(parsed.m_runServer)
        + static_cast<unsigned>(parsed.m_bootstrapAdmin)
        + static_cast<unsigned>(parsed.m_repairInitialOwner)
        + static_cast<unsigned>(parsed.m_checkConfig)
        + static_cast<unsigned>(parsed.m_rekeyTotp)
        + static_cast<unsigned>(parsed.m_rotateMasterKey)
        + static_cast<unsigned>(parsed.m_materializePersistentKeys);
    if (subcommandCount > 1U) {
        return fnd::fail(fnd::ErrorCode::InvalidArgument,
                         "Only one subcommand may be selected.");
    }
    const bool hasBootstrapOnlyOption = parsed.m_organizationName.has_value()
        || parsed.m_externalSubject.has_value();
    if (parsed.m_bootstrapAdmin
        && (!parsed.m_configPath.has_value() || !parsed.m_organizationName.has_value()
            || !parsed.m_identityId.has_value()
            || !parsed.m_externalSubject.has_value())) {
        return fnd::fail(
            fnd::ErrorCode::InvalidArgument,
            "bootstrap-admin requires --config, --organization-name, --identity-id and --subject.");
    }
    if (!parsed.m_bootstrapAdmin && hasBootstrapOnlyOption) {
        return fnd::fail(fnd::ErrorCode::InvalidArgument,
                         "Bootstrap-only options require the bootstrap-admin subcommand.");
    }
    if (parsed.m_repairInitialOwner
        && (!parsed.m_configPath.has_value() || !parsed.m_identityId.has_value()
            || !parsed.m_acknowledgedOffline)) {
        return fnd::fail(
            fnd::ErrorCode::InvalidArgument,
            "repair-initial-owner requires --config, --identity-id and --acknowledge-offline.");
    }
    if (parsed.m_identityId.has_value()
        && !parsed.m_bootstrapAdmin && !parsed.m_repairInitialOwner) {
        return fnd::fail(
            fnd::ErrorCode::InvalidArgument,
            "Option '--identity-id' requires bootstrap-admin or repair-initial-owner.");
    }
    const bool hasRekeyOption = parsed.m_newKeyReference.has_value()
        || parsed.m_newKeyVersion.has_value() || parsed.m_dryRun;
    if ((parsed.m_rekeyTotp || parsed.m_rotateMasterKey)
        && (!parsed.m_configPath.has_value() || !parsed.m_newKeyReference.has_value()
            || !parsed.m_newKeyVersion.has_value()
            || (!parsed.m_dryRun && !parsed.m_acknowledgedOffline))) {
        return fnd::fail(
            fnd::ErrorCode::InvalidArgument,
            "Key rotation requires --config, --new-key-ref and --new-key-version; "
            "a committed run also requires --acknowledge-offline.");
    }
    if (parsed.m_dryRun && parsed.m_acknowledgedOffline) {
        return fnd::fail(
            fnd::ErrorCode::InvalidArgument,
            "Options '--dry-run' and '--acknowledge-offline' are mutually exclusive.");
    }
    if (!parsed.m_rekeyTotp && !parsed.m_rotateMasterKey && hasRekeyOption) {
        return fnd::fail(fnd::ErrorCode::InvalidArgument,
                         "Key rotation options require a key-rotation subcommand.");
    }
    if (parsed.m_acknowledgedOffline
        && !parsed.m_rekeyTotp && !parsed.m_rotateMasterKey
        && !parsed.m_repairInitialOwner) {
        return fnd::fail(
            fnd::ErrorCode::InvalidArgument,
            "Option '--acknowledge-offline' requires an offline maintenance subcommand.");
    }
    const bool hasMaterializeOption = parsed.m_outputDirectory.has_value()
        || parsed.m_acknowledgedSecretExport;
    if (parsed.m_materializePersistentKeys
        && (!parsed.m_configPath.has_value() || !parsed.m_outputDirectory.has_value()
            || !parsed.m_acknowledgedSecretExport)) {
        return fnd::fail(
            fnd::ErrorCode::InvalidArgument,
            "materialize-persistent-keys requires --config, --output-directory and --acknowledge-secret-export.");
    }
    if (!parsed.m_materializePersistentKeys && hasMaterializeOption) {
        return fnd::fail(
            fnd::ErrorCode::InvalidArgument,
            "Persistent-key materialization options require the materialize-persistent-keys subcommand.");
    }

    return parsed;
}

void printUsage()
{
    std::println("{} {} - OpenProof Protocol server", kProgramName, kVersion);
    std::println("");
    std::println("Usage:");
    std::println("  {} server [options]", kProgramName);
    std::println("  {} check-config [--config <path>]", kProgramName);
    std::println("  {} rekey-totp --config <path> --new-key-ref <secret-ref>",
                 kProgramName);
    std::println("      --new-key-version <version> [--dry-run | --acknowledge-offline]");
    std::println("  {} rotate-master-key --config <path> --new-key-ref <secret-ref>",
                 kProgramName);
    std::println("      --new-key-version <version> [--dry-run | --acknowledge-offline]");
    std::println("  {} materialize-persistent-keys --config <path>", kProgramName);
    std::println("      --output-directory <empty-dir> --acknowledge-secret-export");
    std::println("  {} bootstrap-admin --config <path> --organization-name <name>",
                 kProgramName);
    std::println("      --identity-id <id> --subject <local-subject>");
    std::println("  {} repair-initial-owner --config <path> --identity-id <id>",
                 kProgramName);
    std::println("      --acknowledge-offline");
    std::println("  {} [--help | --version | --print-default-config]", kProgramName);
    std::println("");
    std::println("Options:");
    std::println("  -c, --config <path>  Load configuration from a TOML file.");
    std::println("                       Without it, configuration comes from the");
    std::println("                       environment and built-in defaults.");
    std::println("  check-config         Validate configuration and secret references without");
    std::println("                       opening a listener or connecting to dependencies.");
    std::println("  rekey-totp           Offline atomic re-encryption of all persisted TOTP seeds.");
    std::println("  rotate-master-key    Offline atomic invalidation of master-derived state.");
    std::println("  repair-initial-owner Recover an incomplete zero-membership bootstrap only.");
    std::println("  materialize-persistent-keys");
    std::println("                       Export legacy-derived persistent subkeys as hex files.");
    std::println("  --new-key-ref        env:, file: or hexfile: reference for replacement key material.");
    std::println("  --new-key-version    Monotonically increasing key version.");
    std::println("  --dry-run            Perform the locked ceremony, then roll back.");
    std::println("  --acknowledge-offline Confirm the server is stopped for committed offline maintenance.");
    std::println("  --output-directory   Existing empty owner-only directory for derived subkeys.");
    std::println("  --acknowledge-secret-export Confirm protected secret material will be written.");
    std::println("  --print-default-config");
    std::println("                       Print the configuration defaults compiled into");
    std::println("                       this binary and exit.");
    std::println("  -h, --help           Show this message and exit.");
    std::println("  -V, --version        Show the version and exit.");
    std::println("  --organization-name  Display name of the initial tenant.");
    std::println("  --identity-id        Canonical id for bootstrap or constrained owner repair.");
    std::println("  --subject            Local login subject; never reused as identity id.");
    std::println("");
    std::println("Environment overrides:");
    std::println("  OPENPROOF_SERVER_BIND_ADDRESS, OPENPROOF_SERVER_PORT,");
    std::println("  OPENPROOF_SERVER_TRUST_PROXY_CLIENT_IP,");
    std::println("  OPENPROOF_LOGGING_LEVEL, OPENPROOF_LOGGING_CONSOLE,");
    std::println("  OPENPROOF_DATABASE_URL");
    std::println("  OPENPROOF_BOOTSTRAP_PASSWORD (bootstrap-admin only; minimum 16 bytes)");
}

volatile std::sig_atomic_t g_shutdownRequested = 0;

extern "C" void requestShutdown(int) noexcept
{
    g_shutdownRequested = 1;
}

class DenyAccess final : public gateway::AccessController {
public:
    [[nodiscard]] policy::AuthorizationDecision authorize(
        const session::AuthenticatedSession&, const gateway::Route&,
        const fnd::CorrelationId&) override
    {
        return policy::AuthorizationDecision::deny(
            "No protected-route policy is configured in this process.");
    }
};

[[nodiscard]] fnd::Status addPublicRoutes(
    gateway::Router& router, std::string_view prefix)
{
    constexpr gateway::HttpMethod methods[] = {
        gateway::HttpMethod::Get, gateway::HttpMethod::Head,
        gateway::HttpMethod::Post, gateway::HttpMethod::Put,
        gateway::HttpMethod::Patch, gateway::HttpMethod::Delete,
        gateway::HttpMethod::Options};
    for (const gateway::HttpMethod method : methods) {
        auto route = gateway::Route::create(
            gateway::RouteId{std::string{"default-"} +
                std::string{gateway::httpMethodName(method)}},
            method, std::string{prefix}, gateway::ServiceId{"default"}, false,
            identity::OrganizationId{}, policy::Action{}, policy::Resource{});
        if (!route.has_value()) return fnd::fail(route.error());
        const fnd::Status added = router.add(std::move(route).value());
        if (!added.has_value()) return fnd::fail(added.error());
    }
    return fnd::ok();
}

[[nodiscard]] fnd::Result<idp::AssuranceLevel>
configuredAssurance(std::string_view value)
{
    if (value == "ial1") return idp::AssuranceLevel::Ial1;
    if (value == "ial2") return idp::AssuranceLevel::Ial2;
    if (value == "ial3") return idp::AssuranceLevel::Ial3;
    if (value == "ial4") return idp::AssuranceLevel::Ial4;
    return fnd::fail(fnd::ErrorCode::InvalidArgument,
                     "The route assurance policy is invalid.");
}

[[nodiscard]] fnd::Result<std::vector<policy::RolePolicyRule>>
addProtectedRoutes(gateway::Router& router,
                   const std::vector<cfg::RoutePolicyConfig>& configured,
                   const identity::OrganizationId& organization)
{
    std::vector<policy::RolePolicyRule> rules;
    std::size_t routeIndex = 0U;
    for (const cfg::RoutePolicyConfig& routePolicy : configured) {
        auto assurance = configuredAssurance(routePolicy.minimumAssurance());
        if (!assurance) return fnd::fail(assurance.error());
        std::vector<policy::Role> requiredRoles;
        requiredRoles.reserve(routePolicy.requiredRoles().size());
        for (const std::string& role : routePolicy.requiredRoles()) {
            requiredRoles.emplace_back(role);
        }
        for (const std::string& methodName : routePolicy.methods()) {
            auto method = gateway::parseHttpMethod(methodName);
            if (!method) return fnd::fail(method.error());
            const std::string actionName = "proxy."
                + std::string{gateway::httpMethodName(method.value())}
                + ":" + std::string{routePolicy.pathPrefix()};
            const std::string resourceName =
                "upstream:" + std::string{routePolicy.pathPrefix()};
            auto route = gateway::Route::create(
                gateway::RouteId{"policy-" + std::to_string(routeIndex++)},
                method.value(), std::string{routePolicy.pathPrefix()},
                gateway::ServiceId{"default"}, true, organization,
                policy::Action{actionName}, policy::Resource{resourceName},
                std::string{routePolicy.requiredScope()},
                std::string{routePolicy.requiredAudience()});
            auto rule = policy::RolePolicyRule::create(
                policy::Action{actionName}, policy::Resource{resourceName},
                requiredRoles,
                routePolicy.roleMatch() == "all"
                    ? policy::RoleMatchMode::All : policy::RoleMatchMode::Any,
                assurance.value());
            if (!route) return fnd::fail(route.error());
            if (!rule) return fnd::fail(rule.error());
            auto added = router.add(std::move(route).value());
            if (!added) return fnd::fail(added.error());
            rules.push_back(std::move(rule).value());
        }
    }
    return rules;
}

[[nodiscard]] fnd::Result<fnd::SecretString> deriveSecret(
    const fnd::SecretString& master, std::string_view label)
{
    auto digest = security::hmacSha256(master, label);
    if (!digest) return fnd::fail(digest.error());
    std::string raw;
    raw.reserve(digest->size());
    for (std::byte value : digest.value()) {
        raw.push_back(static_cast<char>(std::to_integer<unsigned char>(value)));
    }
    return fnd::SecretString{std::move(raw)};
}

[[nodiscard]] fnd::Result<fnd::SecretString> credentialEncryptionMaterial(
    const cfg::SecurityConfig& configuration)
{
    if (!configuration.credentialEncryptionKey().empty()) {
        return configuration.credentialEncryptionKey().clone();
    }
    return deriveSecret(
        configuration.tokenSigningKey(), "openproof/totp-encryption-key/v1");
}

[[nodiscard]] fnd::Result<fnd::SecretString> persistentSecurityMaterial(
    const fnd::SecretString& dedicated, const cfg::SecurityConfig& configuration,
    std::string_view legacyLabel)
{
    if (!dedicated.empty()) return dedicated.clone();
    return deriveSecret(configuration.tokenSigningKey(), legacyLabel);
}

[[nodiscard]] fnd::Result<fnd::SecretString> passwordPepperMaterial(
    const cfg::SecurityConfig& configuration)
{
    return persistentSecurityMaterial(
        configuration.passwordPepper(), configuration,
        "openproof/password-pepper/v1");
}

[[nodiscard]] fnd::Result<fnd::SecretString> recoveryCodePepperMaterial(
    const cfg::SecurityConfig& configuration)
{
    return persistentSecurityMaterial(
        configuration.recoveryCodePepper(), configuration,
        "openproof/recovery-code-pepper/v1");
}

[[nodiscard]] fnd::Result<fnd::SecretString> auditChainMaterial(
    const cfg::SecurityConfig& configuration)
{
    return persistentSecurityMaterial(
        configuration.auditChainKey(), configuration,
        "openproof/audit-chain-key/v1");
}

[[nodiscard]] fnd::Result<fnd::SecretString> oauthClientSecretMaterial(
    const cfg::SecurityConfig& configuration)
{
    return persistentSecurityMaterial(
        configuration.oauthClientSecretKey(), configuration,
        "openproof/oauth-client-secret-key/v1");
}

[[nodiscard]] fnd::Result<security::Sha256Digest> masterKeyFingerprint(
    const cfg::SecurityConfig& configuration)
{
    return security::hmacSha256(
        configuration.tokenSigningKey(),
        "openproof/master-key-fingerprint/v1");
}

[[nodiscard]] fnd::Status verifyActiveMasterKey(
    postgres::ConnectionPool& pool, const cfg::SecurityConfig& configuration)
{
    auto fingerprint = masterKeyFingerprint(configuration);
    if (!fingerprint) return fnd::fail(fingerprint.error());
    postgres::PostgresMasterKeyRotator rotator{pool};
    return rotator.verifyActive(
        configuration.masterKeyVersion(), fingerprint.value());
}

[[nodiscard]] ExitCode runPersistentKeyMaterialization(
    const cfg::PlatformConfig& platform, const CommandLine& commandLine)
{
    const auto& securityConfig = platform.security();
    if (securityConfig.tokenSigningKey().expose().size() < 32U
        || securityConfig.masterKeyVersion() != 1U
        || securityConfig.credentialEncryptionKeyVersion() != 1U) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Persistent-key materialization requires the legacy version-1 master configuration."});
        return ExitCode::ConfigurationError;
    }
    if (securityConfig.hasDedicatedPersistentKeys()
        || !securityConfig.credentialEncryptionKey().empty()
        || !securityConfig.passwordPepper().empty()
        || !securityConfig.recoveryCodePepper().empty()
        || !securityConfig.auditChainKey().empty()
        || !securityConfig.oauthClientSecretKey().empty()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Persistent-key materialization refuses a mixed or already dedicated key configuration."});
        return ExitCode::ConfigurationError;
    }

    const std::filesystem::path& directory = commandLine.outputDirectory();
    std::error_code filesystemError;
    const auto directoryStatus = std::filesystem::symlink_status(directory, filesystemError);
    if (filesystemError || std::filesystem::is_symlink(directoryStatus)
        || !std::filesystem::is_directory(directoryStatus)) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "The persistent-key output path must be an existing real directory."});
        return ExitCode::UsageError;
    }
    struct stat metadata {};
    if (::stat(directory.c_str(), &metadata) != 0 || !S_ISDIR(metadata.st_mode)
        || metadata.st_uid != ::geteuid() || (metadata.st_mode & 0077) != 0) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::PermissionDenied,
            "The persistent-key output directory must be owned by this user and inaccessible to group/other."});
        return ExitCode::ConfigurationError;
    }
    if (!std::filesystem::is_empty(directory, filesystemError) || filesystemError) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "The persistent-key output directory must be empty."});
        return ExitCode::ConfigurationError;
    }

    struct DerivedFile final {
        std::string_view name;
        std::string_view label;
    };
    constexpr std::array<DerivedFile, 5> files{{
        {"credential-encryption.key", "openproof/totp-encryption-key/v1"},
        {"password-pepper.key", "openproof/password-pepper/v1"},
        {"recovery-code-pepper.key", "openproof/recovery-code-pepper/v1"},
        {"audit-chain.key", "openproof/audit-chain-key/v1"},
        {"oauth-client-secret.key", "openproof/oauth-client-secret-key/v1"},
    }};
    std::vector<std::filesystem::path> created;
    const auto cleanup = [&created] {
        for (auto iterator = created.rbegin(); iterator != created.rend(); ++iterator) {
            std::error_code ignored;
            std::filesystem::remove(*iterator, ignored);
        }
    };
    for (const DerivedFile& file : files) {
        auto material = security::hmacSha256(
            securityConfig.tokenSigningKey(), file.label);
        if (!material) {
            cleanup();
            reportStartupFailure(material.error());
            return ExitCode::InternalError;
        }
        const std::string encoded = fnd::toHex(material.value());
        const std::filesystem::path target = directory / file.name;
        const int descriptor = ::open(
            target.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR);
        if (descriptor < 0) {
            cleanup();
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::Unavailable,
                "A persistent-key output file could not be created."});
            return ExitCode::ConfigurationError;
        }
        created.push_back(target);
        std::size_t offset = 0U;
        bool written = true;
        while (offset < encoded.size()) {
            const ssize_t count = ::write(
                descriptor, encoded.data() + offset, encoded.size() - offset);
            if (count <= 0) {
                written = false;
                break;
            }
            offset += static_cast<std::size_t>(count);
        }
        const bool synced = written && ::fsync(descriptor) == 0;
        const bool closed = ::close(descriptor) == 0;
        if (!written || !synced || !closed) {
            cleanup();
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::Unavailable,
                "A persistent-key output file could not be committed."});
            return ExitCode::ConfigurationError;
        }
    }
    const int directoryDescriptor = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY);
    if (directoryDescriptor < 0) {
        cleanup();
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::Unavailable,
            "The persistent-key output directory could not be committed."});
        return ExitCode::ConfigurationError;
    }
    const bool directorySynced = ::fsync(directoryDescriptor) == 0;
    const bool directoryClosed = ::close(directoryDescriptor) == 0;
    if (!directorySynced || !directoryClosed) {
        cleanup();
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::Unavailable,
            "The persistent-key output directory could not be committed."});
        return ExitCode::ConfigurationError;
    }
    std::println(
        "Materialized 5 legacy-compatible persistent subkeys in {}.",
        directory.string());
    std::println(
        "Reference each file with hexfile: and run opp check-config before restart; "
        "the master key itself was not exported.");
    return ExitCode::Success;
}

[[nodiscard]] fnd::Result<std::vector<oidc::PublishedVerificationJwk>> loadPreviousOidcKeys(
    std::string_view directory, std::string_view activeKeyId)
{
    if (directory.empty()) return std::vector<oidc::PublishedVerificationJwk>{};
    const std::filesystem::path root{directory};
    std::error_code error;
    if (!std::filesystem::is_directory(root, error) || error) {
        return fnd::fail(fnd::ErrorCode::InvalidArgument,
                         "The previous OIDC signing-key directory is invalid.");
    }
    std::vector<std::filesystem::path> paths;
    for (std::filesystem::directory_iterator iterator{root, error}, end;
         !error && iterator != end; iterator.increment(error)) {
        const auto status = iterator->symlink_status(error);
        if (error) break;
        if (std::filesystem::is_symlink(status)) {
            return fnd::fail(fnd::ErrorCode::InvalidArgument,
                             "Previous OIDC key entries cannot be symbolic links.");
        }
        if (std::filesystem::is_regular_file(status)
            && iterator->path().extension() == ".pem") {
            paths.push_back(iterator->path());
        }
    }
    if (error || paths.size() > 8U) {
        return fnd::fail(fnd::ErrorCode::InvalidArgument,
                         "The previous OIDC signing-key directory cannot be enumerated.");
    }
    std::ranges::sort(paths);
    std::set<std::string, std::less<>> keyIds;
    std::vector<oidc::PublishedVerificationJwk> jwks;
    jwks.reserve(paths.size());
    for (const auto& path : paths) {
        const std::string keyId = path.stem().string();
        const bool validKeyId = !keyId.empty() && keyId.size() <= 128U
            && std::ranges::all_of(keyId, [](const char value) {
                   const auto byte = static_cast<unsigned char>(value);
                   return std::isalnum(byte) != 0 || value == '-' || value == '_' || value == '.';
               });
        const auto size = std::filesystem::file_size(path, error);
        if (!validKeyId || keyId == activeKeyId || !keyIds.emplace(keyId).second
            || error || size == 0U || size > 64U * 1024U) {
            return fnd::fail(fnd::ErrorCode::InvalidArgument,
                             "A previous OIDC verification key entry is invalid.");
        }
        std::ifstream input{path, std::ios::binary};
        std::string pem(static_cast<std::size_t>(size), '\0');
        input.read(pem.data(), static_cast<std::streamsize>(pem.size()));
        if (!input || input.gcount() != static_cast<std::streamsize>(pem.size())) {
            return fnd::fail(fnd::ErrorCode::InvalidArgument,
                             "A previous OIDC verification key cannot be read.");
        }
        auto jwk = oidc::PublishedVerificationJwk::create(pem, keyId);
        if (!jwk) return fnd::fail(jwk.error());
        jwks.push_back(std::move(jwk).value());
    }
    return jwks;
}

[[nodiscard]] ExitCode runTotpRekey(
    const cfg::PlatformConfig& platform, const cfg::Environment& environment,
    const CommandLine& commandLine)
{
    if (!platform.database().enabled()
        || (platform.security().credentialEncryptionKey().empty()
            && platform.security().tokenSigningKey().expose().size() < 32U)) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "rekey-totp requires PostgreSQL and either the dedicated credential key "
            "or the legacy master key used to derive it."});
        return ExitCode::ConfigurationError;
    }
    if (commandLine.newKeyVersion()
        <= platform.security().credentialEncryptionKeyVersion()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "The replacement credential key version must be greater than the active version."});
        return ExitCode::UsageError;
    }
    auto replacementMaterial = cfg::resolveSecretReference(
        commandLine.newKeyReference(), environment);
    if (!replacementMaterial) {
        reportStartupFailure(replacementMaterial.error());
        return ExitCode::ConfigurationError;
    }
    auto currentMaterial = credentialEncryptionMaterial(platform.security());
    if (!currentMaterial) {
        reportStartupFailure(currentMaterial.error());
        return ExitCode::ConfigurationError;
    }
    auto currentKey = security::AeadKey::create(
        std::move(currentMaterial).value());
    auto replacementKey = security::AeadKey::create(
        std::move(replacementMaterial).value());
    if (!currentKey || !replacementKey) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "Credential encryption keys must contain exactly 32 bytes."});
        return ExitCode::ConfigurationError;
    }
    if (currentKey->matches(replacementKey.value())) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "The replacement credential key must use different key material."});
        return ExitCode::ConfigurationError;
    }

    auto poolConfig = postgres::PoolConfig::create(
        platform.database().connectionString().clone(), platform.database().poolSize(),
        std::chrono::seconds{5});
    if (!poolConfig) {
        reportStartupFailure(poolConfig.error());
        return ExitCode::ConfigurationError;
    }
    auto pool = postgres::ConnectionPool::create(std::move(poolConfig).value());
    if (!pool) {
        reportStartupFailure(pool.error());
        return ExitCode::ConfigurationError;
    }
    postgres::Migrator migrator{*pool.value()};
    auto migrations = migrator.applyDirectory(platform.database().migrationDirectory());
    if (!migrations) {
        reportStartupFailure(migrations.error());
        return ExitCode::ConfigurationError;
    }
    const fnd::Status activeMaster = verifyActiveMasterKey(
        *pool.value(), platform.security());
    if (!activeMaster) {
        reportStartupFailure(activeMaster.error());
        return ExitCode::ConfigurationError;
    }
    postgres::PostgresCredentialRekeyer rekeyer{*pool.value()};
    auto report = rekeyer.rotateTotp(
        currentKey.value(), platform.security().credentialEncryptionKeyVersion(),
        replacementKey.value(), commandLine.newKeyVersion(), commandLine.dryRun());
    if (!report) {
        reportStartupFailure(report.error());
        return ExitCode::InternalError;
    }
    std::println(
        "TOTP credential rekey {}: {} row(s) re-encrypted, {} already current.",
        report->dryRun ? "dry run passed" : "committed",
        report->rekeyed, report->alreadyCurrent);
    if (!report->dryRun) {
        std::println(
            "Before restarting OpenProof, update credential_encryption_key and "
            "credential_encryption_key_version to the replacement values.");
    }
    return ExitCode::Success;
}

[[nodiscard]] ExitCode runMasterKeyRotation(
    const cfg::PlatformConfig& platform, const cfg::Environment& environment,
    const CommandLine& commandLine)
{
    const auto& securityConfig = platform.security();
    if (!platform.database().enabled()
        || securityConfig.tokenSigningKey().expose().size() < 32U) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "rotate-master-key requires PostgreSQL and an active master key of at least 32 bytes."});
        return ExitCode::ConfigurationError;
    }
    if (!securityConfig.hasDedicatedPersistentKeys()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Master-key rotation requires explicit credential, password, recovery, audit and OAuth client-secret keys."});
        return ExitCode::ConfigurationError;
    }
    if (commandLine.newKeyVersion() <= securityConfig.masterKeyVersion()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "The replacement master key version must be greater than the active version."});
        return ExitCode::UsageError;
    }
    auto replacement = cfg::resolveSecretReference(
        commandLine.newKeyReference(), environment);
    if (!replacement) {
        reportStartupFailure(replacement.error());
        return ExitCode::ConfigurationError;
    }
    if (replacement->expose().size() < 32U) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "The replacement master key must contain at least 32 bytes."});
        return ExitCode::ConfigurationError;
    }
    auto currentFingerprint = masterKeyFingerprint(securityConfig);
    auto replacementFingerprint = security::hmacSha256(
        replacement.value(), "openproof/master-key-fingerprint/v1");
    if (!currentFingerprint || !replacementFingerprint) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    if (security::constantTimeEquals(
            currentFingerprint.value(), replacementFingerprint.value())) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "The replacement master key must use different key material."});
        return ExitCode::ConfigurationError;
    }
    auto poolConfig = postgres::PoolConfig::create(
        platform.database().connectionString().clone(), platform.database().poolSize(),
        std::chrono::seconds{5});
    if (!poolConfig) {
        reportStartupFailure(poolConfig.error());
        return ExitCode::ConfigurationError;
    }
    auto pool = postgres::ConnectionPool::create(std::move(poolConfig).value());
    if (!pool) {
        reportStartupFailure(pool.error());
        return ExitCode::ConfigurationError;
    }
    postgres::Migrator migrator{*pool.value()};
    auto migrations = migrator.applyDirectory(platform.database().migrationDirectory());
    if (!migrations) {
        reportStartupFailure(migrations.error());
        return ExitCode::ConfigurationError;
    }
    postgres::PostgresMasterKeyRotator rotator{*pool.value()};
    const fnd::Status activeMaster = rotator.verifyActive(
        securityConfig.masterKeyVersion(), currentFingerprint.value());
    if (!activeMaster) {
        reportStartupFailure(activeMaster.error());
        return ExitCode::ConfigurationError;
    }
    auto report = rotator.rotate(
        securityConfig.masterKeyVersion(), currentFingerprint.value(),
        commandLine.newKeyVersion(), replacementFingerprint.value(),
        commandLine.dryRun());
    if (!report) {
        reportStartupFailure(report.error());
        return ExitCode::InternalError;
    }
    std::println(
        "Master key rotation {}: {} state row(s) invalidated "
        "(transactions={}, sessions={}, account_challenges={}, passkey_registrations={}, authorization_codes={}, "
        "token_families={}, device_authorizations={}, pushed_requests={}).",
        report->dryRun ? "dry run passed" : "committed", report->invalidated(),
        report->authenticationTransactions, report->sessions,
        report->accountChallenges, report->passkeyRegistrations,
        report->authorizationCodes,
        report->tokenFamilies, report->deviceAuthorizations,
        report->pushedRequests);
    if (!report->dryRun) {
        std::println(
            "Before restarting OpenProof, update token_signing_key and "
            "master_key_version to the replacement values; keep every dedicated "
            "persistent key unchanged.");
    }
    return ExitCode::Success;
}

[[nodiscard]] ExitCode runBootstrapAdmin(
    const cfg::PlatformConfig& platform, const cfg::Environment& environment,
    const CommandLine& commandLine, const fnd::ClockSource& clock)
{
    if (!platform.auth().enabled() || !platform.database().enabled()
        || platform.security().tokenSigningKey().expose().size() < 32U) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "bootstrap-admin requires enabled auth, PostgreSQL and a master key of at least 32 bytes."});
        return ExitCode::ConfigurationError;
    }
    const auto password = environment.get("OPENPROOF_BOOTSTRAP_PASSWORD");
    if (!password.has_value()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "OPENPROOF_BOOTSTRAP_PASSWORD is required by bootstrap-admin."});
        return ExitCode::ConfigurationError;
    }

    auto poolConfig = postgres::PoolConfig::create(
        platform.database().connectionString().clone(), platform.database().poolSize(),
        std::chrono::seconds{5});
    if (!poolConfig) {
        reportStartupFailure(poolConfig.error());
        return ExitCode::ConfigurationError;
    }
    auto pool = postgres::ConnectionPool::create(std::move(poolConfig).value());
    if (!pool) {
        reportStartupFailure(pool.error());
        return ExitCode::ConfigurationError;
    }
    postgres::Migrator migrator{*pool.value()};
    auto migrations = migrator.applyDirectory(platform.database().migrationDirectory());
    if (!migrations) {
        reportStartupFailure(migrations.error());
        return ExitCode::ConfigurationError;
    }
    const fnd::Status activeMaster = verifyActiveMasterKey(
        *pool.value(), platform.security());
    if (!activeMaster) {
        reportStartupFailure(activeMaster.error());
        return ExitCode::ConfigurationError;
    }

    auto passwordSecret = passwordPepperMaterial(platform.security());
    auto totpSecret = credentialEncryptionMaterial(platform.security());
    auto auditSecret = auditChainMaterial(platform.security());
    if (!passwordSecret || !totpSecret || !auditSecret) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    auto passwordHasher = credentials::PasswordHasher::create(
        std::move(passwordSecret).value(), credentials::PasswordPolicy::recommended(),
        std::string{platform.security().passwordHashAlgorithm()});
    auto totpKey = security::AeadKey::create(std::move(totpSecret).value());
    auto auditKey = audit::AuditKey::create(std::move(auditSecret).value());
    auto generatedTotp = credentials::TotpSecret::generate();
    if (!passwordHasher || !totpKey || !auditKey || !generatedTotp) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }

    auto administrator = administration::InitialAdministrator::create(
        identity::OrganizationId{std::string{platform.auth().organizationId()}},
        commandLine.organizationName(),
        identity::IdentityId{commandLine.identityId()},
        idp::ProviderId{std::string{platform.auth().providerId()}},
        idp::ExternalSubject{commandLine.externalSubject()},
        fnd::SecretString{*password}, std::move(generatedTotp).value(), clock.now());
    if (!administrator) {
        reportStartupFailure(administrator.error());
        return ExitCode::ConfigurationError;
    }
    auto repository = postgres::PostgresAdministrationRepository::create(
        *pool.value(), std::move(passwordHasher).value(),
        std::move(totpKey).value(),
        platform.security().credentialEncryptionKeyVersion(),
        idp::ProviderId{std::string{platform.auth().providerId()}},
        std::move(auditKey).value());
    if (!repository) {
        reportStartupFailure(repository.error());
        return ExitCode::InternalError;
    }
    const fnd::Status initialized = repository.value()->initialize(administrator.value());
    if (!initialized) {
        reportStartupFailure(initialized.error());
        return initialized.error().code() == fnd::ErrorCode::AlreadyExists
            ? ExitCode::UsageError : ExitCode::InternalError;
    }

    const fnd::SecretString enrollment = administrator->totp().enrollmentBase32();
    std::println("Initial administrator created for organization '{}'.",
                 platform.auth().organizationId());
    std::println("TOTP secret (Base32; shown once): {}", enrollment.expose());
    std::println("Store this secret in the owner's authenticator before starting the server.");
    return ExitCode::Success;
}

[[nodiscard]] ExitCode runRepairInitialOwner(
    const cfg::PlatformConfig& platform, const CommandLine& commandLine,
    const fnd::ClockSource& clock)
{
    if (!platform.auth().enabled() || !platform.database().enabled()
        || platform.security().tokenSigningKey().expose().size() < 32U) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "repair-initial-owner requires enabled auth, PostgreSQL and configured security keys."});
        return ExitCode::ConfigurationError;
    }

    auto poolConfig = postgres::PoolConfig::create(
        platform.database().connectionString().clone(), platform.database().poolSize(),
        std::chrono::seconds{5});
    if (!poolConfig) {
        reportStartupFailure(poolConfig.error());
        return ExitCode::ConfigurationError;
    }
    auto pool = postgres::ConnectionPool::create(std::move(poolConfig).value());
    if (!pool) {
        reportStartupFailure(pool.error());
        return ExitCode::ConfigurationError;
    }
    postgres::Migrator migrator{*pool.value()};
    auto migrations = migrator.applyDirectory(platform.database().migrationDirectory());
    if (!migrations) {
        reportStartupFailure(migrations.error());
        return ExitCode::ConfigurationError;
    }
    const fnd::Status activeMaster =
        verifyActiveMasterKey(*pool.value(), platform.security());
    if (!activeMaster) {
        reportStartupFailure(activeMaster.error());
        return ExitCode::ConfigurationError;
    }

    auto passwordSecret = passwordPepperMaterial(platform.security());
    auto totpSecret = credentialEncryptionMaterial(platform.security());
    auto auditSecret = auditChainMaterial(platform.security());
    if (!passwordSecret || !totpSecret || !auditSecret) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    auto passwordHasher = credentials::PasswordHasher::create(
        std::move(passwordSecret).value(), credentials::PasswordPolicy::recommended(),
        std::string{platform.security().passwordHashAlgorithm()});
    auto totpKey = security::AeadKey::create(std::move(totpSecret).value());
    auto auditKey = audit::AuditKey::create(std::move(auditSecret).value());
    if (!passwordHasher || !totpKey || !auditKey) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }

    auto repository = postgres::PostgresAdministrationRepository::create(
        *pool.value(), std::move(passwordHasher).value(),
        std::move(totpKey).value(),
        platform.security().credentialEncryptionKeyVersion(),
        idp::ProviderId{std::string{platform.auth().providerId()}},
        std::move(auditKey).value());
    if (!repository) {
        reportStartupFailure(repository.error());
        return ExitCode::InternalError;
    }

    const fnd::Status repaired = repository.value()->repairInitialOwnerMembership(
        identity::OrganizationId{std::string{platform.auth().organizationId()}},
        identity::IdentityId{commandLine.identityId()}, clock.now());
    if (!repaired) {
        reportStartupFailure(repaired.error());
        return repaired.error().code() == fnd::ErrorCode::FailedPrecondition
            || repaired.error().code() == fnd::ErrorCode::AssuranceInsufficient
            ? ExitCode::UsageError : ExitCode::InternalError;
    }

    std::println(
        "Initial-owner membership repaired for identity '{}' in organization '{}'.",
        commandLine.identityId(), platform.auth().organizationId());
    return ExitCode::Success;
}

[[nodiscard]] ExitCode runListener(const cfg::PlatformConfig& platform,
                                   gateway::HttpHandler& handler,
                                   const obs::Logger& logger)
{
    const unsigned int detected = std::thread::hardware_concurrency();
    const std::size_t workers = std::clamp<std::size_t>(
        detected == 0U ? 2U : static_cast<std::size_t>(detected), 2U, 32U);
    auto serverConfig = gatewayHttp::ServerConfig::create(
        std::string{platform.server().bindAddress()}, platform.server().port(),
        64U * 1024U, 8U * 1024U * 1024U, std::chrono::seconds{15},
        std::chrono::seconds{15}, 4'096U, workers,
        platform.server().trustProxyClientIp());
    if (!serverConfig) {
        reportStartupFailure(serverConfig.error());
        return ExitCode::ConfigurationError;
    }
    std::unique_ptr<telemetry::MetricRegistry> metrics;
    std::unique_ptr<operationsHttp::MetricsHttpApi> metricsApi;
    std::unique_ptr<gatewayHttp::CoroutineMetricsAdapter> asyncMetricsApi;
    gateway::HttpHandler* listenerHandler = &handler;
    if (platform.operations().metricsEnabled()) {
        metrics = std::make_unique<telemetry::MetricRegistry>(
            platform.operations().metricsMaximumSeries());
        static_cast<void>(metrics->increment(
            "openproof_process_starts_total", {{"version", std::string{kVersion}}}));
        metricsApi = std::make_unique<operationsHttp::MetricsHttpApi>(
            *metrics, platform.operations().metricsBearerToken().clone(), handler);
        listenerHandler = metricsApi.get();
        if (auto* asyncFallback =
                dynamic_cast<gatewayHttp::CoroutineHttpHandler*>(&handler)) {
            // Metrics is still authenticated by the original facade; all
            // non-metrics Gateway requests retain their coroutine transport
            // and the same low-cardinality request instrumentation.
            asyncMetricsApi = std::make_unique<gatewayHttp::CoroutineMetricsAdapter>(
                *metricsApi, *asyncFallback,
                [observer = metricsApi.get()](
                    gateway::HttpMethod method, int status, double elapsed) noexcept {
                    observer->observeAsyncResponse(method, status, elapsed);
                });
            listenerHandler = asyncMetricsApi.get();
        }
    }
    gatewayHttp::BeastHttpServer server{
        *listenerHandler, std::move(serverConfig).value()};
    const fnd::Status started = server.start();
    if (!started) {
        reportStartupFailure(started.error());
        return ExitCode::InternalError;
    }
    const std::vector<obs::LogField> listenerFields{
        obs::LogField::integer("bound_port", static_cast<std::int64_t>(server.boundPort())),
        obs::LogField::text("upstream_host", std::string{platform.gateway().upstreamHost()}),
        obs::LogField::boolean("upstream_tls", platform.gateway().upstreamTls()),
        obs::LogField::boolean("authentication_enabled", platform.auth().enabled()),
        obs::LogField::boolean(
            "metrics_enabled", platform.operations().metricsEnabled())};
    logger.info("openproof gateway listener started", listenerFields);
    g_shutdownRequested = 0;
    std::signal(SIGINT, requestShutdown);
    std::signal(SIGTERM, requestShutdown);
    while (g_shutdownRequested == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    server.stop();
    logger.info("openproof gateway listener stopped");
    return ExitCode::Success;
}

[[nodiscard]] ExitCode runGatewayServer(const cfg::PlatformConfig& platform,
                                        const cfg::Environment& environment,
                                        const fnd::ClockSource& clock,
                                        const obs::Logger& logger)
{
    const fnd::Status deployment = platform.validateServerDeployment();
    if (!deployment.has_value()) {
        reportStartupFailure(deployment.error());
        return ExitCode::ConfigurationError;
    }

    // Validate the experimental flag before opening any database connection
    // or applying migrations. An invalid opt-in must be side-effect-free.
    const auto nativeProtectedGatewayFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_PROTECTED_GATEWAY");
    if (nativeProtectedGatewayFlag && *nativeProtectedGatewayFlag != "0"
        && *nativeProtectedGatewayFlag != "1") {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_PROTECTED_GATEWAY must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeProtectedGatewayEnabled =
        nativeProtectedGatewayFlag && *nativeProtectedGatewayFlag == "1";
    if (nativeProtectedGatewayEnabled
        && (!platform.auth().enabled() || platform.oidc().enabled())) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
            "Native protected gateway requires authentication without delegated OIDC."});
        return ExitCode::ConfigurationError;
    }
    const auto nativeLdapFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_LDAP");
    if (nativeLdapFlag && *nativeLdapFlag != "0" && *nativeLdapFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_LDAP must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeLdapEnabled =
        nativeLdapFlag && *nativeLdapFlag == "1";
    // Account session management must not depend on whether enterprise LDAP
    // is configured. Keep its native SQL path independently opt-in until
    // compiled listener and disposable-PostgreSQL acceptance is complete.
    const auto nativeAccountFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_SESSIONS");
    if (nativeAccountFlag && *nativeAccountFlag != "0"
        && *nativeAccountFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_SESSIONS must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeAccountEnabled =
        nativeAccountFlag && *nativeAccountFlag == "1";
    // Profile reads use the same native session authority and a separately
    // tenant-scoped coroutine profile reader. Opt in explicitly; enabling
    // session management alone must not migrate another account route.
    const auto nativeAccountProfileFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_PROFILE");
    if (nativeAccountProfileFlag && *nativeAccountProfileFlag != "0"
        && *nativeAccountProfileFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_PROFILE must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeAccountProfileEnabled =
        nativeAccountProfileFlag && *nativeAccountProfileFlag == "1";
    if (nativeAccountProfileEnabled
        && (!nativeAccountEnabled || !platform.account().enabled())) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Native account profile requires enabled account sessions and account API."});
        return ExitCode::ConfigurationError;
    }
    // Read-only connection enumeration is separately gated. It may share
    // the active tenant canonical reader with profile but never enables
    // identity creation, linking or connection mutation.
    const auto nativeAccountConnectionsFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_CONNECTIONS");
    if (nativeAccountConnectionsFlag && *nativeAccountConnectionsFlag != "0"
        && *nativeAccountConnectionsFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_CONNECTIONS must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeAccountConnectionsEnabled =
        nativeAccountConnectionsFlag && *nativeAccountConnectionsFlag == "1";
    if (nativeAccountConnectionsEnabled
        && (!nativeAccountEnabled || !platform.account().enabled())) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Native account connections require enabled account sessions and account API."});
        return ExitCode::ConfigurationError;
    }
    // Status is read-only and independently gated; enrollment and disable
    // remain on the compatibility implementation until migrated separately.
    const auto nativeAccountTotpStatusFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_TOTP_STATUS");
    if (nativeAccountTotpStatusFlag && *nativeAccountTotpStatusFlag != "0"
        && *nativeAccountTotpStatusFlag != "1") {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_ACCOUNT_TOTP_STATUS must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeAccountTotpStatusEnabled =
        nativeAccountTotpStatusFlag && *nativeAccountTotpStatusFlag == "1";
    if (nativeAccountTotpStatusEnabled
        && (!nativeAccountEnabled || !platform.account().enabled())) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
            "Native TOTP status requires enabled account sessions and account API."});
        return ExitCode::ConfigurationError;
    }
    // Wallet/Farcaster already expose native verification coroutines, but
    // their synchronous browser-handoff APIs are not yet migrated. Select
    // only the direct native start/complete pair with a separate opt-in.
    const auto nativeWeb3Flag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_WEB3_LOGIN");
    if (nativeWeb3Flag && *nativeWeb3Flag != "0"
        && *nativeWeb3Flag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_WEB3_LOGIN must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeWeb3Enabled = nativeWeb3Flag && *nativeWeb3Flag == "1";
    // Session rotation/revocation has its own native SQL service and HTTP
    // listener. Enable only these three methods; do not infer readiness of
    // password login, OAuth or recovery-code issuance.
    const auto nativeAuthSessionFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_AUTH_SESSIONS");
    if (nativeAuthSessionFlag && *nativeAuthSessionFlag != "0"
        && *nativeAuthSessionFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_AUTH_SESSIONS must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeAuthSessionEnabled =
        nativeAuthSessionFlag && *nativeAuthSessionFlag == "1";
    const auto nativeAdminReadFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_ADMIN_MEMBERS");
    if (nativeAdminReadFlag && *nativeAdminReadFlag != "0" && *nativeAdminReadFlag != "1") {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_ADMIN_MEMBERS must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeAdminReadEnabled = nativeAdminReadFlag && *nativeAdminReadFlag == "1";
    if (nativeAdminReadEnabled && (!nativeAuthSessionEnabled || !platform.auth().enabled())) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
            "Native administration reads require native authentication sessions and authentication API."});
        return ExitCode::ConfigurationError;
    }
    // Recovery-code issuance is separately opted in and uses only native
    // session authentication and tenant-scoped canonical eligibility reads.
    const auto nativeRecoveryFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_RECOVERY_CODES");
    if (nativeRecoveryFlag && *nativeRecoveryFlag != "0"
        && *nativeRecoveryFlag != "1") {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_RECOVERY_CODES must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeRecoveryEnabled =
        nativeRecoveryFlag && *nativeRecoveryFlag == "1";
    if (nativeRecoveryEnabled && (!nativeAuthSessionEnabled || !platform.auth().enabled())) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
            "Native recovery-code issuance requires native authentication sessions and authentication API."});
        return ExitCode::ConfigurationError;
    }
#ifndef OPENPROOF_HAS_NATIVE_RECOVERY_HTTP
    if (nativeRecoveryEnabled) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
            "Native recovery-code HTTP capability was excluded from this build."});
        return ExitCode::ConfigurationError;
    }
#endif
    // Public OIDC discovery/JWKS are memory-only and can be served without
    // the synchronous OAuth handler. Keep all state-changing OAuth routes
    // on the existing compatibility chain until their SQL SPI is migrated.
    const auto nativeOidcDiscoveryFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_OIDC_DISCOVERY");
    if (nativeOidcDiscoveryFlag && *nativeOidcDiscoveryFlag != "0"
        && *nativeOidcDiscoveryFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_OIDC_DISCOVERY must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeOidcDiscoveryEnabled =
        nativeOidcDiscoveryFlag && *nativeOidcDiscoveryFlag == "1";
    // Browser consent management uses the existing native first-party
    // session stack, but never turns on any other OAuth endpoint.
    const auto nativeConsentFlag = environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_OAUTH_CONSENTS");
    if (nativeConsentFlag && *nativeConsentFlag != "0" && *nativeConsentFlag != "1") {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_OAUTH_CONSENTS must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeConsentEnabled = nativeConsentFlag && *nativeConsentFlag == "1";
    if (nativeConsentEnabled && (!nativeAuthSessionEnabled
        || !platform.auth().enabled() || !platform.oidc().enabled())) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
            "Native OAuth consent management requires authentication, OIDC and native sessions."});
        return ExitCode::ConfigurationError;
    }
    // /auth/providers is a public, in-memory registry projection. It can
    // migrate independently of federated callback/token/session services.
    const auto nativeCatalogFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_PROVIDER_CATALOG");
    if (nativeCatalogFlag && *nativeCatalogFlag != "0"
        && *nativeCatalogFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_PROVIDER_CATALOG must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeCatalogEnabled =
        nativeCatalogFlag && *nativeCatalogFlag == "1";
    // Experimental native first leg of federated login; no legacy provider
    // fallback is permitted on the async route.
    const auto nativeFederatedStartFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_FEDERATED_START");
    if (nativeFederatedStartFlag && *nativeFederatedStartFlag != "0"
        && *nativeFederatedStartFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_FEDERATED_START must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeFederatedStartEnabled =
        nativeFederatedStartFlag && *nativeFederatedStartFlag == "1";
    // The callback has a separate experimental gate: enabling only the
    // first leg must not change compatibility callbacks or SAML/OAuth1.
    const auto nativeFederatedCallbackFlag =
        environment.get("OPENPROOF_EXPERIMENTAL_NATIVE_FEDERATED_CALLBACK");
    if (nativeFederatedCallbackFlag && *nativeFederatedCallbackFlag != "0"
        && *nativeFederatedCallbackFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_EXPERIMENTAL_NATIVE_FEDERATED_CALLBACK must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool nativeFederatedCallbackEnabled =
        nativeFederatedCallbackFlag && *nativeFederatedCallbackFlag == "1";
    // Both HTTP legs must use the SAME native transaction repository.
    // A native start followed by a legacy callback cannot redeem the
    // persisted challenge, while a native callback cannot consume a
    // transaction created by the legacy synchronous store. Refuse a
    // split-brain deployment before the listener and any migrations start.
    if (nativeFederatedStartEnabled != nativeFederatedCallbackEnabled) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Native federated start and callback must be enabled together."});
        return ExitCode::ConfigurationError;
    }
    if (nativeFederatedStartEnabled && !platform.auth().enabled()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Native federated start requires enabled authentication."});
        return ExitCode::ConfigurationError;
    }
    if (nativeCatalogEnabled && !platform.auth().enabled()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Native provider catalog requires enabled authentication."});
        return ExitCode::ConfigurationError;
    }
    if (nativeOidcDiscoveryEnabled && !platform.oidc().enabled()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Native OIDC discovery requires enabled OIDC configuration."});
        return ExitCode::ConfigurationError;
    }
    if (nativeAuthSessionEnabled && !platform.auth().enabled()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Native authentication sessions require enabled authentication."});
        return ExitCode::ConfigurationError;
    }
    if (nativeWeb3Enabled && !platform.auth().enabled()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Native Web3 login requires enabled authentication."});
        return ExitCode::ConfigurationError;
    }
    if (nativeAccountEnabled && !platform.account().enabled()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Native account sessions require enabled account management."});
        return ExitCode::ConfigurationError;
    }
    if (nativeLdapEnabled) {
        const auto ldapUri = environment.get("OPENPROOF_LDAP_URI");
        if (!platform.auth().enabled() || !ldapUri || ldapUri->empty()) {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::FailedPrecondition,
                "Native LDAP requires enabled authentication and a registered LDAP provider."});
            return ExitCode::ConfigurationError;
        }
    }

    auto sessionSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/session-key/v1");
    auto contextSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/trusted-context-key/v1");
    if (!sessionSecret || !contextSecret) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    // Native issuance must use the legacy session HMAC key. Never create
    // another copy of that key for a disabled feature.
    std::optional<fnd::SecretString> nativeSessionSecret;
    if (nativeLdapEnabled || nativeAccountEnabled || nativeWeb3Enabled
        || nativeAuthSessionEnabled || nativeFederatedStartEnabled
        || nativeProtectedGatewayEnabled)
        nativeSessionSecret.emplace(sessionSecret->clone());
    auto sessionKey = session::SessionKey::create(
        std::move(sessionSecret).value());
    auto contextKey = gateway::TrustedContextKey::create(
        std::move(contextSecret).value());
    if (!sessionKey.has_value() || !contextKey.has_value()) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }

    auto limiter = gateway::TokenBucketRateLimiter::create(
        clock, static_cast<double>(platform.gateway().rateLimitCapacity()),
        static_cast<double>(platform.gateway().rateLimitRefillPerSecond()),
        platform.gateway().rateLimitMaximumKeys());
    auto circuits = gateway::CircuitBreaker::create(
        clock, 5U, std::chrono::seconds{30});
    auto signer = gateway::TrustedContextSigner::create(
        clock, std::move(contextKey).value(), std::chrono::seconds{30});
    auto proxy = gatewayHttp::BeastProxyTransport::create(
        gatewayHttp::ProxyConfig::create(
            64U * 1024U, 64U * 1024U * 1024U,
            std::string{platform.gateway().upstreamCaFile()}).value());
    if (!limiter || !circuits || !signer || !proxy) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::InvalidArgument});
        return ExitCode::ConfigurationError;
    }

    gateway::Router router;
    const bool authenticationEnabled = platform.auth().enabled();
    fnd::Status routes = fnd::ok();
    std::vector<policy::RolePolicyRule> authorizationRules;
    if (authenticationEnabled) {
        auto configuredRoutes = addProtectedRoutes(
            router, platform.auth().routePolicies(),
            identity::OrganizationId{std::string{platform.auth().organizationId()}});
        if (!configuredRoutes) {
            reportStartupFailure(configuredRoutes.error());
            return ExitCode::ConfigurationError;
        }
        authorizationRules = std::move(configuredRoutes).value();
    } else {
        routes = addPublicRoutes(router, platform.gateway().routePrefix());
    }
    gateway::StaticServiceDiscovery discovery;
    auto endpoint = gateway::Endpoint::create(
        gateway::EndpointId{"default-1"},
        std::string{platform.gateway().upstreamHost()},
        platform.gateway().upstreamPort(), platform.gateway().upstreamTls(), 1U);
    if (!routes || !endpoint || !discovery.set(
            gateway::ServiceId{"default"},
            std::vector<gateway::Endpoint>{std::move(endpoint).value()})) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::InvalidArgument});
        return ExitCode::ConfigurationError;
    }
    gateway::WeightedRoundRobin loadBalancer;
    const auto sessionPolicy = session::SessionPolicy::create(
        std::chrono::hours{8}, std::chrono::minutes{30}).value();

    if (!authenticationEnabled) {
        session::InMemorySessionRepository sessionRepository;
        session::SessionService sessions{
            sessionRepository, clock, std::move(sessionKey).value(), sessionPolicy};
        DenyAccess access;
        gateway::Gateway gatewayCore{
            router, sessions, access, limiter.value(), discovery, loadBalancer,
            circuits.value(), *proxy.value(), signer.value(), std::chrono::seconds{10}};
        // The public, non-authenticated gateway uses the same routing,
        // security-header and circuit-breaker decisions as the legacy path,
        // but awaits its upstream network I/O instead of blocking a worker.
        gatewayHttp::CoroutineGatewayAdapter asyncGateway{gatewayCore, *proxy.value()};
        return runListener(platform, asyncGateway, logger);
    }

    auto poolConfig = postgres::PoolConfig::create(
        platform.database().connectionString().clone(), platform.database().poolSize(),
        std::chrono::seconds{5});
    if (!poolConfig) {
        reportStartupFailure(poolConfig.error());
        return ExitCode::ConfigurationError;
    }
    auto pool = postgres::ConnectionPool::create(std::move(poolConfig).value());
    if (!pool) {
        reportStartupFailure(pool.error());
        return ExitCode::ConfigurationError;
    }
    postgres::Migrator migrator{*pool.value()};
    auto migrations = migrator.applyDirectory(platform.database().migrationDirectory());
    if (!migrations) {
        reportStartupFailure(migrations.error());
        return ExitCode::ConfigurationError;
    }
    const fnd::Status activeMaster = verifyActiveMasterKey(
        *pool.value(), platform.security());
    if (!activeMaster) {
        reportStartupFailure(activeMaster.error());
        return ExitCode::ConfigurationError;
    }

    postgres::PostgresIdentityRepository identities{*pool.value()};
    postgres::PostgresExternalIdentityDirectory externalIdentities{*pool.value()};
    postgres::PostgresOrganizationRepository organizations{*pool.value()};
    postgres::PostgresMembershipRepository memberships{*pool.value()};
    postgres::PostgresSessionRepository sessionRepository{*pool.value()};
    postgres::PostgresAuthenticationTransactionStore transactions{*pool.value()};
    postgres::PostgresRecoveryCodeRepository recoveryRepository{*pool.value()};
    postgres::PostgresPasskeyRepository passkeyRepository{*pool.value()};

    auto configuredOrganization = organizations.findById(
        identity::OrganizationId{std::string{platform.auth().organizationId()}});
    if (!configuredOrganization) {
        reportStartupFailure(configuredOrganization.error());
        return ExitCode::ConfigurationError;
    }
    if (!configuredOrganization->has_value()
        || !configuredOrganization->value().isUsable()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "The configured authentication organization is absent or inactive."});
        return ExitCode::ConfigurationError;
    }

    auto passwordSecret = passwordPepperMaterial(platform.security());
    auto totpSecret = credentialEncryptionMaterial(platform.security());
    auto recoverySecret = recoveryCodePepperMaterial(platform.security());
    auto auditSecret = auditChainMaterial(platform.security());
    if (!passwordSecret || !totpSecret || !recoverySecret || !auditSecret) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    auto administrationPasswordHasher = credentials::PasswordHasher::create(
        passwordSecret->clone(), credentials::PasswordPolicy::recommended(),
        std::string{platform.security().passwordHashAlgorithm()});
    auto administrationTotpKey = security::AeadKey::create(totpSecret->clone());
    auto administrationAuditKey = audit::AuditKey::create(auditSecret->clone());
    auto authorizationAuditKey = audit::AuditKey::create(
        std::move(auditSecret).value());
    auto passwordHasher = credentials::PasswordHasher::create(
        std::move(passwordSecret).value(), credentials::PasswordPolicy::recommended(),
        std::string{platform.security().passwordHashAlgorithm()});
    auto totpKey = security::AeadKey::create(std::move(totpSecret).value());
    if (!passwordHasher || !totpKey || !administrationPasswordHasher
        || !administrationTotpKey || !administrationAuditKey
        || !authorizationAuditKey) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    const idp::ProviderId providerId{std::string{platform.auth().providerId()}};
    auto accounts = postgres::PostgresLocalAccountDirectory::create(
        *pool.value(), std::move(passwordHasher).value(),
        credentials::TotpPolicy::recommended(), std::move(totpKey).value(),
        platform.security().credentialEncryptionKeyVersion(),
        providerId);
#ifdef OPENPROOF_HAS_NATIVE_RECOVERY_HTTP
    std::optional<fnd::SecretString> nativeRecoverySecret;
    if (nativeRecoveryEnabled) nativeRecoverySecret.emplace(recoverySecret->clone());
#endif
    auto recoveryCodes = credentials::RecoveryCodeService::create(
        recoveryRepository, std::move(recoverySecret).value());
    auto administrationRepository = postgres::PostgresAdministrationRepository::create(
        *pool.value(), std::move(administrationPasswordHasher).value(),
        std::move(administrationTotpKey).value(),
        platform.security().credentialEncryptionKeyVersion(), providerId,
        std::move(administrationAuditKey).value());
    if (!accounts || !recoveryCodes || !administrationRepository) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }

    idp::ProviderRegistry providers;
    auto provider = std::make_unique<local::LocalAuthenticationProvider>(
        providerId, *accounts.value(), clock, std::chrono::minutes{5},
        &externalIdentities, &recoveryCodes.value());
    const fnd::Status registered = providers.registerProvider(std::move(provider));
    auth::ProviderTrustPolicy trust;
    const fnd::Status trusted = trust.trust(providerId, idp::AssuranceLevel::Ial2);
    if (!registered || !trusted) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }

    std::optional<passkey::PasskeyConfig> passkeyConfig;
    if (const auto relyingPartyId = environment.get("OPENPROOF_WEBAUTHN_RP_ID");
        relyingPartyId && !relyingPartyId->empty()) {
        const auto origin = environment.get("OPENPROOF_WEBAUTHN_ORIGIN");
        if (!origin || origin->empty()) {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::FailedPrecondition,
                "OPENPROOF_WEBAUTHN_ORIGIN is required when passkeys are enabled."});
            return ExitCode::ConfigurationError;
        }
        auto derivationKey = deriveSecret(
            platform.security().tokenSigningKey(), "openproof/webauthn-challenge-key/v1");
        if (!derivationKey) {
            reportStartupFailure(derivationKey.error());
            return ExitCode::InternalError;
        }
        auto configured = passkey::PasskeyConfig::create(
            *relyingPartyId,
            environment.get("OPENPROOF_WEBAUTHN_RP_NAME").value_or("OpenProof"),
            *origin, std::move(derivationKey).value(), std::chrono::minutes{5});
        if (!configured) {
            reportStartupFailure(configured.error());
            return ExitCode::ConfigurationError;
        }
        passkeyConfig.emplace(std::move(configured).value());
        auto implementation = std::make_unique<passkey::PasskeyAuthenticationProvider>(
            passkeyRepository, clock, *passkeyConfig);
        auto status = providers.registerProvider(std::move(implementation));
        if (status) {
            status = trust.trust(idp::ProviderId{"passkey"}, idp::AssuranceLevel::Ial2);
        }
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }

    const auto federationCallback = environment.get("OPENPROOF_FEDERATION_CALLBACK_URI");
    const auto federationCaFile = environment.get("OPENPROOF_FEDERATION_CA_FILE");
    const auto registerOidcProvider = [&](std::string_view name,
                                          std::string issuer,
                                          std::vector<std::string> scopes,
                                          std::string_view keyLabel,
                                          externalOidc::OidcClientAuthenticationMethod
                                              clientAuthentication = externalOidc::
                                                  OidcClientAuthenticationMethod::
                                                      ClientSecretPost,
                                          externalOidc::OidcAuthorizationResponseMode
                                              authorizationResponseMode = externalOidc::
                                                  OidcAuthorizationResponseMode::
                                                      Query,
                                          externalOidc::OidcPkceMode pkceMode =
                                              externalOidc::OidcPkceMode::S256,
                                          externalOidc::OidcNonceMode nonceMode =
                                              externalOidc::OidcNonceMode::Required,
                                          std::string idTokenIssuer = {}) -> fnd::Status {
        const std::string upperName = [&] {
            std::string output{name};
            std::ranges::transform(output, output.begin(), [](unsigned char symbol) {
                return static_cast<char>(std::toupper(symbol));
            });
            return output;
        }();
        const auto clientId = environment.get("OPENPROOF_" + upperName + "_CLIENT_ID");
        if (!clientId || clientId->empty()) return fnd::ok();
        const auto clientSecret = environment.get("OPENPROOF_" + upperName + "_CLIENT_SECRET");
        if (!clientSecret || clientSecret->empty() || !federationCallback
            || federationCallback->empty()) {
            return fnd::fail(fnd::ErrorCode::FailedPrecondition,
                "Federated OIDC providers require a client secret and callback URI.");
        }
        auto derivationKey = deriveSecret(platform.security().tokenSigningKey(), keyLabel);
        if (!derivationKey) return fnd::fail(derivationKey.error());
        auto config = externalOidc::OidcProviderConfig::create(
            idp::ProviderId{std::string{name}}, std::move(issuer), *clientId,
            fnd::SecretString{*clientSecret}, *federationCallback, std::move(scopes),
            std::move(derivationKey).value(), std::chrono::minutes{5},
            clientAuthentication, authorizationResponseMode, pkceMode,
            nonceMode, std::move(idTokenIssuer));
        if (!config) return fnd::fail(config.error());
        auto implementation = std::make_unique<externalOidc::OidcAuthenticationProvider>(
            std::move(config).value(), clock, federationCaFile.value_or(std::string{}));
        auto status = providers.registerProvider(std::move(implementation));
        if (!status) return status;
        return trust.trust(idp::ProviderId{std::string{name}}, idp::AssuranceLevel::Ial1, true);
    };

    {
        const auto googleIssuer = environment.get("OPENPROOF_GOOGLE_ISSUER");
        auto status = registerOidcProvider(
            "google", googleIssuer.value_or("https://accounts.google.com"),
            {"openid", "profile", "email"}, "openproof/federation/google/v1");
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }
    {
        const auto appleClientId = environment.get("OPENPROOF_APPLE_CLIENT_ID");
        if (appleClientId && !appleClientId->empty()) {
            const auto appleIssuer = environment.get("OPENPROOF_APPLE_ISSUER");
            const auto staticAppleSecret = environment.get("OPENPROOF_APPLE_CLIENT_SECRET");
            auto status = fnd::ok();
            if (staticAppleSecret && !staticAppleSecret->empty()) {
                status = registerOidcProvider(
                    "apple", appleIssuer.value_or("https://appleid.apple.com"),
                    {"name", "email"}, "openproof/federation/apple/v1",
                    externalOidc::OidcClientAuthenticationMethod::ClientSecretPost,
                    externalOidc::OidcAuthorizationResponseMode::FormPost);
            } else {
                const auto teamId = environment.get("OPENPROOF_APPLE_TEAM_ID");
                const auto keyId = environment.get("OPENPROOF_APPLE_KEY_ID");
                const auto keyFile = environment.get("OPENPROOF_APPLE_PRIVATE_KEY_FILE");
                if (!teamId || teamId->empty() || !keyId || keyId->empty()
                    || !keyFile || keyFile->empty() || !federationCallback
                    || federationCallback->empty()) {
                    reportStartupFailure(fnd::Error{
                        fnd::ErrorCode::FailedPrecondition,
                        "Apple federation requires either OPENPROOF_APPLE_CLIENT_SECRET "
                        "or TEAM_ID, KEY_ID and PRIVATE_KEY_FILE, plus the callback URI."});
                    return ExitCode::ConfigurationError;
                }
                std::error_code fileError;
                const std::filesystem::path path{*keyFile};
                const auto fileStatus = std::filesystem::symlink_status(path, fileError);
                const auto size = fileError ? 0U : std::filesystem::file_size(path, fileError);
                if (fileError || std::filesystem::is_symlink(fileStatus)
                    || !std::filesystem::is_regular_file(fileStatus) || size == 0U
                    || size > 16U * 1024U) {
                    reportStartupFailure(fnd::Error{
                        fnd::ErrorCode::InvalidArgument,
                        "OPENPROOF_APPLE_PRIVATE_KEY_FILE is invalid."});
                    return ExitCode::ConfigurationError;
                }
                std::ifstream input{path, std::ios::binary};
                std::string pem(static_cast<std::size_t>(size), '\0');
                input.read(pem.data(), static_cast<std::streamsize>(pem.size()));
                if (!input || input.gcount() != static_cast<std::streamsize>(pem.size())) {
                    reportStartupFailure(fnd::Error{
                        fnd::ErrorCode::InvalidArgument,
                        "OPENPROOF_APPLE_PRIVATE_KEY_FILE could not be read."});
                    return ExitCode::ConfigurationError;
                }
                auto derivationKey = deriveSecret(
                    platform.security().tokenSigningKey(), "openproof/federation/apple/v1");
                if (!derivationKey) {
                    reportStartupFailure(derivationKey.error());
                    return ExitCode::InternalError;
                }
                auto config = externalOidc::OidcProviderConfig::createApple(
                    idp::ProviderId{"apple"},
                    appleIssuer.value_or("https://appleid.apple.com"), *appleClientId,
                    *teamId, *keyId, fnd::SecretString{std::move(pem)},
                    *federationCallback, {"name", "email"},
                    std::move(derivationKey).value(), std::chrono::minutes{5});
                if (!config) {
                    reportStartupFailure(config.error());
                    return ExitCode::ConfigurationError;
                }
                auto implementation = std::make_unique<externalOidc::OidcAuthenticationProvider>(
                    std::move(config).value(), clock,
                    federationCaFile.value_or(std::string{}));
                status = providers.registerProvider(std::move(implementation));
                if (status) {
                    status = trust.trust(
                        idp::ProviderId{"apple"}, idp::AssuranceLevel::Ial1, true);
                }
            }
            if (!status) {
                reportStartupFailure(status.error());
                return ExitCode::ConfigurationError;
            }
        }
    }
    {
        const auto linkedinIssuer = environment.get("OPENPROOF_LINKEDIN_ISSUER");
        auto status = registerOidcProvider(
            "linkedin", linkedinIssuer.value_or("https://www.linkedin.com/oauth"),
            {"openid", "profile", "email"}, "openproof/federation/linkedin/v1",
            externalOidc::OidcClientAuthenticationMethod::ClientSecretPost,
            externalOidc::OidcAuthorizationResponseMode::Query,
            externalOidc::OidcPkceMode::Disabled,
            externalOidc::OidcNonceMode::Disabled);
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }
    {
        const auto telegramIssuer = environment.get("OPENPROOF_TELEGRAM_ISSUER");
        auto status = registerOidcProvider(
            "telegram", telegramIssuer.value_or("https://oauth.telegram.org"),
            {"openid", "profile"}, "openproof/federation/telegram/v1",
            externalOidc::OidcClientAuthenticationMethod::ClientSecretBasic);
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }
    if (const auto microsoftClientId = environment.get("OPENPROOF_MICROSOFT_CLIENT_ID");
        microsoftClientId && !microsoftClientId->empty()) {
        const auto microsoftIssuer = environment.get("OPENPROOF_MICROSOFT_ISSUER");
        if (!microsoftIssuer || microsoftIssuer->empty()
            || microsoftIssuer->contains("{tenantid}")
            || microsoftIssuer->contains("/common/")
            || microsoftIssuer->contains("/organizations/")
            || microsoftIssuer->contains("/consumers/")) {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::FailedPrecondition,
                "OPENPROOF_MICROSOFT_ISSUER must be a tenant-specific v2 issuer."});
            return ExitCode::ConfigurationError;
        }
        auto status = registerOidcProvider(
            "microsoft", *microsoftIssuer, {"openid", "profile", "email"},
            "openproof/federation/microsoft/v1",
            externalOidc::OidcClientAuthenticationMethod::ClientSecretPost,
            externalOidc::OidcAuthorizationResponseMode::FormPost);
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }
    if (const auto githubClientId = environment.get("OPENPROOF_GITHUB_CLIENT_ID");
        githubClientId && !githubClientId->empty()) {
        const auto githubClientSecret = environment.get("OPENPROOF_GITHUB_CLIENT_SECRET");
        if (!githubClientSecret || githubClientSecret->empty()
            || !federationCallback || federationCallback->empty()) {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::FailedPrecondition,
                "GitHub federation requires a client secret and callback URI."});
            return ExitCode::ConfigurationError;
        }
        auto derivationKey = deriveSecret(
            platform.security().tokenSigningKey(), "openproof/federation/github/v1");
        if (!derivationKey) {
            reportStartupFailure(derivationKey.error());
            return ExitCode::InternalError;
        }
        auto githubConfig = github::GitHubProviderConfig::create(
            *githubClientId, fnd::SecretString{*githubClientSecret}, *federationCallback,
            std::move(derivationKey).value(), std::chrono::minutes{5});
        if (!githubConfig) {
            reportStartupFailure(githubConfig.error());
            return ExitCode::ConfigurationError;
        }
        auto githubProvider = std::make_unique<github::GitHubAuthenticationProvider>(
            std::move(githubConfig).value(), clock,
            federationCaFile.value_or(std::string{}));
        auto status = providers.registerProvider(std::move(githubProvider));
        if (status) {
            status = trust.trust(idp::ProviderId{"github"}, idp::AssuranceLevel::Ial1, true);
        }
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }
    if (const auto xApiKey = environment.get("OPENPROOF_X_API_KEY");
        xApiKey && !xApiKey->empty()) {
        const auto xApiSecret = environment.get("OPENPROOF_X_API_SECRET");
        if (!xApiSecret || xApiSecret->empty()
            || !federationCallback || federationCallback->empty()) {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::FailedPrecondition,
                "X OAuth 1.0a federation requires an API key, API secret, and callback URI."});
            return ExitCode::ConfigurationError;
        }
        auto derivationKey = deriveSecret(
            platform.security().tokenSigningKey(),
            "openproof/federation/x/oauth1/v1");
        if (!derivationKey) {
            reportStartupFailure(derivationKey.error());
            return ExitCode::InternalError;
        }
        auto xConfig = xProvider::XProviderConfig::create(
            *xApiKey, fnd::SecretString{*xApiSecret}, *federationCallback,
            std::move(derivationKey).value(), std::chrono::minutes{5});
        if (!xConfig) {
            reportStartupFailure(xConfig.error());
            return ExitCode::ConfigurationError;
        }
        auto xAuthenticationProvider = std::make_unique<xProvider::XAuthenticationProvider>(
            std::move(xConfig).value(), clock,
            federationCaFile.value_or(std::string{}));
        auto status = providers.registerProvider(std::move(xAuthenticationProvider));
        if (status) {
            status = trust.trust(idp::ProviderId{"x"}, idp::AssuranceLevel::Ial1, true);
        }
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }
    const auto parseChainId = [&](std::string_view name, std::uint64_t fallback)
        -> fnd::Result<std::uint64_t> {
        const auto configured = environment.get(std::string{name});
        if (!configured || configured->empty()) return fallback;
        std::uint64_t value{};
        const auto parsed = std::from_chars(
            configured->data(), configured->data() + configured->size(), value, 10);
        if (parsed.ec != std::errc{} || parsed.ptr != configured->data() + configured->size()
            || value == 0U) {
            return fnd::fail(fnd::ErrorCode::InvalidArgument,
                             "A configured Web3 chain id is invalid.");
        }
        return value;
    };
    const auto web3Domain = environment.get("OPENPROOF_WEB3_DOMAIN");
    const auto web3Uri = environment.get("OPENPROOF_WEB3_URI");
    const auto web3CaFile = environment.get("OPENPROOF_WEB3_CA_FILE").value_or(std::string{});
    const auto ethereumEnabledValue = environment.get("OPENPROOF_ETHEREUM_WALLET_ENABLED");
    // Generic opt-out for automatic onboarding. Existing wallet links continue
    // to authenticate normally; only previously unseen subjects are rejected.
    // Defaults to the historical behavior until an operator opts out.
    bool ethereumSelfProvision = true;
    if (const auto configured = environment.get("OPENPROOF_ETHEREUM_WALLET_SELF_PROVISIONING");
        configured.has_value()) {
        std::string lowered = *configured;
        std::ranges::transform(lowered, lowered.begin(), [](unsigned char symbol) {
            return static_cast<char>(std::tolower(symbol));
        });
        if (lowered == "1" || lowered == "true" || lowered == "yes" || lowered == "on") {
            ethereumSelfProvision = true;
        } else if (lowered == "0" || lowered == "false" || lowered == "no" || lowered == "off") {
            ethereumSelfProvision = false;
        } else {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::InvalidArgument,
                "OPENPROOF_ETHEREUM_WALLET_SELF_PROVISIONING must be a boolean value."});
            return ExitCode::ConfigurationError;
        }
    }
    const auto ethereumLegacyRpc = environment.get("OPENPROOF_ETHEREUM_RPC_ENDPOINT");
    const auto ethereumRpcMapValue = environment.get("OPENPROOF_ETHEREUM_RPC_ENDPOINTS");
    bool ethereumEnabled = (ethereumLegacyRpc && !ethereumLegacyRpc->empty())
        || (ethereumRpcMapValue && !ethereumRpcMapValue->empty());
    if (ethereumEnabledValue && !ethereumEnabledValue->empty()) {
        std::string lowered = *ethereumEnabledValue;
        std::ranges::transform(lowered, lowered.begin(), [](unsigned char symbol) {
            return static_cast<char>(std::tolower(symbol));
        });
        if (lowered == "1" || lowered == "true" || lowered == "yes" || lowered == "on") {
            ethereumEnabled = true;
        } else if (lowered == "0" || lowered == "false" || lowered == "no" || lowered == "off") {
            ethereumEnabled = false;
        } else {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::InvalidArgument,
                "OPENPROOF_ETHEREUM_WALLET_ENABLED must be a boolean value."});
            return ExitCode::ConfigurationError;
        }
    }
    if (ethereumEnabled) {
        if (!web3Domain || web3Domain->empty() || !web3Uri || web3Uri->empty()) {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::FailedPrecondition,
                "OPENPROOF_WEB3_DOMAIN and OPENPROOF_WEB3_URI are required for Web3 login."});
            return ExitCode::ConfigurationError;
        }

        std::map<std::uint64_t, std::string> walletRpcEndpoints;
        if (ethereumRpcMapValue && !ethereumRpcMapValue->empty()) {
            std::string_view remaining{*ethereumRpcMapValue};
            while (!remaining.empty()) {
                const auto separator = remaining.find(';');
                const auto entry = remaining.substr(
                    0U, separator == std::string_view::npos ? remaining.size() : separator);
                const auto equals = entry.find('=');
                if (equals == std::string_view::npos || equals == 0U || equals + 1U >= entry.size()) {
                    reportStartupFailure(fnd::Error{
                        fnd::ErrorCode::InvalidArgument,
                        "OPENPROOF_ETHEREUM_RPC_ENDPOINTS must use chain_id=https://rpc;... syntax."});
                    return ExitCode::ConfigurationError;
                }
                std::uint64_t chainId{};
                const auto chainText = entry.substr(0U, equals);
                const auto parsed = std::from_chars(
                    chainText.data(), chainText.data() + chainText.size(), chainId, 10);
                if (parsed.ec != std::errc{} || parsed.ptr != chainText.data() + chainText.size()
                    || chainId == 0U
                    || !walletRpcEndpoints.emplace(chainId, std::string{entry.substr(equals + 1U)}).second) {
                    reportStartupFailure(fnd::Error{
                        fnd::ErrorCode::InvalidArgument,
                        "OPENPROOF_ETHEREUM_RPC_ENDPOINTS contains an invalid or duplicate chain id."});
                    return ExitCode::ConfigurationError;
                }
                if (separator == std::string_view::npos) break;
                remaining.remove_prefix(separator + 1U);
            }
        }
        if (ethereumLegacyRpc && !ethereumLegacyRpc->empty()) {
            auto chainId = parseChainId("OPENPROOF_ETHEREUM_CHAIN_ID", 1U);
            if (!chainId) {
                reportStartupFailure(chainId.error());
                return ExitCode::ConfigurationError;
            }
            walletRpcEndpoints.insert_or_assign(chainId.value(), *ethereumLegacyRpc);
        }

        auto derivationKey = deriveSecret(
            platform.security().tokenSigningKey(), "openproof/federation/ethereum-wallet/v1");
        if (!derivationKey) {
            reportStartupFailure(derivationKey.error());
            return ExitCode::ConfigurationError;
        }
        auto walletConfig = web3::WalletProviderConfig::create(
            *web3Domain, *web3Uri, std::move(walletRpcEndpoints),
            std::move(derivationKey).value(), std::chrono::minutes{5}, web3CaFile,
            fnd::SecretString{environment.get("OPENPROOF_ETHEREUM_RPC_AUTHORIZATION").value_or(std::string{})});
        if (!walletConfig) {
            reportStartupFailure(walletConfig.error());
            return ExitCode::ConfigurationError;
        }
        auto status = providers.registerProvider(
            std::make_unique<web3::WalletAuthenticationProvider>(std::move(walletConfig).value(), clock));
        if (status) {
            status = trust.trust(idp::ProviderId{"ethereum-wallet"}, idp::AssuranceLevel::Ial1,
                                 ethereumSelfProvision);
        }
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }
    // Explicitly opt in to a TLS-verified *literal loopback* Farcaster RPC.
    // Default provider traffic still rejects loopback, private IPs, and DNS
    // rebinding. Never infer permission from a URL or a CA file alone.
    const auto farcasterLoopbackFlag =
        environment.get("OPENPROOF_FARCASTER_TRUSTED_LOOPBACK_RPC");
    if (farcasterLoopbackFlag && *farcasterLoopbackFlag != "0"
        && *farcasterLoopbackFlag != "1") {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::InvalidArgument,
            "OPENPROOF_FARCASTER_TRUSTED_LOOPBACK_RPC must be 0 or 1."});
        return ExitCode::ConfigurationError;
    }
    const bool trustedFarcasterLoopback =
        farcasterLoopbackFlag && *farcasterLoopbackFlag == "1";
    const auto configuredFarcasterRpc = environment.get("OPENPROOF_FARCASTER_RPC_ENDPOINT");
    if (trustedFarcasterLoopback
        && (!configuredFarcasterRpc || configuredFarcasterRpc->empty())) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Trusted Farcaster loopback RPC requires an explicit endpoint."});
        return ExitCode::ConfigurationError;
    }
    if (const auto farcasterRpc = configuredFarcasterRpc;
        farcasterRpc && !farcasterRpc->empty()) {
        constexpr std::string_view canonicalIdRegistry{
            "0x00000000fc6c5f01fc30151999387bb99a9f489b"};
        constexpr std::string_view canonicalKeyRegistry{
            "0x00000000fc1237824fb747abde0ff18990e59b7e"};
        const auto registry = environment.get("OPENPROOF_FARCASTER_ID_REGISTRY")
            .value_or(std::string{canonicalIdRegistry});
        const auto keyRegistry = environment.get("OPENPROOF_FARCASTER_KEY_REGISTRY")
            .value_or(std::string{canonicalKeyRegistry});
        if (!web3Domain || web3Domain->empty() || !web3Uri || web3Uri->empty()
            || registry.empty() || keyRegistry.empty()) {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::FailedPrecondition,
                "Farcaster login requires WEB3 domain/URI and valid registry addresses."});
            return ExitCode::ConfigurationError;
        }
        auto chainId = parseChainId("OPENPROOF_FARCASTER_CHAIN_ID", 10U);
        auto derivationKey = deriveSecret(
            platform.security().tokenSigningKey(), "openproof/federation/farcaster/v1");
        if (!chainId || !derivationKey) {
            reportStartupFailure(chainId ? derivationKey.error() : chainId.error());
            return ExitCode::ConfigurationError;
        }
        auto farcasterConfig = web3::FarcasterProviderConfig::create(
            *web3Domain, *web3Uri, chainId.value(), *farcasterRpc, registry,
            std::move(derivationKey).value(), std::chrono::minutes{5}, web3CaFile,
            fnd::SecretString{environment.get("OPENPROOF_FARCASTER_RPC_AUTHORIZATION").value_or(std::string{})},
            keyRegistry, trustedFarcasterLoopback);
        if (!farcasterConfig) {
            reportStartupFailure(farcasterConfig.error());
            return ExitCode::ConfigurationError;
        }
        auto status = providers.registerProvider(
            std::make_unique<web3::FarcasterAuthenticationProvider>(
                std::move(farcasterConfig).value(), clock));
        if (status) {
            status = trust.trust(idp::ProviderId{"farcaster"}, idp::AssuranceLevel::Ial1, true);
        }
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }

    if (const auto ldapUri = environment.get("OPENPROOF_LDAP_URI"); ldapUri && !ldapUri->empty()) {
        const auto baseDn = environment.get("OPENPROOF_LDAP_BASE_DN");
        if (!baseDn || baseDn->empty()) {
            reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                "OPENPROOF_LDAP_BASE_DN is required when LDAP login is enabled."});
            return ExitCode::ConfigurationError;
        }
        auto derivationKey = deriveSecret(
            platform.security().tokenSigningKey(), "openproof/federation/ldap/v1");
        if (!derivationKey) {
            reportStartupFailure(derivationKey.error());
            return ExitCode::InternalError;
        }
        auto ldapConfig = enterprise::LdapProviderConfig::create(
            *ldapUri, *baseDn,
            environment.get("OPENPROOF_LDAP_USERNAME_ATTRIBUTE").value_or("uid"),
            environment.get("OPENPROOF_LDAP_SUBJECT_ATTRIBUTE").value_or("entryUUID"),
            environment.get("OPENPROOF_LDAP_DISPLAY_NAME_ATTRIBUTE").value_or("cn"),
            environment.get("OPENPROOF_LDAP_EMAIL_ATTRIBUTE").value_or("mail"),
            environment.get("OPENPROOF_LDAP_BIND_DN").value_or(std::string{}),
            fnd::SecretString{environment.get("OPENPROOF_LDAP_BIND_PASSWORD").value_or(std::string{})},
            std::move(derivationKey).value(),
            environment.get("OPENPROOF_LDAP_CA_FILE").value_or(std::string{}),
            std::chrono::minutes{5});
        if (!ldapConfig) {
            reportStartupFailure(ldapConfig.error());
            return ExitCode::ConfigurationError;
        }
        auto ldapProvider = std::make_unique<enterprise::LdapAuthenticationProvider>(
            std::move(ldapConfig).value(), clock);
        if (!ldapProvider->nativeTrustReady()) {
            reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                "LDAP certificate trust could not be prepared."});
            return ExitCode::ConfigurationError;
        }
        auto status = providers.registerProvider(std::move(ldapProvider));
        if (status) status = trust.trust(idp::ProviderId{"ldap"}, idp::AssuranceLevel::Ial1, true);
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }

    if (const auto samlSso = environment.get("OPENPROOF_SAML_IDP_SSO_URL"); samlSso && !samlSso->empty()) {
        const auto spEntity = environment.get("OPENPROOF_SAML_SP_ENTITY_ID");
        const auto idpEntity = environment.get("OPENPROOF_SAML_IDP_ENTITY_ID");
        const auto certificate = environment.get("OPENPROOF_SAML_IDP_CERTIFICATE_PEM");
        if (!spEntity || spEntity->empty() || !idpEntity || idpEntity->empty()
            || !certificate || certificate->empty() || !federationCallback || federationCallback->empty()) {
            reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                "SAML login requires SP/IdP entity IDs, IdP certificate PEM and the federation callback URI."});
            return ExitCode::ConfigurationError;
        }
        auto derivationKey = deriveSecret(
            platform.security().tokenSigningKey(), "openproof/federation/saml/v1");
        if (!derivationKey) {
            reportStartupFailure(derivationKey.error());
            return ExitCode::InternalError;
        }
        auto samlConfig = enterprise::SamlProviderConfig::create(
            *spEntity, *federationCallback, *idpEntity, *samlSso, *certificate,
            std::move(derivationKey).value(), std::chrono::minutes{5}, std::chrono::minutes{2});
        if (!samlConfig) {
            reportStartupFailure(samlConfig.error());
            return ExitCode::ConfigurationError;
        }
        auto status = providers.registerProvider(std::make_unique<enterprise::SamlAuthenticationProvider>(
            std::move(samlConfig).value(), clock));
        if (status) status = trust.trust(idp::ProviderId{"saml"}, idp::AssuranceLevel::Ial1, true);
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
    }

    // A deployment may deny first-login account creation across any configured
    // provider without restricting login for already linked external subjects.
    // The list is validated only after all provider trust rules are registered.
    if (const auto disabled = environment.get("OPENPROOF_SELF_PROVISIONING_DISABLED_PROVIDERS");
        disabled.has_value()) {
        const auto restricted = trust.disableSelfProvisioningFor(*disabled);
        if (!restricted) {
            reportStartupFailure(restricted.error());
            return ExitCode::ConfigurationError;
        }
    }

    // Restrict automatic email-based account linking without disabling sign-in,
    // explicit account connection, or independently allowed new registration.
    if (const auto disabled = environment.get("OPENPROOF_EMAIL_CONVERGENCE_DISABLED_PROVIDERS");
        disabled.has_value()) {
        const auto restricted = trust.disableVerifiedEmailConvergenceFor(*disabled);
        if (!restricted) {
            reportStartupFailure(restricted.error());
            return ExitCode::ConfigurationError;
        }
    }

    postgres::PostgresIdentityProviderStore identityProviderStore{*pool.value()};
    // Retain the original synchronous AuthenticationService for the existing
    // OAuth, account, SAML and other compatibility handlers. LDAP's native
    // coordinator receives its own identical operator trust policy.
    auto nativeTrust = trust;
    auth::AuthenticationService authentication{
        providers, transactions, externalIdentities, clock, std::move(trust),
        std::chrono::minutes{5}, &identities,
        identity::OrganizationId{std::string{platform.auth().organizationId()}},
        &identityProviderStore};
    session::SessionService sessions{
        sessionRepository, clock, std::move(sessionKey).value(), sessionPolicy};

    // Native LDAP is deliberately opt-in until the complete compiler
    // and real-login E2E acceptance criteria have passed.
    // The pool owns only its executor and is destroyed *after* the native
    // repositories. runListener() first stops/joins all handler workers, so
    // no request may outlive this composition root. Three separate bounded
    // pools avoid borrowing a synchronous libpq session onto the reactor.
    std::unique_ptr<boost::asio::thread_pool> nativeIo;
    std::unique_ptr<postgres::CoroutinePostgresAuthenticationTransactionStore>
        nativeTransactions;
    std::unique_ptr<postgres::CoroutinePostgresCanonicalFinalizer>
        nativeCanonical;
    std::unique_ptr<postgres::CoroutinePostgresSessionRepository>
        nativeSessionRepository;
    std::unique_ptr<postgres::CoroutinePostgresSessionService>
        nativeSessions;
    std::unique_ptr<auth::AuthenticationService> nativeAuthentication;
    std::unique_ptr<postgres::CoroutineSessionAuthenticator> nativeGatewayVerifier;
    std::unique_ptr<postgres::CoroutineAuthorizationDecisionSink> nativeGatewayAudit;
    std::unique_ptr<postgres::CoroutineConsentStore> nativeConsentStore;
#ifdef OPENPROOF_HAS_NATIVE_RECOVERY_HTTP
    std::unique_ptr<postgres::CoroutinePostgresRecoveryCodeRepository> nativeRecoveryRepository;
    std::optional<credentials::CoroutineRecoveryCodeService> nativeRecoveryCodes;
#endif
    if (nativeLdapEnabled || nativeAccountEnabled || nativeWeb3Enabled
        || nativeAuthSessionEnabled || nativeFederatedStartEnabled
        || nativeProtectedGatewayEnabled) {
        nativeIo = std::make_unique<boost::asio::thread_pool>(2U);
        const auto executor = nativeIo->get_executor();
        const std::size_t nativeConnections =
            std::min<std::size_t>(2U, platform.database().poolSize());
        constexpr auto acquireDeadline = std::chrono::seconds{2};
        constexpr auto connectDeadline = std::chrono::seconds{3};
        constexpr auto queryDeadline = std::chrono::seconds{5};
        // Session management has independent SQL storage. Profile reads add
        // a tenant-scoped canonical reader only under their separate opt-in;
        // account-only sessions must not initialize OAuth transactions.
        nativeSessionRepository = std::make_unique<
            postgres::CoroutinePostgresSessionRepository>(
                executor, platform.database().connectionString().clone(),
                nativeConnections, acquireDeadline, connectDeadline, queryDeadline);
        if (nativeProtectedGatewayEnabled) {
            nativeGatewayVerifier = std::make_unique<postgres::CoroutineSessionAuthenticator>(
                *nativeSessionRepository, clock, nativeSessionSecret->clone());
            auto key = audit::AuditKey::create(authorizationAuditKey->secret().clone());
            if (!key) {
                reportStartupFailure(key.error());
                return ExitCode::ConfigurationError;
            }
            nativeGatewayAudit = std::make_unique<postgres::CoroutineAuthorizationDecisionSink>(
                executor, platform.database().connectionString().clone(),
                std::move(key).value(), clock, nativeConnections,
                acquireDeadline, connectDeadline, queryDeadline);
        }
        nativeSessions = std::make_unique<
            postgres::CoroutinePostgresSessionService>(
                *nativeSessionRepository, clock,
                std::move(*nativeSessionSecret), sessionPolicy);
        if (nativeConsentEnabled) {
            nativeConsentStore = std::make_unique<postgres::CoroutineConsentStore>(
                executor, platform.database().connectionString().clone(),
                identity::OrganizationId{std::string{platform.auth().organizationId()}},
                nativeConnections, acquireDeadline, connectDeadline, queryDeadline);
        }
        if (nativeLdapEnabled || nativeWeb3Enabled || nativeFederatedStartEnabled
            || nativeAccountProfileEnabled || nativeAccountConnectionsEnabled
            || nativeAccountTotpStatusEnabled || nativeAdminReadEnabled || nativeRecoveryEnabled || nativeProtectedGatewayEnabled) {
            nativeCanonical = std::make_unique<
                postgres::CoroutinePostgresCanonicalFinalizer>(
                    executor, platform.database().connectionString().clone(),
                    identity::OrganizationId{
                        std::string{platform.auth().organizationId()}},
                    nativeConnections, acquireDeadline, connectDeadline, queryDeadline);
        }
#ifdef OPENPROOF_HAS_NATIVE_RECOVERY_HTTP
        if (nativeRecoveryEnabled) {
            nativeRecoveryRepository = std::make_unique<
                postgres::CoroutinePostgresRecoveryCodeRepository>(
                    executor, platform.database().connectionString().clone(),
                    nativeConnections, acquireDeadline, connectDeadline, queryDeadline);
            auto created = credentials::CoroutineRecoveryCodeService::create(
                *nativeRecoveryRepository, std::move(*nativeRecoverySecret));
            if (!created) {
                reportStartupFailure(created.error());
                return ExitCode::ConfigurationError;
            }
            nativeRecoveryCodes.emplace(std::move(created).value());
        }
#endif
        if (nativeLdapEnabled || nativeWeb3Enabled || nativeFederatedStartEnabled) {
            nativeTransactions = std::make_unique<
                postgres::CoroutinePostgresAuthenticationTransactionStore>(
                    executor, platform.database().connectionString().clone(),
                    nativeConnections, acquireDeadline, connectDeadline, queryDeadline);
            nativeAuthentication = std::make_unique<auth::AuthenticationService>(
                providers, *nativeTransactions, externalIdentities, clock,
                std::move(nativeTrust), std::chrono::minutes{5},
                &identities,
                identity::OrganizationId{
                    std::string{platform.auth().organizationId()}},
                &identityProviderStore, nativeCanonical.get());
        }
    }

    std::optional<passkey::PasskeyService> passkeyService;
    if (passkeyConfig) {
        passkeyService.emplace(passkeyRepository, externalIdentities, clock, *passkeyConfig);
    }
    auto memberPolicy = policy::RolePolicyEngine::create(
        std::move(authorizationRules));
    if (!memberPolicy) {
        reportStartupFailure(memberPolicy.error());
        return ExitCode::ConfigurationError;
    }
    postgres::PostgresAuthorizationDecisionSink authorizationAudit{
        *pool.value(), std::move(authorizationAuditKey).value(), clock};
    gateway::PolicyAccessController access{
        memberPolicy->get(), organizations, identities, memberships,
        &authorizationAudit};

    postgres::PostgresEvidenceChallengeStore evidenceChallengeStore{*pool.value()};
    evidence::EvidenceService evidenceService{identityProviderStore, clock};
    evidenceVerification::ChallengeService evidenceChallenges{
        evidenceChallengeStore, clock, std::chrono::minutes{5}};
    std::set<std::string, std::less<>> evidenceProviders;

    if (const auto publicKey = environment.get("OPENPROOF_EVIDENCE_JWT_PUBLIC_KEY_PEM");
        publicKey && !publicKey->empty()) {
        const auto issuer = environment.get("OPENPROOF_EVIDENCE_JWT_ISSUER");
        const auto audience = environment.get("OPENPROOF_EVIDENCE_JWT_AUDIENCE");
        if (!issuer || issuer->empty() || !audience || audience->empty()) {
            reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                "Signed evidence JWT verification requires issuer and audience configuration."});
            return ExitCode::ConfigurationError;
        }
        auto verifier = evidenceVerification::SignedJwtVerifier::create(
            idp::ProviderId{"signed-jwt-evidence"}, *issuer, *audience, *publicKey,
            std::chrono::minutes{10});
        if (!verifier) {
            reportStartupFailure(verifier.error());
            return ExitCode::ConfigurationError;
        }
        auto status = evidenceService.registerVerifier(std::move(verifier).value());
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
        evidenceProviders.emplace("signed-jwt-evidence");
    }

    if (const auto caFile = environment.get("OPENPROOF_EVIDENCE_X509_CA_FILE");
        caFile && !caFile->empty()) {
        auto verifier = evidenceVerification::X509Verifier::create(
            idp::ProviderId{"x509-evidence"}, *caFile,
            environment.get("OPENPROOF_EVIDENCE_X509_CRL_FILE").value_or(std::string{}));
        if (!verifier) {
            reportStartupFailure(verifier.error());
            return ExitCode::ConfigurationError;
        }
        auto status = evidenceService.registerVerifier(std::move(verifier).value());
        if (!status) {
            reportStartupFailure(status.error());
            return ExitCode::ConfigurationError;
        }
        evidenceProviders.emplace("x509-evidence");
    }

    trustModel::TrustPolicy evidenceTrustPolicy;
    if (!evidenceTrustPolicy.setWeight("jwt.attestation", 85U)
        || !evidenceTrustPolicy.setWeight("x509.identity", 95U)
        || !evidenceTrustPolicy.setWeight("x509.certificate", 75U)) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    trustModel::TrustEngine evidenceTrust{identityProviderStore, clock, std::move(evidenceTrustPolicy)};

    postgres::PostgresAccountRepository accountRepository{*pool.value()};
    postgres::PostgresScimDirectoryRepository scimDirectory{*pool.value()};
    scim::Service scimService{
        identity::OrganizationId{std::string{platform.auth().organizationId()}},
        scimDirectory, identities, identityProviderStore, memberships, clock};
    std::optional<fnd::SecretString> scimBearerToken;
    if (auto configuredScimToken = environment.get("OPENPROOF_SCIM_BEARER_TOKEN");
        configuredScimToken && !configuredScimToken->empty()) {
        if (configuredScimToken->size() < 32U) {
            reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                "OPENPROOF_SCIM_BEARER_TOKEN must contain at least 32 bytes."});
            return ExitCode::ConfigurationError;
        }
        scimBearerToken.emplace(std::move(*configuredScimToken));
    }

    operationsHttp::PostgresReadinessCheck readiness{*pool.value()};
    const oidc::OpenIdProvider* nativeOidcProvider = nullptr;
    gateway::Gateway* nativeGatewayCore = nullptr;

    const auto runWithEvidence = [&](
        gateway::HttpHandler& fallback,
        gatewayHttp::CoroutineHttpHandler& nativeEnterprise) -> ExitCode {
        evidenceHttp::Api evidenceApi{
            evidenceService, identityProviderStore, evidenceChallenges, evidenceTrust,
            sessions, evidenceProviders, limiter.value(), fallback};
        operationsHttp::HealthHttpApi healthApi{readiness, evidenceApi};
        // Legacy health, evidence and SCIM middleware remain the authoritative
        // compatibility chain. Exact native routes bypass it only when their
        // independently verified coroutine dependencies are available.
        // Only opt-in native PostgreSQL sessions can serve account session
        // routes without blocking the HTTP reactor on the legacy libpq pool.
        // All other account routes remain on the compatibility worker.
        std::unique_ptr<postgres::CoroutineSessionListenerStack> asyncAuthSessions;
        std::unique_ptr<accountHttp::CoroutineAccountSessionAdapter> asyncAccount;
        std::unique_ptr<oauthHttp::CoroutineOidcDiscoveryAdapter> asyncOidc;
        std::unique_ptr<oauthHttp::CoroutineConsentAdapter> asyncConsent;
        std::unique_ptr<authHttp::CoroutineProviderCatalogAdapter> asyncCatalog;
        std::unique_ptr<authHttp::CoroutineFederatedStartAdapter> asyncFederated;
        std::unique_ptr<authHttp::CoroutineFederatedCallbackAdapter> asyncFederatedCallback;
        std::unique_ptr<adminHttp::CoroutineAdministrationReadAdapter> asyncAdminRead;
#ifdef OPENPROOF_HAS_NATIVE_RECOVERY_HTTP
        std::unique_ptr<authHttp::CoroutineRecoveryCodeHttpAdapter> asyncRecovery;
#endif
        gatewayHttp::CoroutineHttpHandler* nativeHandler = &nativeEnterprise;
        std::vector<std::string> nativePaths;
        // A Web3-only opt-in must never activate LDAP inadvertently just
        // because both login types share the native canonical SQL stack.
        if (nativeLdapEnabled) {
            nativePaths.emplace_back("/auth/ldap/start");
            nativePaths.emplace_back("/auth/ldap/complete");
        }
        if (nativeWeb3Enabled) {
            nativePaths.emplace_back("/auth/web3/start");
            nativePaths.emplace_back("/auth/web3/complete");
        }
        if (nativeAuthSessionEnabled && nativeSessions) {
            // The existing coroutine session listener owns the native
            // rotate/logout application dispatcher and rejects all sync
            // compatibility calls. Its only fallback is the already-gated
            // Web3/LDAP native handler; the route overlay whitelists only
            // these three explicitly enabled session mutations.
            asyncAuthSessions = std::make_unique<postgres::CoroutineSessionListenerStack>(
                *nativeSessions, limiter.value(), *nativeHandler, true);
            nativeHandler = &asyncAuthSessions->handler();
            nativePaths.emplace_back("/auth/session/rotate");
            nativePaths.emplace_back("/auth/logout");
            nativePaths.emplace_back("/auth/logout-all");
        }
#ifdef OPENPROOF_HAS_NATIVE_RECOVERY_HTTP
        if (nativeRecoveryEnabled) {
            if (!nativeSessions || !nativeCanonical || !nativeRecoveryCodes) {
                reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                    "Native recovery-code service is unavailable."});
                return ExitCode::ConfigurationError;
            }
            auto* service = nativeSessions.get();
            auto* canonical = nativeCanonical.get();
            asyncRecovery = std::make_unique<authHttp::CoroutineRecoveryCodeHttpAdapter>(
                *nativeHandler, limiter.value(), *nativeRecoveryCodes,
                [service](fnd::SecretString bearer) {
                    return service->authenticate(std::move(bearer));
                },
                [canonical, providerId](identity::IdentityId owner)
                    -> boost::asio::awaitable<fnd::Result<bool>> {
                    // Both adapter eligibility calls use fresh, tenant-bound
                    // reads of canonical ownership and local credential state.
                    auto status = co_await canonical->readTotpStatusAsync(owner, providerId);
                    if (!status) {
                        if (status.error().code() == fnd::ErrorCode::NotFound)
                            co_return false;
                        co_return fnd::fail(status.error());
                    }
                    if (status->first != owner)
                        co_return fnd::fail(fnd::ErrorCode::Unavailable);
                    co_return status->second.value_or(false);
                });
            nativeHandler = asyncRecovery.get();
        }
#endif
        if (platform.account().enabled() && nativeAccountEnabled && nativeSessions) {
            auto* service = nativeSessions.get();
            accountHttp::CoroutineAccountSessionAdapter::ReadProfile profileReader;
            if (nativeAccountProfileEnabled) {
                if (!nativeCanonical) {
                    reportStartupFailure(fnd::Error{
                        fnd::ErrorCode::FailedPrecondition,
                        "Native account profile requires a canonical reader."});
                    return ExitCode::ConfigurationError;
                }
                auto* reader = nativeCanonical.get();
                profileReader = [reader](identity::IdentityId owner) {
                    return reader->readProfileAsync(std::move(owner));
                };
            }
            accountHttp::CoroutineAccountSessionAdapter::ReadConnections connectionsReader;
            if (nativeAccountConnectionsEnabled) {
                if (!nativeCanonical) {
                    reportStartupFailure(fnd::Error{
                        fnd::ErrorCode::FailedPrecondition,
                        "Native account connections require a canonical reader."});
                    return ExitCode::ConfigurationError;
                }
                auto* reader = nativeCanonical.get();
                // Match AuthenticationService::connections: the directory can
                // retain a link after its provider is removed from runtime
                // configuration. Such a link is not a usable login method
                // and must not be exposed in the account projection.
                // The registry is assembled before listener startup; this
                // immutable snapshot avoids registry locks on IO workers.
                connectionsReader = [reader, registered = providers.ids()](identity::IdentityId owner)
                    -> boost::asio::awaitable<fnd::Result<
                        accountHttp::CoroutineAccountSessionAdapter::ConnectionList>> {
                    auto result = co_await reader->readConnectionsAsync(std::move(owner));
                    if (!result) co_return fnd::fail(result.error());
                    std::erase_if(result->second, [&registered](const auto& external) {
                        return std::ranges::find(registered, external.providerId()) == registered.end();
                    });
                    co_return std::move(result).value();
                };
            }
            accountHttp::CoroutineAccountSessionAdapter::ReadTotpStatus totpStatusReader;
            if (nativeAccountTotpStatusEnabled) {
                if (!nativeCanonical) {
                    reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                        "Native TOTP status requires a canonical reader."});
                    return ExitCode::ConfigurationError;
                }
                auto* reader = nativeCanonical.get();
                totpStatusReader = [reader, providerId](identity::IdentityId owner) {
                    return reader->readTotpStatusAsync(std::move(owner), providerId);
                };
            }
            asyncAccount = std::make_unique<accountHttp::CoroutineAccountSessionAdapter>(
                healthApi, *nativeHandler, limiter.value(),
                [service](fnd::SecretString bearer) {
                    return service->authenticate(std::move(bearer));
                },
                [service](identity::IdentityId owner) {
                    return service->list(std::move(owner));
                },
                [service](identity::IdentityId owner, session::SessionId target) {
                    return service->revokeOwned(std::move(owner), std::move(target));
                }, std::move(profileReader), std::move(connectionsReader),
                std::move(totpStatusReader));
            nativeHandler = asyncAccount.get();
            nativePaths.emplace_back("/account/sessions");
            nativePaths.emplace_back("/account/sessions/revoke");
            // This read-only route is method scoped below. PATCH/PUT on
            // /account/profile must keep using the compatibility API.
        }
        if (nativeConsentEnabled) {
            if (!nativeSessions || !nativeConsentStore) {
                reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                    "Native OAuth consent dependencies are unavailable."});
                return ExitCode::ConfigurationError;
            }
            auto* sessionService = nativeSessions.get();
            auto* store = nativeConsentStore.get();
            asyncConsent = std::make_unique<oauthHttp::CoroutineConsentAdapter>(
                *nativeHandler, limiter.value(), clock,
                [sessionService](fnd::SecretString credential) {
                    return sessionService->authenticate(std::move(credential));
                },
                [store](identity::IdentityId owner) {
                    return store->listAsync(std::move(owner));
                },
                [store](consent::ConsentId id, identity::IdentityId owner, fnd::Instant now) {
                    return store->revokeAsync(std::move(id), std::move(owner), now);
                });
            nativeHandler = asyncConsent.get();
        }
        if (nativeOidcDiscoveryEnabled) {
            if (nativeOidcProvider == nullptr) {
                reportStartupFailure(fnd::Error{
                    fnd::ErrorCode::FailedPrecondition,
                    "Native OIDC discovery provider is unavailable."});
                return ExitCode::ConfigurationError;
            }
            // Build documents from the configured issuer/key set before
            // starting listener workers; no database or signing-key read
            // occurs on the native reactor for these public endpoints.
            auto jwks = nativeOidcProvider->jwksDocument();
            if (!jwks) {
                reportStartupFailure(jwks.error());
                return ExitCode::ConfigurationError;
            }
            asyncOidc = std::make_unique<oauthHttp::CoroutineOidcDiscoveryAdapter>(
                *nativeHandler, nativeOidcProvider->discoveryDocument(),
                std::move(jwks).value());
            nativeHandler = asyncOidc.get();
            nativePaths.emplace_back("/.well-known/openid-configuration");
            nativePaths.emplace_back("/.well-known/jwks.json");
        }
        if (nativeCatalogEnabled) {
            // Preserve the FederatedAuthenticationHttpApi projection exactly,
            // but build it once from the registered providers before workers
            // start. No registry mutex or provider call runs on the reactor.
            boost::json::array redirectProviders;
            boost::json::array challengeProviders;
            for (const auto& registeredProvider : providers.ids()) {
                auto* implementation = providers.find(registeredProvider);
                if (implementation == nullptr) continue;
                if (implementation->interactionModel()
                    == idp::InteractionModel::Redirect) {
                    redirectProviders.emplace_back(registeredProvider.value());
                } else if (implementation->interactionModel()
                           == idp::InteractionModel::ChallengeResponse) {
                    challengeProviders.emplace_back(registeredProvider.value());
                }
            }
            boost::json::object catalog;
            catalog["providers"] = std::move(redirectProviders);
            catalog["challenge_providers"] = std::move(challengeProviders);
            asyncCatalog = std::make_unique<authHttp::CoroutineProviderCatalogAdapter>(
                *nativeHandler, boost::json::serialize(catalog));
            nativeHandler = asyncCatalog.get();
            nativePaths.emplace_back("/auth/providers");
        }
        if (nativeFederatedStartEnabled) {
            if (!nativeAuthentication) {
                reportStartupFailure(fnd::Error{
                    fnd::ErrorCode::FailedPrecondition,
                    "Native federated start requires a native authentication stack."});
                return ExitCode::ConfigurationError;
            }
            asyncFederated = std::make_unique<authHttp::CoroutineFederatedStartAdapter>(
                *nativeAuthentication, providers, limiter.value(), *nativeHandler);
            nativeHandler = asyncFederated.get();
            nativePaths.emplace_back("/auth/federated/start");
        }
        if (nativeFederatedCallbackEnabled) {
            if (!nativeAuthentication || !nativeSessions) {
                reportStartupFailure(fnd::Error{
                    fnd::ErrorCode::FailedPrecondition,
                    "Native federated callback requires native canonical and session services."});
                return ExitCode::ConfigurationError;
            }
            asyncFederatedCallback = std::make_unique<
                authHttp::CoroutineFederatedCallbackAdapter>(
                    *nativeAuthentication, *nativeSessions, *nativeHandler);
            nativeHandler = asyncFederatedCallback.get();
            nativePaths.emplace_back("/auth/federated/callback");
        }
        std::vector<std::pair<std::string, gateway::HttpMethod>> nativeMethods;
        if (nativeAccountProfileEnabled) {
            nativeMethods.emplace_back("/account/profile", gateway::HttpMethod::Get);
        }
        if (nativeAccountConnectionsEnabled) {
            nativeMethods.emplace_back("/account/connections", gateway::HttpMethod::Get);
        }
        if (nativeAccountTotpStatusEnabled) {
            nativeMethods.emplace_back("/account/totp", gateway::HttpMethod::Get);
        }
        if (nativeAdminReadEnabled) {
            if (!nativeSessions || !nativeCanonical) {
                reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                    "Native administration reader is unavailable."});
                return ExitCode::ConfigurationError;
            }
            auto* service = nativeSessions.get();
            auto* canonical = nativeCanonical.get();
            asyncAdminRead = std::make_unique<adminHttp::CoroutineAdministrationReadAdapter>(
                *nativeHandler, limiter.value(),
                [service](fnd::SecretString bearer) {
                    return service->authenticate(std::move(bearer));
                },
                [canonical](identity::IdentityId actor) {
                    return canonical->readMembersAsync(std::move(actor));
                });
            nativeHandler = asyncAdminRead.get();
            nativeMethods.emplace_back("/admin/local-members", gateway::HttpMethod::Get);
        }
        if (nativeRecoveryEnabled) {
            nativeMethods.emplace_back("/auth/recovery-codes", gateway::HttpMethod::Post);
        }
        if (nativeConsentEnabled) {
            nativeMethods.emplace_back("/oauth/consents", gateway::HttpMethod::Get);
            nativeMethods.emplace_back("/oauth/consents/revoke", gateway::HttpMethod::Post);
        }
        gatewayHttp::CoroutineRouteOverlay nativeRoutes{
            healthApi, *nativeHandler, std::move(nativePaths),
            std::move(nativeMethods)};
        if (nativeProtectedGatewayEnabled) {
            if (!nativeGatewayCore || !nativeGatewayVerifier || !nativeCanonical || !nativeGatewayAudit) {
                reportStartupFailure(fnd::Error{fnd::ErrorCode::FailedPrecondition,
                    "Native protected gateway dependencies are unavailable."});
                return ExitCode::ConfigurationError;
            }
            gatewayHttp::CoroutineProtectedGatewayAdapter nativeGateway{
                *nativeGatewayCore, *proxy.value(), nativeRoutes,
                [verifier = nativeGatewayVerifier.get()](fnd::SecretString bearer) {
                    return verifier->verifyAsync(std::move(bearer));
                },
                [reader = nativeCanonical.get(), sink = nativeGatewayAudit.get(),
                 engine = memberPolicy->get()](session::AuthenticatedSession authenticated,
                    gateway::Route route, fnd::CorrelationId correlation)
                    -> boost::asio::awaitable<policy::AuthorizationDecision> {
                    auto context = co_await reader->readAuthorizationContextAsync(
                        authenticated, route.organization(), route.action(), route.resource());
                    auto decision = context
                        ? policy::evaluateProtected(engine, context.value())
                        : policy::AuthorizationDecision::indeterminate(
                            "Trusted authorization context failed: "
                            + std::string{context.error().internalDetail()});
                    if (!decision.isPermitted()) {
                        const auto recorded = co_await sink->recordAsync(
                            std::move(authenticated), route.organization(), route.action(),
                            route.resource(), decision, std::move(correlation));
                        if (!recorded)
                            co_return policy::AuthorizationDecision::indeterminate(
                                "Authorization was denied and its security audit could not be persisted.");
                    }
                    co_return decision;
                }};
            return runListener(platform, nativeGateway, logger);
        }
        return runListener(platform, nativeRoutes, logger);
    };

    const auto runWithScim = [&](
        gateway::HttpHandler& fallback,
        gatewayHttp::CoroutineHttpHandler& nativeEnterprise) -> ExitCode {
        if (!scimBearerToken) return runWithEvidence(fallback, nativeEnterprise);
        scimHttp::Api scimApi{
            scimService, scimBearerToken->clone(), limiter.value(), fallback};
        return runWithEvidence(scimApi, nativeEnterprise);
    };

    const auto runWithEnterprise = [&](gateway::HttpHandler& fallback) -> ExitCode {
        authHttp::EnterpriseAuthenticationHttpApi enterpriseApi{
            nativeAuthentication ? *nativeAuthentication : authentication,
            sessions, limiter.value(), fallback, nativeSessions.get()};
        if (nativeWeb3Enabled) {
            // Compose native Web3 ABOVE the native LDAP adapter. Its guarded
            // coroutine fallback delegates LDAP without touching the legacy
            // Web3 handler, and the exact-path overlay decides which opt-ins
            // actually receive native requests.
            authHttp::Web3AuthenticationHttpApi nativeWeb3Api{
                *nativeAuthentication, providers, sessions, limiter.value(),
                enterpriseApi, nullptr, nativeSessions.get()};
            return runWithScim(enterpriseApi, nativeWeb3Api);
        }
        return runWithScim(enterpriseApi, enterpriseApi);
    };

    const auto runWithWeb3 = [&](gateway::HttpHandler& fallback,
                                 session::DelegatedAccessAuthenticator* delegated) -> ExitCode {
        authHttp::Web3AuthenticationHttpApi web3Api{
            authentication, providers, sessions, limiter.value(), fallback, delegated};
        return runWithEnterprise(web3Api);
    };

    const auto runWithPasskey = [&](gateway::HttpHandler& fallback,
                                    session::DelegatedAccessAuthenticator* delegated) -> ExitCode {
        if (!passkeyService) return runWithWeb3(fallback, delegated);
        authHttp::PasskeyAuthenticationHttpApi passkeyApi{
            *passkeyService, authentication, sessions, limiter.value(), fallback};
        return runWithWeb3(passkeyApi, delegated);
    };

    const auto runWithAccount = [&](gateway::HttpHandler& fallback,
                                    session::DelegatedAccessAuthenticator* delegated) -> ExitCode {
        if (!platform.account().enabled()) return runWithPasskey(fallback, delegated);

        auto verificationMaterial = deriveSecret(
            platform.security().tokenSigningKey(), "openproof/account-verification-key/v1");
        if (!verificationMaterial) {
            reportStartupFailure(verificationMaterial.error());
            return ExitCode::InternalError;
        }
        auto verificationKey = account::VerificationKey::create(
            std::move(verificationMaterial).value());
        auto accountPolicy = account::AccountPolicy::create(
            std::chrono::hours{24}, std::chrono::minutes{10},
            std::chrono::minutes{30}, 8U);
        auto deliveryProxyConfig = gatewayHttp::ProxyConfig::create(
            32U * 1024U, 256U * 1024U,
            std::string{platform.account().deliveryCaFile()});
        if (!verificationKey || !accountPolicy || !deliveryProxyConfig) {
            reportStartupFailure(fnd::Error{fnd::ErrorCode::InvalidArgument});
            return ExitCode::ConfigurationError;
        }
        auto deliveryTransport = gatewayHttp::BeastProxyTransport::create(
            std::move(deliveryProxyConfig).value());
        if (!deliveryTransport) {
            reportStartupFailure(deliveryTransport.error());
            return ExitCode::ConfigurationError;
        }
        auto delivery = accountDelivery::createWebhookVerificationDelivery(
            *deliveryTransport.value(),
            std::string{platform.account().deliveryHost()},
            platform.account().deliveryPort(), platform.account().deliveryTls(),
            std::string{platform.account().deliveryPath()},
            platform.account().deliveryAuthorization().clone(),
            std::chrono::seconds{10});
        if (!delivery) {
            reportStartupFailure(delivery.error());
            return ExitCode::ConfigurationError;
        }
        account::AccountService accountService{
            identity::OrganizationId{std::string{platform.auth().organizationId()}},
            providerId,
            idp::ProviderId{std::string{platform.account().phoneProviderId()}},
            identities, externalIdentities, identityProviderStore,
            *accounts.value(), recoveryCodes.value(), accountRepository, sessions, clock,
            std::move(verificationKey).value(), accountPolicy.value(), *delivery.value()};
        accountHttp::AccountHttpApi accountApi{
            accountService, authentication, sessions, limiter.value(), fallback, delegated};
        return runWithPasskey(accountApi, delegated);
    };

    if (!platform.oidc().enabled()) {
        gateway::Gateway gatewayCore{
            router, sessions, access, limiter.value(), discovery, loadBalancer,
            circuits.value(), *proxy.value(), signer.value(), std::chrono::seconds{10}};
        if (nativeProtectedGatewayEnabled) nativeGatewayCore = &gatewayCore;
        adminHttp::AdministrationHttpApi administrationApi{
            sessions, *administrationRepository.value(), identities, memberships,
            limiter.value(),
            identity::OrganizationId{std::string{platform.auth().organizationId()}},
            providerId, clock, gatewayCore};
        authHttp::AuthenticationHttpApi authApi{
            authentication, sessions, recoveryCodes.value(), *accounts.value(),
            limiter.value(), providerId, administrationApi};
        authHttp::FederatedAuthenticationHttpApi federatedApi{
            authentication, providers, sessions, limiter.value(), authApi};
        return runWithAccount(federatedApi, nullptr);
    }

    auto clientSecretMaterial = oauthClientSecretMaterial(platform.security());
    auto authorizationCodeMaterial = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/oauth-authorization-code-key/v1");
    auto tokenMaterial = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/oauth-token-key/v1");
    auto deviceAuthorizationMaterial = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/oauth-device-authorization-key/v1");
    if (!clientSecretMaterial || !authorizationCodeMaterial || !tokenMaterial
        || !deviceAuthorizationMaterial) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    auto clientSecretKey = client::ClientSecretKey::create(
        std::move(clientSecretMaterial).value());
    auto authorizationCodeKey = oauth::AuthorizationCodeKey::create(
        std::move(authorizationCodeMaterial).value());
    auto tokenKey = token::TokenKey::create(std::move(tokenMaterial).value());
    auto deviceAuthorizationKey = oauth::DeviceAuthorizationKey::create(
        std::move(deviceAuthorizationMaterial).value());
    auto tokenPolicy = token::TokenPolicy::create(
        std::chrono::minutes{15}, std::chrono::hours{24 * 30});
    auto oidcIssuer = oidc::Issuer::create(std::string{platform.oidc().issuer()});
    auto oidcPolicy = oidc::OidcPolicy::create(std::chrono::minutes{5});
    auto oidcSigner = security::RsaSha256Signer::create(
        platform.oidc().signingKey().clone(), std::string{platform.oidc().keyId()});
    auto previousOidcKeys = loadPreviousOidcKeys(
        platform.oidc().previousSigningKeysDirectory(), platform.oidc().keyId());
    if (!clientSecretKey || !authorizationCodeKey || !tokenKey
        || !deviceAuthorizationKey || !tokenPolicy || !oidcIssuer || !oidcPolicy
        || !oidcSigner || !previousOidcKeys) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::InvalidArgument});
        return ExitCode::ConfigurationError;
    }

    postgres::PostgresResourceRepository resourceRepository{*pool.value()};
    postgres::PostgresConsentRepository consentRepository{*pool.value()};
    resource::ResourceRegistry resourceRegistry{resourceRepository, clock};
    consent::ConsentService consentService{consentRepository, clock};

    application::ApplicationRegistry applicationRegistry{identityProviderStore, clock};
    client::ClientManager clientManager{
        identityProviderStore, identityProviderStore, clock,
        std::move(clientSecretKey).value()};
    resource::ServiceIdentityService serviceIdentityService{
        identity::OrganizationId{std::string{platform.auth().organizationId()}},
        identities, resourceRepository, clientManager, clock};
    oauth::AuthorizationService authorizationService{
        clientManager, identityProviderStore, clock,
        std::move(authorizationCodeKey).value(), std::chrono::minutes{5}};
    token::TokenService tokenService{
        identityProviderStore, clientManager, clock, std::move(tokenKey).value(),
        std::move(tokenPolicy).value()};
    oauth::DeviceAuthorizationService deviceAuthorizationService{
        identityProviderStore, clientManager, clock,
        std::move(deviceAuthorizationKey).value(), std::chrono::minutes{10},
        std::chrono::seconds{5}};
    oauth::PushedAuthorizationService pushedAuthorizationService{
        identityProviderStore, clock, std::chrono::seconds{90}};
    oauth::JarService jarService{identityProviderStore, identityProviderStore, clock};
    oidc::OpenIdProvider openIdProvider{
        std::move(oidcIssuer).value(), clock, std::move(oidcSigner).value(),
        identityProviderStore, std::move(oidcPolicy).value(),
        std::move(previousOidcKeys).value()};
    nativeOidcProvider = &openIdProvider;
    oauth::DpopService dpopService{
        identityProviderStore, clock, std::chrono::minutes{5}};
    std::optional<fnd::SecretString> mtlsForwardingKey;
    if (auto configuredKey = environment.get("OPENPROOF_MTLS_FORWARDING_KEY");
        configuredKey.has_value()) {
        if (configuredKey->size() < 32U) {
            reportStartupFailure(fnd::Error{
                fnd::ErrorCode::FailedPrecondition,
                "OPENPROOF_MTLS_FORWARDING_KEY must contain at least 32 bytes."});
            return ExitCode::ConfigurationError;
        }
        mtlsForwardingKey.emplace(std::move(configuredKey).value());
    }
    oauthHttp::SenderProofVerifier senderProof{
        dpopService, identityProviderStore, clock, std::string{openIdProvider.issuer()},
        std::move(mtlsForwardingKey)};

    gateway::Gateway gatewayCore{
        router, sessions, access, limiter.value(), discovery, loadBalancer,
        circuits.value(), *proxy.value(), signer.value(), std::chrono::seconds{10},
        &tokenService, &senderProof};
    adminHttp::AdministrationHttpApi administrationApi{
        sessions, *administrationRepository.value(), identities, memberships,
        limiter.value(),
        identity::OrganizationId{std::string{platform.auth().organizationId()}},
        providerId, clock, gatewayCore};
    authHttp::AuthenticationHttpApi authApi{
        authentication, sessions, recoveryCodes.value(), *accounts.value(),
        limiter.value(), providerId, administrationApi};
    authHttp::FederatedAuthenticationHttpApi federatedApi{
        authentication, providers, sessions, limiter.value(), authApi, &tokenService};
    oauthHttp::OAuthHttpApi oauthApi{
        authorizationService, tokenService, openIdProvider, clientManager,
        authentication, sessions, providerId, consentService, resourceRegistry,
        serviceIdentityService, deviceAuthorizationService, pushedAuthorizationService,
        jarService, senderProof, limiter.value(), federatedApi};
    applicationHttp::ApplicationManagementHttpApi applicationApi{
        applicationRegistry, identityProviderStore, clientManager,
        identityProviderStore, resourceRegistry, serviceIdentityService, jarService,
        sessions, memberships, limiter.value(),
        identity::OrganizationId{std::string{platform.auth().organizationId()}},
        oauthApi};
    return runWithAccount(applicationApi, &tokenService);
}

/** @brief Reports a startup failure on stderr, before a logger may exist. */
void reportStartupFailure(const fnd::Error& failure)
{
    // The operator-only detail is shown here because stderr at startup is an
    // operator channel, not a client response.
    std::print(stderr, "{}: {} [{}]\n", kProgramName, failure.message(),
               fnd::errorCodeName(failure.code()));
    if (failure.hasInternalDetail()) {
        std::print(stderr, "{}: {}\n", kProgramName, failure.internalDetail());
    }
}

/**
 * @brief Reports the process locale without making wire encoding depend on it.
 *
 * OpenProof protocol, JSON and log text are UTF-8 by contract. The host locale
 * is diagnostic metadata only; changing LC_ALL/LC_CTYPE/LANG must never alter
 * protocol encoding or require an experimental standard-library runtime.
 */
[[nodiscard]] std::optional<std::string> localeEnvironment()
{
    constexpr std::string_view names[]{"LC_ALL", "LC_CTYPE", "LANG"};
    for (const std::string_view name : names) {
        const std::string key{name};
        const char* const value = std::getenv(key.c_str());
        if (value != nullptr && value[0] != '\0') {
            return std::string{value};
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool localeDeclaresUtf8(std::string_view locale)
{
    std::string normalized;
    normalized.reserve(locale.size());
    for (const char symbol : locale) {
        const auto byte = static_cast<unsigned char>(symbol);
        if (std::isalnum(byte) != 0) {
            normalized.push_back(static_cast<char>(std::tolower(byte)));
        }
    }
    return normalized.find("utf8") != std::string::npos;
}

[[nodiscard]] std::vector<obs::LogField> textEncodingFields()
{
    std::vector<obs::LogField> fields{
        obs::LogField::text("text_encoding_policy", "UTF-8"),
    };

    const std::optional<std::string> locale = localeEnvironment();
    if (!locale.has_value()) {
        fields.push_back(obs::LogField::null("locale_environment"));
        fields.push_back(obs::LogField::null("locale_environment_declares_utf8"));
        return fields;
    }

    fields.push_back(obs::LogField::text("locale_environment", *locale));
    fields.push_back(obs::LogField::boolean("locale_environment_declares_utf8",
                                            localeDeclaresUtf8(*locale)));
    return fields;
}

[[nodiscard]] std::shared_ptr<obs::LogSink> makeSink(const cfg::LoggingConfig& logging)
{
    if (logging.console()) {
        return std::make_shared<obs::ConsoleLogSink>();
    }
    // Until a file or collector transport exists, a deployment that disables the
    // console still gets a sink; records are retained rather than discarded, so
    // that "logging is off" never silently means "security events vanish".
    return std::make_shared<obs::MemoryLogSink>();
}

[[nodiscard]] ExitCode run(std::span<const std::string_view> arguments)
{
    const fnd::Result<CommandLine> commandLine = CommandLine::parse(arguments);
    if (!commandLine.has_value()) {
        reportStartupFailure(commandLine.error());
        printUsage();
        return ExitCode::UsageError;
    }

    if (commandLine->showHelp()) {
        printUsage();
        return ExitCode::Success;
    }
    if (commandLine->showVersion()) {
        std::println("{} {}", kProgramName, kVersion);
        return ExitCode::Success;
    }
    if (commandLine->printDefaultConfig()) {
        if constexpr (!kDefaultConfigEmbedded) {
            std::print(stderr,
                       "{}: this build was produced by a compiler without #embed, so the "
                       "default configuration is not available from the binary.\n",
                       kProgramName);
            return ExitCode::UsageError;
        } else {
            std::print("{}", kDefaultConfig);
            return ExitCode::Success;
        }
    }
    if (!commandLine->runServer() && !commandLine->bootstrapAdmin()
        && !commandLine->repairInitialOwner()
        && !commandLine->checkConfig() && !commandLine->rekeyTotp()
        && !commandLine->rotateMasterKey()
        && !commandLine->materializePersistentKeys()) {
        printUsage();
        return ExitCode::UsageError;
    }

    const cfg::SystemEnvironment environment;
    fnd::Result<cfg::PlatformConfig> configuration =
        commandLine->configPath().has_value()
            ? cfg::PlatformConfig::loadFromFile(*commandLine->configPath(), environment)
            : cfg::PlatformConfig::loadFromEnvironment(environment);

    if (!configuration.has_value()) {
        reportStartupFailure(configuration.error());
        return ExitCode::ConfigurationError;
    }

    const cfg::PlatformConfig& platform = configuration.value();

    if (platform.security().passwordHashAlgorithm() == "argon2id"
        && !credentials::PasswordHasher::supportsArgon2id()) {
        reportStartupFailure(fnd::Error{
            fnd::ErrorCode::FailedPrecondition,
            "Argon2id selected but OpenProof was built without a usable libsodium backend."});
        return ExitCode::ConfigurationError;
    }

    if (commandLine->checkConfig()) {
        std::println("OpenProof configuration is valid.");
        return ExitCode::Success;
    }

    if (commandLine->materializePersistentKeys()) {
        return runPersistentKeyMaterialization(platform, commandLine.value());
    }

    if (commandLine->rekeyTotp()) {
        return runTotpRekey(platform, environment, commandLine.value());
    }
    if (commandLine->rotateMasterKey()) {
        return runMasterKeyRotation(platform, environment, commandLine.value());
    }

    const auto clock = std::make_shared<const fnd::SystemClockSource>();
    const obs::Logger logger{makeSink(platform.logging()), clock, platform.logging().level()};

    if (commandLine->bootstrapAdmin()) {
        return runBootstrapAdmin(platform, environment, commandLine.value(), *clock);
    }
    if (commandLine->repairInitialOwner()) {
        return runRepairInitialOwner(platform, commandLine.value(), *clock);
    }

    std::vector<obs::LogField> startupFields{
        obs::LogField::text("version", std::string{kVersion}),
        obs::LogField::text("bind_address", std::string{platform.server().bindAddress()}),
        obs::LogField::integer("port", static_cast<std::int64_t>(platform.server().port())),
        obs::LogField::text("log_level", std::string{obs::logLevelName(platform.logging().level())}),
        obs::LogField::boolean("token_signing_key_configured",
                               !platform.security().tokenSigningKey().empty()),
        // Contracts are always compiled in; the operator still needs to know
        // which evaluation semantic this binary was built with, because
        // `observe` does not stop a process whose invariants have broken.
        obs::LogField::text("contract_semantic", std::string{OPENPROOF_CONTRACT_SEMANTIC}),
    };

    const std::vector<obs::LogField> encodingFields = textEncodingFields();
    startupFields.insert(startupFields.end(), encodingFields.begin(), encodingFields.end());

    logger.info("openproof server starting", startupFields);

    return runGatewayServer(platform, environment, *clock, logger);
}

}

int main(int argc, char** argv)
{
    try {
        std::vector<std::string_view> arguments;
        arguments.reserve(argc > 0 ? static_cast<std::size_t>(argc - 1) : 0U);
        for (int index = 1; index < argc; ++index) {
            arguments.emplace_back(argv[index]);
        }

        return toInt(run(arguments));
    } catch (const std::exception& failure) {
        // Last line of defence. An escaped exception is a defect, so it is
        // reported plainly rather than translated into a success exit code.
        std::print(stderr, "{}: fatal: {}\n", kProgramName, failure.what());
        return toInt(ExitCode::InternalError);
    } catch (...) {
        std::print(stderr, "{}: fatal: unknown error\n", kProgramName);
        return toInt(ExitCode::InternalError);
    }
}
