// Composition root of the OpenProof Protocol server.
//
// This translation unit is the only place allowed to know how the platform is
// assembled: it reads configuration, constructs the logger, builds the provider
// registry and wires the layers together. Every other unit receives what it
// needs and never reaches for a global.
//
// The `server` subcommand composes and runs the bounded HTTP reverse gateway.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <version>

#if defined(__cpp_lib_text_encoding) && __cpp_lib_text_encoding >= 202306
#include <text_encoding>
#define OPENPROOF_HAS_TEXT_ENCODING 1
#else
#define OPENPROOF_HAS_TEXT_ENCODING 0
#endif

import openproof.administration;
import openproof.administration.http;
import openproof.audit;
import openproof.config;
import openproof.authentication;
import openproof.authentication.http;
import openproof.credentials;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.observability;
import openproof.gateway;
import openproof.gateway.http;
import openproof.policy;
import openproof.provider.local;
import openproof.security;
import openproof.session;
import openproof.storage.postgres;

namespace {

namespace fnd = openproof::foundation;
namespace administration = openproof::administration;
namespace adminHttp = openproof::administration::http;
namespace audit = openproof::audit;
namespace cfg = openproof::config;
namespace auth = openproof::authentication;
namespace authHttp = openproof::authentication::http;
namespace credentials = openproof::credentials;
namespace obs = openproof::observability;
namespace identity = openproof::identity::core;
namespace gateway = openproof::gateway;
namespace gatewayHttp = openproof::gateway::http;
namespace policy = openproof::policy;
namespace local = openproof::provider::local;
namespace security = openproof::security;
namespace session = openproof::session;
namespace postgres = openproof::storage::postgres;
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
    std::optional<std::filesystem::path> m_configPath;
    std::optional<std::string> m_organizationName;
    std::optional<std::string> m_identityId;
    std::optional<std::string> m_externalSubject;
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
        } else {
            return fnd::fail(fnd::ErrorCode::InvalidArgument,
                             std::string{"Unrecognized option: "} + std::string{argument});
        }
    }

    if (parsed.m_showHelp) return parsed;
    if (parsed.m_runServer && parsed.m_bootstrapAdmin) {
        return fnd::fail(fnd::ErrorCode::InvalidArgument,
                         "Only one subcommand may be selected.");
    }
    const bool hasBootstrapOption = parsed.m_organizationName.has_value()
        || parsed.m_identityId.has_value() || parsed.m_externalSubject.has_value();
    if (parsed.m_bootstrapAdmin
        && (!parsed.m_configPath.has_value() || !parsed.m_organizationName.has_value()
            || !parsed.m_identityId.has_value()
            || !parsed.m_externalSubject.has_value())) {
        return fnd::fail(
            fnd::ErrorCode::InvalidArgument,
            "bootstrap-admin requires --config, --organization-name, --identity-id and --subject.");
    }
    if (!parsed.m_bootstrapAdmin && hasBootstrapOption) {
        return fnd::fail(fnd::ErrorCode::InvalidArgument,
                         "Bootstrap options require the bootstrap-admin subcommand.");
    }

    return parsed;
}

void printUsage()
{
    std::println("{} {} - OpenProof Protocol server", kProgramName, kVersion);
    std::println("");
    std::println("Usage:");
    std::println("  {} server [options]", kProgramName);
    std::println("  {} bootstrap-admin --config <path> --organization-name <name>",
                 kProgramName);
    std::println("      --identity-id <id> --subject <local-subject>");
    std::println("  {} [--help | --version | --print-default-config]", kProgramName);
    std::println("");
    std::println("Options:");
    std::println("  -c, --config <path>  Load configuration from a TOML file.");
    std::println("                       Without it, configuration comes from the");
    std::println("                       environment and built-in defaults.");
    std::println("  --print-default-config");
    std::println("                       Print the configuration defaults compiled into");
    std::println("                       this binary and exit.");
    std::println("  -h, --help           Show this message and exit.");
    std::println("  -V, --version        Show the version and exit.");
    std::println("  --organization-name  Display name of the initial tenant.");
    std::println("  --identity-id        Canonical id for the initial owner.");
    std::println("  --subject            Local login subject; never reused as identity id.");
    std::println("");
    std::println("Environment overrides:");
    std::println("  OPENPROOF_SERVER_BIND_ADDRESS, OPENPROOF_SERVER_PORT,");
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
                policy::Action{actionName}, policy::Resource{resourceName});
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

    auto passwordSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/password-pepper/v1");
    auto totpSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/totp-encryption-key/v1");
    auto auditSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/audit-chain-key/v1");
    if (!passwordSecret || !totpSecret || !auditSecret) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    auto passwordHasher = credentials::PasswordHasher::create(
        std::move(passwordSecret).value(), credentials::PasswordPolicy::recommended());
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
        std::move(totpKey).value(), 1U,
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
        std::chrono::seconds{15}, 4'096U, workers);
    if (!serverConfig) {
        reportStartupFailure(serverConfig.error());
        return ExitCode::ConfigurationError;
    }
    gatewayHttp::BeastHttpServer server{handler, std::move(serverConfig).value()};
    const fnd::Status started = server.start();
    if (!started) {
        reportStartupFailure(started.error());
        return ExitCode::InternalError;
    }
    const std::vector<obs::LogField> listenerFields{
        obs::LogField::integer("bound_port", static_cast<std::int64_t>(server.boundPort())),
        obs::LogField::text("upstream_host", std::string{platform.gateway().upstreamHost()}),
        obs::LogField::boolean("upstream_tls", platform.gateway().upstreamTls()),
        obs::LogField::boolean("authentication_enabled", platform.auth().enabled())};
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
                                        const fnd::ClockSource& clock,
                                        const obs::Logger& logger)
{
    const fnd::Status deployment = platform.validateServerDeployment();
    if (!deployment.has_value()) {
        reportStartupFailure(deployment.error());
        return ExitCode::ConfigurationError;
    }

    auto sessionSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/session-key/v1");
    auto contextSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/trusted-context-key/v1");
    if (!sessionSecret || !contextSecret) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    auto sessionKey = session::SessionKey::create(
        std::move(sessionSecret).value());
    auto contextKey = gateway::TrustedContextKey::create(
        std::move(contextSecret).value());
    if (!sessionKey.has_value() || !contextKey.has_value()) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }

    auto limiter = gateway::TokenBucketRateLimiter::create(
        clock, 1'000.0, 100.0, 100'000U);
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
        return runListener(platform, gatewayCore, logger);
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

    postgres::PostgresIdentityRepository identities{*pool.value()};
    postgres::PostgresExternalIdentityDirectory externalIdentities{*pool.value()};
    postgres::PostgresOrganizationRepository organizations{*pool.value()};
    postgres::PostgresMembershipRepository memberships{*pool.value()};
    postgres::PostgresSessionRepository sessionRepository{*pool.value()};
    postgres::PostgresAuthenticationTransactionStore transactions{*pool.value()};
    postgres::PostgresRecoveryCodeRepository recoveryRepository{*pool.value()};

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

    auto passwordSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/password-pepper/v1");
    auto totpSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/totp-encryption-key/v1");
    auto recoverySecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/recovery-code-pepper/v1");
    auto auditSecret = deriveSecret(
        platform.security().tokenSigningKey(), "openproof/audit-chain-key/v1");
    if (!passwordSecret || !totpSecret || !recoverySecret || !auditSecret) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    auto administrationPasswordHasher = credentials::PasswordHasher::create(
        passwordSecret->clone(), credentials::PasswordPolicy::recommended());
    auto administrationTotpKey = security::AeadKey::create(totpSecret->clone());
    auto administrationAuditKey = audit::AuditKey::create(auditSecret->clone());
    auto authorizationAuditKey = audit::AuditKey::create(
        std::move(auditSecret).value());
    auto passwordHasher = credentials::PasswordHasher::create(
        std::move(passwordSecret).value(), credentials::PasswordPolicy::recommended());
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
        credentials::TotpPolicy::recommended(), std::move(totpKey).value(), 1U,
        providerId);
    auto recoveryCodes = credentials::RecoveryCodeService::create(
        recoveryRepository, std::move(recoverySecret).value());
    auto administrationRepository = postgres::PostgresAdministrationRepository::create(
        *pool.value(), std::move(administrationPasswordHasher).value(),
        std::move(administrationTotpKey).value(), 1U, providerId,
        std::move(administrationAuditKey).value());
    if (!accounts || !recoveryCodes || !administrationRepository) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }

    idp::ProviderRegistry providers;
    auto provider = std::make_unique<local::LocalAuthenticationProvider>(
        providerId, *accounts.value(), clock, std::chrono::minutes{5});
    const fnd::Status registered = providers.registerProvider(std::move(provider));
    auth::ProviderTrustPolicy trust;
    const fnd::Status trusted = trust.trust(providerId, idp::AssuranceLevel::Ial2);
    if (!registered || !trusted) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    auth::AuthenticationService authentication{
        providers, transactions, externalIdentities, clock, std::move(trust),
        std::chrono::minutes{5}};
    session::SessionService sessions{
        sessionRepository, clock, std::move(sessionKey).value(), sessionPolicy};
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
    gateway::Gateway gatewayCore{
        router, sessions, access, limiter.value(), discovery, loadBalancer,
        circuits.value(), *proxy.value(), signer.value(), std::chrono::seconds{10}};
    adminHttp::AdministrationHttpApi administrationApi{
        sessions, *administrationRepository.value(), limiter.value(),
        identity::OrganizationId{std::string{platform.auth().organizationId()}},
        providerId, clock, gatewayCore};
    authHttp::AuthenticationHttpApi authApi{
        authentication, sessions, recoveryCodes.value(), limiter.value(),
        providerId, administrationApi};
    return runListener(platform, authApi, logger);
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
 * @brief Describes the environment's text encoding for the startup record.
 *
 * Not decoration. The platform emits JSON log records and JSON error envelopes,
 * and its escaper passes bytes at or above 0x80 through unchanged on the
 * assumption that they are UTF-8. On a host whose environment encoding is not
 * UTF-8, that assumption produces malformed records precisely when an operator
 * is reading them during an incident. Recording the encoding at startup makes
 * the assumption auditable instead of implicit.
 */
[[nodiscard]] std::vector<obs::LogField> textEncodingFields()
{
#if OPENPROOF_HAS_TEXT_ENCODING
    const std::text_encoding environment = std::text_encoding::environment();
    const std::text_encoding literal = std::text_encoding::literal();

    return {
        obs::LogField::text("text_encoding_environment", std::string{environment.name()}),
        obs::LogField::text("text_encoding_literal", std::string{literal.name()}),
        obs::LogField::boolean("text_encoding_is_utf8",
                               environment.mib() == std::text_encoding::id::UTF8),
    };
#else
    // The field is emitted as an explicit null rather than omitted: "this build
    // could not determine the encoding" is a different fact from "nobody asked".
    return {obs::LogField::null("text_encoding_environment")};
#endif
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
    if (!commandLine->runServer() && !commandLine->bootstrapAdmin()) {
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

    const auto clock = std::make_shared<const fnd::SystemClockSource>();
    const obs::Logger logger{makeSink(platform.logging()), clock, platform.logging().level()};

    if (commandLine->bootstrapAdmin()) {
        return runBootstrapAdmin(platform, environment, commandLine.value(), *clock);
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

    return runGatewayServer(platform, *clock, logger);
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
