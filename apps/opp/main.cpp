// Composition root of the OpenProof Protocol server.
//
// This translation unit is the only place allowed to know how the platform is
// assembled: it reads configuration, constructs the logger, builds the provider
// registry and wires the layers together. Every other unit receives what it
// needs and never reaches for a global.
//
// The `server` subcommand composes and runs the bounded HTTP reverse gateway.

#include <algorithm>
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

import openproof.config;
import openproof.foundation;
import openproof.identity.core;
import openproof.observability;
import openproof.gateway;
import openproof.gateway.http;
import openproof.policy;
import openproof.security;
import openproof.session;

namespace {

namespace fnd = openproof::foundation;
namespace cfg = openproof::config;
namespace obs = openproof::observability;
namespace identity = openproof::identity::core;
namespace gateway = openproof::gateway;
namespace gatewayHttp = openproof::gateway::http;
namespace policy = openproof::policy;
namespace security = openproof::security;
namespace session = openproof::session;

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

    [[nodiscard]] const std::optional<std::filesystem::path>& configPath() const noexcept
    {
        return m_configPath;
    }

private:
    bool m_showHelp{false};
    bool m_showVersion{false};
    bool m_printDefaultConfig{false};
    bool m_runServer{false};
    std::optional<std::filesystem::path> m_configPath;
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
            parsed.m_configPath = std::filesystem::path{arguments[index]};
        } else {
            return fnd::fail(fnd::ErrorCode::InvalidArgument,
                             std::string{"Unrecognized option: "} + std::string{argument});
        }
    }

    return parsed;
}

void printUsage()
{
    std::println("{} {} - OpenProof Protocol server", kProgramName, kVersion);
    std::println("");
    std::println("Usage:");
    std::println("  {} server [options]", kProgramName);
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
    std::println("");
    std::println("Environment overrides:");
    std::println("  OPENPROOF_SERVER_BIND_ADDRESS, OPENPROOF_SERVER_PORT,");
    std::println("  OPENPROOF_LOGGING_LEVEL, OPENPROOF_LOGGING_CONSOLE");
}

volatile std::sig_atomic_t g_shutdownRequested = 0;

extern "C" void requestShutdown(int) noexcept
{
    g_shutdownRequested = 1;
}

class DenyAccess final : public gateway::AccessController {
public:
    [[nodiscard]] policy::AuthorizationDecision authorize(
        const session::AuthenticatedSession&, const gateway::Route&) override
    {
        return policy::AuthorizationDecision::deny(
            "No protected-route policy is configured in this process.");
    }
};

[[nodiscard]] fnd::Status addPublicRoutes(gateway::Router& router,
                                          std::string_view prefix)
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

[[nodiscard]] ExitCode runGatewayServer(const cfg::PlatformConfig& platform,
                                        const fnd::ClockSource& clock,
                                        const obs::Logger& logger)
{
    const fnd::Status deployment = platform.validateServerDeployment();
    if (!deployment.has_value()) {
        reportStartupFailure(deployment.error());
        return ExitCode::ConfigurationError;
    }

    auto sessionDigest = security::hmacSha256(
        platform.security().tokenSigningKey(), "openproof/session-key/v1");
    auto contextDigest = security::hmacSha256(
        platform.security().tokenSigningKey(), "openproof/trusted-context-key/v1");
    if (!sessionDigest.has_value() || !contextDigest.has_value()) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }
    auto sessionKey = session::SessionKey::create(
        fnd::SecretString{fnd::toHex(sessionDigest.value())});
    auto contextKey = gateway::TrustedContextKey::create(
        fnd::SecretString{fnd::toHex(contextDigest.value())});
    if (!sessionKey.has_value() || !contextKey.has_value()) {
        reportStartupFailure(fnd::Error{fnd::ErrorCode::Internal});
        return ExitCode::InternalError;
    }

    session::InMemorySessionRepository sessionRepository;
    session::SessionService sessions{
        sessionRepository, clock, std::move(sessionKey).value(),
        session::SessionPolicy::create(std::chrono::hours{8},
                                       std::chrono::minutes{30}).value()};
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
    const fnd::Status routes = addPublicRoutes(router, platform.gateway().routePrefix());
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
    DenyAccess access;
    gateway::Gateway gatewayCore{
        router, sessions, access, limiter.value(), discovery, loadBalancer,
        circuits.value(), *proxy.value(), signer.value(), std::chrono::seconds{10}};

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
    gatewayHttp::BeastHttpServer server{gatewayCore, std::move(serverConfig).value()};
    const fnd::Status started = server.start();
    if (!started) {
        reportStartupFailure(started.error());
        return ExitCode::InternalError;
    }
    const std::vector<obs::LogField> listenerFields{
        obs::LogField::integer("bound_port", static_cast<std::int64_t>(server.boundPort())),
        obs::LogField::text("upstream_host", std::string{platform.gateway().upstreamHost()}),
        obs::LogField::boolean("upstream_tls", platform.gateway().upstreamTls())};
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
    if (!commandLine->runServer()) {
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
