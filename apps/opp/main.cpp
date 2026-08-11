// Composition root of the OpenProof Protocol server.
//
// This translation unit is the only place allowed to know how the platform is
// assembled: it reads configuration, constructs the logger, builds the provider
// registry and wires the layers together. Every other unit receives what it
// needs and never reaches for a global.
//
// Current development scope: the process starts, validates its configuration,
// composes the trusted authentication boundary, emits structured startup state,
// and exits cleanly. There is no listener yet, and none is pretended.

#include <cstdint>
#include <chrono>
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
import openproof.authentication;
import openproof.foundation;
import openproof.identity.core;
import openproof.identity.provider;
import openproof.observability;

namespace {

namespace fnd = openproof::foundation;
namespace cfg = openproof::config;
namespace auth = openproof::authentication;
namespace obs = openproof::observability;
namespace identity = openproof::identity::core;
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

    [[nodiscard]] const std::optional<std::filesystem::path>& configPath() const noexcept
    {
        return m_configPath;
    }

private:
    bool m_showHelp{false};
    bool m_showVersion{false};
    bool m_printDefaultConfig{false};
    std::optional<std::filesystem::path> m_configPath;
};

fnd::Result<CommandLine> CommandLine::parse(std::span<const std::string_view> arguments)
{
    CommandLine parsed;

    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const std::string_view argument = arguments[index];

        if (argument == "--help" || argument == "-h") {
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
    std::println("  {} [options]", kProgramName);
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

    // The provider registry starts empty by design. The SPI and trusted broker
    // exist, but no concrete provider exists yet, and none is fabricated.
    idp::ProviderRegistry providers;
    idp::InMemoryAuthenticationTransactionStore authenticationTransactions;
    identity::InMemoryExternalIdentityDirectory externalIdentities;
    auth::ProviderTrustPolicy providerTrust;
    const auth::AuthenticationService authentication{
        providers, authenticationTransactions, externalIdentities, *clock,
        std::move(providerTrust),
        std::chrono::minutes{5}};
    static_cast<void>(authentication);

    std::vector<obs::LogField> startupFields{
        obs::LogField::text("version", std::string{kVersion}),
        obs::LogField::text("bind_address", std::string{platform.server().bindAddress()}),
        obs::LogField::integer("port", static_cast<std::int64_t>(platform.server().port())),
        obs::LogField::text("log_level", std::string{obs::logLevelName(platform.logging().level())}),
        obs::LogField::integer("registered_providers",
                               static_cast<std::int64_t>(providers.size())),
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

    // Note what is deliberately absent, so a reader of the logs is never left to
    // infer that a listener failed to start.
    logger.info("development scope: authentication broker composed; no network listener is started");

    logger.info("openproof server stopped");
    return ExitCode::Success;
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
