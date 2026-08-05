module;

#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

// The TOML parser is configured to report failures as values rather than
// exceptions, and this is load-bearing rather than stylistic.
//
// Verified on Clang 22.1.8 / libc++ with this project's module layout: an
// exception thrown from a header-only third-party library included in a named
// module's global module fragment is not matched by a catch handler inside that
// module's implementation unit -- not even `catch (const std::exception&)`. The
// same code in an ordinary translation unit catches it correctly. Relying on
// cross-boundary exception type identity here would therefore terminate the
// process on a malformed configuration file.
//
// Reporting the failure as a value is also what ERR-001 asks for: a malformed
// configuration file is an expected, recoverable outcome, not an exceptional one.
//
// TOML_HEADER_ONLY=1 and TOML_EXCEPTIONS=0 are set as target-local compile
// definitions in this directory's CMakeLists.txt; see the rationale there.
#include <toml++/toml.hpp>

module openproof.config;

namespace openproof::config {

namespace {

constexpr std::string_view kEnvironmentPrefix = "env:";
constexpr std::string_view kFilePrefix = "file:";

constexpr std::string_view kDefaultBindAddress = "127.0.0.1";
constexpr std::uint16_t kDefaultPort = 8443;

[[nodiscard]] foundation::Result<std::string> readFileContents(const std::filesystem::path& path)
{
    std::ifstream stream{path, std::ios::binary};
    if (!stream.is_open()) {
        return foundation::fail(
            foundation::ErrorCode::NotFound,
            "The configuration could not be read.",
            std::format("Unable to open '{}'.", path.string()));
    }

    std::string contents{std::istreambuf_iterator<char>{stream},
                         std::istreambuf_iterator<char>{}};
    if (stream.bad()) {
        return foundation::fail(
            foundation::ErrorCode::Internal,
            "The configuration could not be read.",
            std::format("Read error while loading '{}'.", path.string()));
    }
    return contents;
}

/** Strips a single trailing line ending, which editors and `echo` routinely add. */
void stripOneTrailingNewline(std::string& text)
{
    if (!text.empty() && text.back() == '\n') {
        text.pop_back();
    }
    if (!text.empty() && text.back() == '\r') {
        text.pop_back();
    }
}

[[nodiscard]] foundation::Result<std::uint16_t> parsePort(std::string_view text)
{
    std::uint32_t parsed = 0;
    const char* first = text.data();
    const char* last = text.data() + text.size();
    const std::from_chars_result result = std::from_chars(first, last, parsed);

    if (result.ec != std::errc{} || result.ptr != last) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The configured port is not a number.");
    }
    if (parsed == 0U || parsed > 65535U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The configured port is outside the range 1-65535.");
    }
    return static_cast<std::uint16_t>(parsed);
}

[[nodiscard]] foundation::Result<bool> parseBoolean(std::string_view text)
{
    if (text == "true" || text == "1" || text == "yes" || text == "on") {
        return true;
    }
    if (text == "false" || text == "0" || text == "no" || text == "off") {
        return false;
    }
    return foundation::fail(foundation::ErrorCode::InvalidArgument,
                            "The configured value is not a boolean.");
}

}

std::optional<std::string> SystemEnvironment::get(std::string_view name) const
{
    // std::getenv needs a null-terminated name, and the returned pointer is only
    // guaranteed valid until the environment is modified, so the value is copied
    // immediately.
    const std::string terminatedName{name};
    const char* const value = std::getenv(terminatedName.c_str());
    if (value == nullptr) {
        return std::nullopt;
    }
    return std::string{value};
}

void MapEnvironment::set(std::string name, std::string value)
{
    m_values.insert_or_assign(std::move(name), std::move(value));
}

std::optional<std::string> MapEnvironment::get(std::string_view name) const
{
    const auto position = m_values.find(name);
    if (position == m_values.end()) {
        return std::nullopt;
    }
    return position->second;
}

foundation::Result<foundation::SecretString>
resolveSecretReference(std::string_view reference, const Environment& environment)
{
    if (reference.starts_with(kEnvironmentPrefix)) {
        const std::string name{reference.substr(kEnvironmentPrefix.size())};
        if (name.empty()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "A secret reference of the form 'env:' is missing a "
                                    "variable name.");
        }

        std::optional<std::string> value = environment.get(name);
        if (!value.has_value()) {
            return foundation::fail(
                foundation::ErrorCode::FailedPrecondition,
                "A required secret is not available.",
                std::format("Environment variable '{}' referenced by configuration is not set.",
                            name));
        }
        return foundation::SecretString{std::move(value).value()};
    }

    if (reference.starts_with(kFilePrefix)) {
        const std::string_view rawPath = reference.substr(kFilePrefix.size());
        if (rawPath.empty()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "A secret reference of the form 'file:' is missing a path.");
        }

        foundation::Result<std::string> contents =
            readFileContents(std::filesystem::path{rawPath});
        if (!contents.has_value()) {
            return foundation::fail(contents.error());
        }

        std::string value = std::move(contents).value();
        stripOneTrailingNewline(value);
        return foundation::SecretString{std::move(value)};
    }

    // The rejected text is deliberately not echoed: if an operator did inline a
    // credential, quoting it here would copy it straight into the logs.
    return foundation::fail(
        foundation::ErrorCode::InvalidArgument,
        "A secret must be given as a reference of the form 'env:NAME' or 'file:/path'. "
        "Inline secret values are not accepted.");
}

foundation::Result<ServerConfig> ServerConfig::create(std::string bindAddress, std::uint16_t port)
{
    if (bindAddress.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The server bind address must not be empty.");
    }
    if (port == 0U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The server port must be in the range 1-65535.");
    }
    return ServerConfig{std::move(bindAddress), port};
}

ServerConfig::ServerConfig(std::string bindAddress, std::uint16_t port)
    : m_bindAddress(std::move(bindAddress))
    , m_port(port)
{
}

std::string_view ServerConfig::bindAddress() const noexcept
{
    return m_bindAddress;
}

std::uint16_t ServerConfig::port() const noexcept
{
    return m_port;
}

LoggingConfig::LoggingConfig(observability::LogLevel level, bool console)
    : m_level(level)
    , m_console(console)
{
}

observability::LogLevel LoggingConfig::level() const noexcept
{
    return m_level;
}

bool LoggingConfig::console() const noexcept
{
    return m_console;
}

SecurityConfig::SecurityConfig(foundation::SecretString tokenSigningKey)
    : m_tokenSigningKey(std::move(tokenSigningKey))
{
}

const foundation::SecretString& SecurityConfig::tokenSigningKey() const noexcept
{
    return m_tokenSigningKey;
}

PlatformConfig::PlatformConfig(ServerConfig server, LoggingConfig logging, SecurityConfig security)
    : m_server(std::move(server))
    , m_logging(logging)
    , m_security(std::move(security))
{
}

foundation::Result<PlatformConfig> PlatformConfig::loadFromToml(std::string_view tomlText,
                                                                const Environment& environment)
{
    const toml::parse_result parsedDocument = toml::parse(tomlText);
    if (!parsedDocument) {
        const toml::parse_error& failure = parsedDocument.error();
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "The configuration could not be parsed.",
            std::format("TOML parse error at line {}, column {}: {}",
                        failure.source().begin.line, failure.source().begin.column,
                        failure.description()));
    }

    const toml::table& document = parsedDocument.table();

    std::string bindAddress{
        document["server"]["bind_address"].value_or(std::string{kDefaultBindAddress})};
    std::uint16_t port = kDefaultPort;

    if (const std::optional<std::int64_t> configuredPort =
            document["server"]["port"].value<std::int64_t>();
        configuredPort.has_value()) {
        if (*configuredPort < 1 || *configuredPort > 65535) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The configured port is outside the range 1-65535.");
        }
        port = static_cast<std::uint16_t>(*configuredPort);
    }

    observability::LogLevel level = observability::LogLevel::Info;
    if (const std::optional<std::string> configuredLevel =
            document["logging"]["level"].value<std::string>();
        configuredLevel.has_value()) {
        const std::optional<observability::LogLevel> parsed =
            observability::parseLogLevel(*configuredLevel);
        if (!parsed.has_value()) {
            return foundation::fail(
                foundation::ErrorCode::InvalidArgument,
                "The configured log level is not recognized.",
                std::format("Unknown log level '{}'.", *configuredLevel));
        }
        level = *parsed;
    }

    bool console = document["logging"]["console"].value_or(true);

    // Environment overrides are applied after the file so that a deployment can
    // change a setting without rebuilding the image it ships in.
    if (const std::optional<std::string> overrideValue = environment.get("OPENPROOF_SERVER_BIND_ADDRESS");
        overrideValue.has_value()) {
        bindAddress = *overrideValue;
    }
    if (const std::optional<std::string> overrideValue = environment.get("OPENPROOF_SERVER_PORT");
        overrideValue.has_value()) {
        const foundation::Result<std::uint16_t> parsed = parsePort(*overrideValue);
        if (!parsed.has_value()) {
            return foundation::fail(parsed.error());
        }
        port = parsed.value();
    }
    if (const std::optional<std::string> overrideValue = environment.get("OPENPROOF_LOGGING_LEVEL");
        overrideValue.has_value()) {
        const std::optional<observability::LogLevel> parsed =
            observability::parseLogLevel(*overrideValue);
        if (!parsed.has_value()) {
            return foundation::fail(
                foundation::ErrorCode::InvalidArgument,
                "The configured log level is not recognized.",
                std::format("Unknown log level '{}' in OPENPROOF_LOGGING_LEVEL.", *overrideValue));
        }
        level = *parsed;
    }
    if (const std::optional<std::string> overrideValue = environment.get("OPENPROOF_LOGGING_CONSOLE");
        overrideValue.has_value()) {
        const foundation::Result<bool> parsed = parseBoolean(*overrideValue);
        if (!parsed.has_value()) {
            return foundation::fail(parsed.error());
        }
        console = parsed.value();
    }

    foundation::Result<ServerConfig> server = ServerConfig::create(std::move(bindAddress), port);
    if (!server.has_value()) {
        return foundation::fail(server.error());
    }

    SecurityConfig security;
    if (const std::optional<std::string> signingKeyReference =
            document["security"]["token_signing_key"].value<std::string>();
        signingKeyReference.has_value()) {
        foundation::Result<foundation::SecretString> resolved =
            resolveSecretReference(*signingKeyReference, environment);
        if (!resolved.has_value()) {
            return foundation::fail(resolved.error());
        }
        security = SecurityConfig{std::move(resolved).value()};
    }

    return PlatformConfig{std::move(server).value(), LoggingConfig{level, console},
                          std::move(security)};
}

foundation::Result<PlatformConfig> PlatformConfig::loadFromFile(const std::filesystem::path& path,
                                                                const Environment& environment)
{
    const foundation::Result<std::string> contents = readFileContents(path);
    if (!contents.has_value()) {
        return foundation::fail(contents.error());
    }
    return loadFromToml(contents.value(), environment);
}

foundation::Result<PlatformConfig>
PlatformConfig::loadFromEnvironment(const Environment& environment)
{
    return loadFromToml(std::string_view{}, environment);
}

const ServerConfig& PlatformConfig::server() const noexcept
{
    return m_server;
}

const LoggingConfig& PlatformConfig::logging() const noexcept
{
    return m_logging;
}

const SecurityConfig& PlatformConfig::security() const noexcept
{
    return m_security;
}

}
