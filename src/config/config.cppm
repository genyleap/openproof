module;

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>

export module openproof.config;

import openproof.foundation;
import openproof.observability;

export namespace openproof::config {

/**
 * @brief How a configuration value must be handled (brief section 42).
 *
 * The classification is part of the configuration contract, not a comment:
 * a Secret value may never be written to a log, a diagnostic dump, or an
 * administrative API response, and is represented in this layer by
 * openproof::foundation::Secret so the type system enforces that.
 */
enum class ConfigClassification {
    Public,  ///< Safe to expose, including to unauthenticated clients.
    Private, ///< Operational detail; operators only.
    Secret,  ///< Credential material; never logged, never returned.
    Runtime, ///< Derived at startup; not written by an operator.
};

/**
 * @brief Read access to process environment variables.
 *
 * Abstracted so that configuration loading is testable without mutating global
 * process state, which would make tests order-dependent (TST-004).
 */
class Environment {
public:
    Environment(const Environment&) = delete;
    Environment& operator=(const Environment&) = delete;
    Environment(Environment&&) = delete;
    Environment& operator=(Environment&&) = delete;

    virtual ~Environment() = default;

    /** @brief Returns the value of @p name, or std::nullopt when unset. */
    [[nodiscard]] virtual std::optional<std::string> get(std::string_view name) const = 0;

protected:
    Environment() = default;
};

/** @brief Reads the real process environment. */
class SystemEnvironment final : public Environment {
public:
    [[nodiscard]] std::optional<std::string> get(std::string_view name) const override;
};

/** @brief An in-memory environment for tests and for embedding defaults. */
class MapEnvironment final : public Environment {
public:
    MapEnvironment() = default;

    /** @brief Sets @p name to @p value, replacing any previous value. */
    void set(std::string name, std::string value);

    [[nodiscard]] std::optional<std::string> get(std::string_view name) const override;

private:
    std::map<std::string, std::string, std::less<>> m_values;
};

/**
 * @brief Resolves a secret reference into the secret it names.
 *
 * A secret is never written literally in a configuration file. The file holds a
 * reference, and this function dereferences it:
 *
 *   - `env:NAME`   reads the environment variable NAME.
 *   - `file:/path` reads the contents of /path, stripping one trailing newline.
 *
 * Any other form is rejected with ErrorCode::InvalidArgument, including a plain
 * literal. Rejecting literals is the point: a configuration file is routinely
 * committed, copied into an image, attached to a ticket and printed during
 * debugging, and a scheme that merely discourages inline secrets eventually
 * gets one anyway.
 *
 * @param reference   The reference text from configuration.
 * @param environment Environment used to resolve `env:` references.
 * @return The resolved secret, or an error. The error message never echoes the
 *         reference value.
 */
[[nodiscard]] foundation::Result<foundation::SecretString>
resolveSecretReference(std::string_view reference, const Environment& environment);

/** @brief Network listener settings. */
class ServerConfig final {
public:
    /**
     * @brief Validates and constructs listener settings.
     * @return ErrorCode::InvalidArgument when the address is empty or the port is 0.
     */
    [[nodiscard]] static foundation::Result<ServerConfig> create(std::string bindAddress,
                                                                 std::uint16_t port);

    [[nodiscard]] std::string_view bindAddress() const noexcept;
    [[nodiscard]] std::uint16_t port() const noexcept;

private:
    ServerConfig(std::string bindAddress, std::uint16_t port);

    std::string m_bindAddress;
    std::uint16_t m_port;
};

/** @brief Logging settings. */
class LoggingConfig final {
public:
    LoggingConfig() = default;
    LoggingConfig(observability::LogLevel level, bool console);

    [[nodiscard]] observability::LogLevel level() const noexcept;

    /** @brief Whether records are written to standard output. */
    [[nodiscard]] bool console() const noexcept;

private:
    observability::LogLevel m_level{observability::LogLevel::Info};
    bool m_console{true};
};

/** @brief Secret material required at startup. */
class SecurityConfig final {
public:
    SecurityConfig() = default;
    explicit SecurityConfig(foundation::SecretString tokenSigningKey);

    SecurityConfig(const SecurityConfig&) = delete;
    SecurityConfig& operator=(const SecurityConfig&) = delete;
    SecurityConfig(SecurityConfig&&) noexcept = default;
    SecurityConfig& operator=(SecurityConfig&&) noexcept = default;
    ~SecurityConfig() = default;

    /** @brief Key used to sign platform-issued tokens. May be empty in Phase 1. */
    [[nodiscard]] const foundation::SecretString& tokenSigningKey() const noexcept;

private:
    foundation::SecretString m_tokenSigningKey;
};

/**
 * @brief The complete, validated platform configuration.
 *
 * Loading is total: the returned value is either fully valid or an error. There
 * is no partially-initialized configuration and no silent default substituted
 * for a malformed value, because a misread security setting is indistinguishable
 * from a deliberately weakened one.
 *
 * The type is move-only because it owns secret material that must not be
 * duplicated implicitly.
 */
class PlatformConfig final {
public:
    PlatformConfig(const PlatformConfig&) = delete;
    PlatformConfig& operator=(const PlatformConfig&) = delete;
    PlatformConfig(PlatformConfig&&) noexcept = default;
    PlatformConfig& operator=(PlatformConfig&&) noexcept = default;
    ~PlatformConfig() = default;

    /**
     * @brief Parses configuration from TOML text.
     *
     * Environment variables override file values, so that a deployment can
     * change a setting without rewriting an image:
     *   OPENPROOF_SERVER_BIND_ADDRESS, OPENPROOF_SERVER_PORT, OPENPROOF_LOGGING_LEVEL,
     *   OPENPROOF_LOGGING_CONSOLE.
     */
    [[nodiscard]] static foundation::Result<PlatformConfig>
    loadFromToml(std::string_view tomlText, const Environment& environment);

    /** @brief Reads @p path and parses it as TOML. */
    [[nodiscard]] static foundation::Result<PlatformConfig>
    loadFromFile(const std::filesystem::path& path, const Environment& environment);

    /** @brief Builds configuration from environment variables and defaults alone. */
    [[nodiscard]] static foundation::Result<PlatformConfig>
    loadFromEnvironment(const Environment& environment);

    [[nodiscard]] const ServerConfig& server() const noexcept;
    [[nodiscard]] const LoggingConfig& logging() const noexcept;
    [[nodiscard]] const SecurityConfig& security() const noexcept;

private:
    PlatformConfig(ServerConfig server, LoggingConfig logging, SecurityConfig security);

    ServerConfig m_server;
    LoggingConfig m_logging;
    SecurityConfig m_security;
};

}
