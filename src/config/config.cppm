module;

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

    /** @brief Master key used to derive platform signing and token keys. */
    [[nodiscard]] const foundation::SecretString& tokenSigningKey() const noexcept;

private:
    foundation::SecretString m_tokenSigningKey;
};


/** @brief OpenID Provider configuration and asymmetric signing material. */
class OidcConfig final {
public:
    OidcConfig();
    OidcConfig(bool enabled, std::string issuer, std::string keyId,
               foundation::SecretString signingKey);
    OidcConfig(const OidcConfig&) = delete;
    OidcConfig& operator=(const OidcConfig&) = delete;
    OidcConfig(OidcConfig&&) noexcept = default;
    OidcConfig& operator=(OidcConfig&&) noexcept = default;
    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] std::string_view issuer() const noexcept;
    [[nodiscard]] std::string_view keyId() const noexcept;
    [[nodiscard]] const foundation::SecretString& signingKey() const noexcept;
private:
    bool m_enabled{};
    std::string m_issuer;
    std::string m_keyId;
    foundation::SecretString m_signingKey;
};

/** Configuration for the runnable single-upstream reverse-gateway process. */
class GatewayConfig final {
public:
    [[nodiscard]] static foundation::Result<GatewayConfig>
    create(bool enabled, std::string routePrefix, std::string upstreamHost,
           std::uint16_t upstreamPort, bool upstreamTls, std::string upstreamCaFile);
    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] std::string_view routePrefix() const noexcept;
    [[nodiscard]] std::string_view upstreamHost() const noexcept;
    [[nodiscard]] std::uint16_t upstreamPort() const noexcept;
    [[nodiscard]] bool upstreamTls() const noexcept;
    [[nodiscard]] std::string_view upstreamCaFile() const noexcept;
private:
    GatewayConfig(bool enabled, std::string routePrefix, std::string upstreamHost,
                  std::uint16_t upstreamPort, bool upstreamTls,
                  std::string upstreamCaFile);
    bool m_enabled{};
    std::string m_routePrefix;
    std::string m_upstreamHost;
    std::uint16_t m_upstreamPort{};
    bool m_upstreamTls{};
    std::string m_upstreamCaFile;
};

class DatabaseConfig final {
public:
    DatabaseConfig();
    DatabaseConfig(foundation::SecretString connectionString,
                   std::size_t poolSize, std::filesystem::path migrationDirectory);
    DatabaseConfig(const DatabaseConfig&) = delete;
    DatabaseConfig& operator=(const DatabaseConfig&) = delete;
    DatabaseConfig(DatabaseConfig&&) noexcept = default;
    DatabaseConfig& operator=(DatabaseConfig&&) noexcept = default;
    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] const foundation::SecretString& connectionString() const noexcept;
    [[nodiscard]] std::size_t poolSize() const noexcept;
    [[nodiscard]] const std::filesystem::path& migrationDirectory() const noexcept;
private:
    foundation::SecretString m_connectionString;
    std::size_t m_poolSize{8U};
    std::filesystem::path m_migrationDirectory{"migrations"};
};

/** One explicit protected-route RBAC and assurance policy. */
class RoutePolicyConfig final {
public:
    [[nodiscard]] static foundation::Result<RoutePolicyConfig>
    create(std::string pathPrefix, std::vector<std::string> methods,
           std::vector<std::string> requiredRoles, std::string roleMatch,
           std::string minimumAssurance, std::string requiredScope = {},
           std::string requiredAudience = {});
    [[nodiscard]] std::string_view pathPrefix() const noexcept;
    [[nodiscard]] const std::vector<std::string>& methods() const noexcept;
    [[nodiscard]] const std::vector<std::string>& requiredRoles() const noexcept;
    [[nodiscard]] std::string_view roleMatch() const noexcept;
    [[nodiscard]] std::string_view minimumAssurance() const noexcept;
    /** OAuth scope required when the protected route is accessed with a delegated token. */
    [[nodiscard]] std::string_view requiredScope() const noexcept;
    /** OAuth audience required when the protected route uses delegated access. */
    [[nodiscard]] std::string_view requiredAudience() const noexcept;
private:
    RoutePolicyConfig(std::string pathPrefix, std::vector<std::string> methods,
                      std::vector<std::string> requiredRoles,
                      std::string roleMatch, std::string minimumAssurance,
                      std::string requiredScope, std::string requiredAudience);
    std::string m_pathPrefix;
    std::vector<std::string> m_methods;
    std::vector<std::string> m_requiredRoles;
    std::string m_roleMatch;
    std::string m_minimumAssurance;
    std::string m_requiredScope;
    std::string m_requiredAudience;
};

/** @brief Consumer account lifecycle and verification-delivery settings. */
class AccountConfig final {
public:
    AccountConfig();
    AccountConfig(bool enabled, std::string phoneProviderId,
                  std::string deliveryHost, std::uint16_t deliveryPort,
                  bool deliveryTls, std::string deliveryPath,
                  std::string deliveryCaFile,
                  foundation::SecretString deliveryAuthorization);
    AccountConfig(const AccountConfig&) = delete;
    AccountConfig& operator=(const AccountConfig&) = delete;
    AccountConfig(AccountConfig&&) noexcept = default;
    AccountConfig& operator=(AccountConfig&&) noexcept = default;

    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] std::string_view phoneProviderId() const noexcept;
    [[nodiscard]] std::string_view deliveryHost() const noexcept;
    [[nodiscard]] std::uint16_t deliveryPort() const noexcept;
    [[nodiscard]] bool deliveryTls() const noexcept;
    [[nodiscard]] std::string_view deliveryPath() const noexcept;
    [[nodiscard]] std::string_view deliveryCaFile() const noexcept;
    [[nodiscard]] const foundation::SecretString& deliveryAuthorization() const noexcept;

private:
    bool m_enabled{};
    std::string m_phoneProviderId{"phone"};
    std::string m_deliveryHost;
    std::uint16_t m_deliveryPort{};
    bool m_deliveryTls{true};
    std::string m_deliveryPath{"/v1/openproof/verification"};
    std::string m_deliveryCaFile;
    foundation::SecretString m_deliveryAuthorization;
};

class AuthConfig final {
public:
    [[nodiscard]] static foundation::Result<AuthConfig>
    create(bool enabled, std::string providerId, std::string organizationId,
           std::string protectedRoutePrefix,
           std::vector<RoutePolicyConfig> routePolicies);
    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] std::string_view providerId() const noexcept;
    [[nodiscard]] std::string_view organizationId() const noexcept;
    [[nodiscard]] std::string_view protectedRoutePrefix() const noexcept;
    [[nodiscard]] const std::vector<RoutePolicyConfig>& routePolicies() const noexcept;
private:
    AuthConfig(bool enabled, std::string providerId, std::string organizationId,
               std::string protectedRoutePrefix,
               std::vector<RoutePolicyConfig> routePolicies);
    bool m_enabled{};
    std::string m_providerId;
    std::string m_organizationId;
    std::string m_protectedRoutePrefix;
    std::vector<RoutePolicyConfig> m_routePolicies;
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
    [[nodiscard]] const GatewayConfig& gateway() const noexcept;
    [[nodiscard]] const DatabaseConfig& database() const noexcept;
    [[nodiscard]] const AuthConfig& auth() const noexcept;
    [[nodiscard]] const AccountConfig& account() const noexcept;
    [[nodiscard]] const OidcConfig& oidc() const noexcept;
    /** Validates the additional fail-closed requirements of `opp server`. */
    [[nodiscard]] foundation::Status validateServerDeployment() const;

private:
    PlatformConfig(ServerConfig server, LoggingConfig logging, SecurityConfig security,
                   GatewayConfig gateway, DatabaseConfig database, AuthConfig auth,
                   AccountConfig account, OidcConfig oidc);

    ServerConfig m_server;
    LoggingConfig m_logging;
    SecurityConfig m_security;
    GatewayConfig m_gateway;
    DatabaseConfig m_database;
    AuthConfig m_auth;
    AccountConfig m_account;
    OidcConfig m_oidc;
};

}
