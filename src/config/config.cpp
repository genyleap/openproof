module;

#include <charconv>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <initializer_list>
#include <ios>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

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

[[nodiscard]] bool isAllowedKey(
    std::string_view key, std::initializer_list<std::string_view> allowed) noexcept
{
    return std::ranges::find(allowed, key) != allowed.end();
}

[[nodiscard]] foundation::Status validateTableKeys(
    const toml::table& table, std::string_view tableName,
    std::initializer_list<std::string_view> allowed)
{
    for (const auto& [key, value] : table) {
        static_cast<void>(value);
        if (!isAllowedKey(key.str(), allowed)) {
            return foundation::fail(
                foundation::ErrorCode::InvalidArgument,
                "The configuration contains an unknown setting.",
                std::format("Unknown configuration key '{}.{}'.", tableName, key.str()));
        }
    }
    return foundation::ok();
}

[[nodiscard]] foundation::Status validateConfigurationSchema(const toml::table& document)
{
    for (const auto& [key, value] : document) {
        if (!isAllowedKey(key.str(), {"server", "logging", "security", "gateway",
                                      "database", "auth", "account", "oidc"})) {
            return foundation::fail(
                foundation::ErrorCode::InvalidArgument,
                "The configuration contains an unknown section.",
                std::format("Unknown top-level configuration key '{}'.", key.str()));
        }
        if (!value.is_table()) {
            return foundation::fail(
                foundation::ErrorCode::InvalidArgument,
                "A configuration section has the wrong type.",
                std::format("Configuration section '{}' must be a TOML table.", key.str()));
        }
    }

    if (const toml::table* server = document["server"].as_table(); server != nullptr) {
        const foundation::Status keys =
            validateTableKeys(*server, "server", {
                "bind_address", "port", "trust_proxy_client_ip"});
        if (!keys.has_value()) {
            return foundation::fail(keys.error());
        }
    }
    if (const toml::table* logging = document["logging"].as_table(); logging != nullptr) {
        const foundation::Status keys =
            validateTableKeys(*logging, "logging", {"level", "console"});
        if (!keys.has_value()) {
            return foundation::fail(keys.error());
        }
    }
    if (const toml::table* security = document["security"].as_table(); security != nullptr) {
        const foundation::Status keys =
            validateTableKeys(*security, "security", {"token_signing_key"});
        if (!keys.has_value()) {
            return foundation::fail(keys.error());
        }
    }
    if (const toml::table* oidc = document["oidc"].as_table(); oidc != nullptr) {
        const foundation::Status keys =
            validateTableKeys(*oidc, "oidc", {"enabled", "issuer", "key_id", "signing_key",
                                               "previous_signing_keys_directory"});
        if (!keys.has_value()) return foundation::fail(keys.error());
    }
    if (const toml::table* gateway = document["gateway"].as_table(); gateway != nullptr) {
        const foundation::Status keys = validateTableKeys(
            *gateway, "gateway", {"enabled", "route_prefix", "upstream_host",
                                   "upstream_port", "upstream_tls", "upstream_ca_file"});
        if (!keys.has_value()) return foundation::fail(keys.error());
    }
    if (const toml::table* database = document["database"].as_table(); database != nullptr) {
        const foundation::Status keys = validateTableKeys(
            *database, "database", {"connection_string", "pool_size", "migration_directory"});
        if (!keys.has_value()) return foundation::fail(keys.error());
    }
    if (const toml::table* account = document["account"].as_table(); account != nullptr) {
        const foundation::Status keys = validateTableKeys(
            *account, "account", {"enabled", "phone_provider_id", "delivery_host",
                                   "delivery_port", "delivery_tls", "delivery_path",
                                   "delivery_ca_file", "delivery_authorization"});
        if (!keys.has_value()) return foundation::fail(keys.error());
    }
    if (const toml::table* auth = document["auth"].as_table(); auth != nullptr) {
        const foundation::Status keys = validateTableKeys(
            *auth, "auth", {"enabled", "provider_id", "organization_id",
                             "protected_route_prefix", "route_policies"});
        if (!keys.has_value()) return foundation::fail(keys.error());
        if (const toml::node* policies = auth->get("route_policies");
            policies != nullptr) {
            const toml::array* array = policies->as_array();
            if (array == nullptr || array->empty() || array->size() > 256U) {
                return foundation::fail(
                    foundation::ErrorCode::InvalidArgument,
                    "The route policy configuration is invalid.");
            }
            for (const toml::node& node : *array) {
                const toml::table* policy = node.as_table();
                if (policy == nullptr) {
                    return foundation::fail(
                        foundation::ErrorCode::InvalidArgument,
                        "Each route policy must be a TOML table.");
                }
                const foundation::Status policyKeys = validateTableKeys(
                    *policy, "auth.route_policies",
                    {"path_prefix", "methods", "required_roles", "role_match",
                     "minimum_assurance", "required_scope", "required_audience"});
                if (!policyKeys) return foundation::fail(policyKeys.error());
                const auto requiredString = [&](std::string_view key) {
                    const toml::node* value = policy->get(key);
                    return value != nullptr && value->is_string();
                };
                const auto requiredArray = [&](std::string_view key) {
                    const toml::node* value = policy->get(key);
                    return value != nullptr && value->is_array();
                };
                const auto optionalString = [&](std::string_view key) {
                    const toml::node* value = policy->get(key);
                    return value == nullptr || value->is_string();
                };
                if (!requiredString("path_prefix")
                    || !requiredArray("methods")
                    || !requiredArray("required_roles")
                    || !optionalString("role_match")
                    || !optionalString("minimum_assurance")
                    || !optionalString("required_scope")
                    || !optionalString("required_audience")) {
                    return foundation::fail(
                        foundation::ErrorCode::InvalidArgument,
                        "A route policy setting has the wrong type.");
                }
            }
        }
    }

    const auto requireType = [&document](std::string_view section, std::string_view key,
                                         auto predicate, std::string_view expected)
        -> foundation::Status {
        const toml::node_view<const toml::node> node = document[section][key];
        if (node && !predicate(node)) {
            return foundation::fail(
                foundation::ErrorCode::InvalidArgument,
                "A configuration setting has the wrong type.",
                std::format("Configuration key '{}.{}' must be {}.", section, key, expected));
        }
        return foundation::ok();
    };

    const foundation::Status bindAddress = requireType(
        "server", "bind_address", [](const auto& node) { return node.is_string(); }, "a string");
    if (!bindAddress.has_value()) {
        return foundation::fail(bindAddress.error());
    }
    const foundation::Status port = requireType(
        "server", "port", [](const auto& node) { return node.is_integer(); }, "an integer");
    if (!port.has_value()) {
        return foundation::fail(port.error());
    }
    const foundation::Status trustProxyClientIp = requireType(
        "server", "trust_proxy_client_ip",
        [](const auto& node) { return node.is_boolean(); }, "a boolean");
    if (!trustProxyClientIp.has_value()) {
        return foundation::fail(trustProxyClientIp.error());
    }
    const foundation::Status level = requireType(
        "logging", "level", [](const auto& node) { return node.is_string(); }, "a string");
    if (!level.has_value()) {
        return foundation::fail(level.error());
    }
    const foundation::Status console = requireType(
        "logging", "console", [](const auto& node) { return node.is_boolean(); }, "a boolean");
    if (!console.has_value()) {
        return foundation::fail(console.error());
    }
    const foundation::Status signingKey = requireType(
        "security", "token_signing_key", [](const auto& node) { return node.is_string(); },
        "a secret-reference string");
    if (!signingKey.has_value()) {
        return foundation::fail(signingKey.error());
    }
    const foundation::Status oidcEnabled = requireType(
        "oidc", "enabled", [](const auto& node) { return node.is_boolean(); }, "a boolean");
    if (!oidcEnabled.has_value()) return foundation::fail(oidcEnabled.error());
    for (const std::string_view key : {
             "issuer", "key_id", "signing_key", "previous_signing_keys_directory"}) {
        const foundation::Status type = requireType(
            "oidc", key, [](const auto& node) { return node.is_string(); }, "a string");
        if (!type.has_value()) return foundation::fail(type.error());
    }
    for (const std::string_view key : {
             "route_prefix", "upstream_host", "upstream_ca_file"}) {
        const foundation::Status type = requireType(
            "gateway", key,
            [](const auto& node) { return node.is_string(); }, "a string");
        if (!type.has_value()) return foundation::fail(type.error());
    }
    const foundation::Status gatewayEnabled = requireType(
        "gateway", "enabled", [](const auto& node) { return node.is_boolean(); }, "a boolean");
    if (!gatewayEnabled.has_value()) return foundation::fail(gatewayEnabled.error());
    const foundation::Status upstreamPort = requireType(
        "gateway", "upstream_port", [](const auto& node) { return node.is_integer(); }, "an integer");
    if (!upstreamPort.has_value()) return foundation::fail(upstreamPort.error());
    const foundation::Status upstreamTls = requireType(
        "gateway", "upstream_tls", [](const auto& node) { return node.is_boolean(); }, "a boolean");
    if (!upstreamTls.has_value()) return foundation::fail(upstreamTls.error());
    for (const std::string_view key : {"connection_string", "migration_directory"}) {
        const foundation::Status type = requireType(
            "database", key, [](const auto& node) { return node.is_string(); }, "a string");
        if (!type.has_value()) return foundation::fail(type.error());
    }
    const foundation::Status poolSize = requireType(
        "database", "pool_size", [](const auto& node) { return node.is_integer(); }, "an integer");
    if (!poolSize.has_value()) return foundation::fail(poolSize.error());
    const foundation::Status accountEnabled = requireType(
        "account", "enabled", [](const auto& node) { return node.is_boolean(); }, "a boolean");
    if (!accountEnabled.has_value()) return foundation::fail(accountEnabled.error());
    for (const std::string_view key : {"phone_provider_id", "delivery_host", "delivery_path",
                                       "delivery_ca_file", "delivery_authorization"}) {
        const foundation::Status type = requireType(
            "account", key, [](const auto& node) { return node.is_string(); }, "a string");
        if (!type.has_value()) return foundation::fail(type.error());
    }
    const foundation::Status deliveryPort = requireType(
        "account", "delivery_port", [](const auto& node) { return node.is_integer(); }, "an integer");
    if (!deliveryPort.has_value()) return foundation::fail(deliveryPort.error());
    const foundation::Status deliveryTls = requireType(
        "account", "delivery_tls", [](const auto& node) { return node.is_boolean(); }, "a boolean");
    if (!deliveryTls.has_value()) return foundation::fail(deliveryTls.error());
    const foundation::Status authEnabled = requireType(
        "auth", "enabled", [](const auto& node) { return node.is_boolean(); }, "a boolean");
    if (!authEnabled.has_value()) return foundation::fail(authEnabled.error());
    for (const std::string_view key : {"provider_id", "organization_id", "protected_route_prefix"}) {
        const foundation::Status type = requireType(
            "auth", key, [](const auto& node) { return node.is_string(); }, "a string");
        if (!type.has_value()) return foundation::fail(type.error());
    }
    const foundation::Status routePolicies = requireType(
        "auth", "route_policies", [](const auto& node) { return node.is_array(); },
        "an array of tables");
    if (!routePolicies.has_value()) return foundation::fail(routePolicies.error());

    return foundation::ok();
}

[[nodiscard]] foundation::Result<std::vector<std::string>> stringArray(
    const toml::table& table, std::string_view key)
{
    const toml::array* values = table[key].as_array();
    if (values == nullptr) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A route policy array is missing or invalid.");
    }
    std::vector<std::string> output;
    output.reserve(values->size());
    for (const toml::node& node : *values) {
        const auto value = node.value<std::string>();
        if (!value.has_value()) {
            return foundation::fail(
                foundation::ErrorCode::InvalidArgument,
                "Every route policy array item must be a string.");
        }
        output.push_back(*value);
    }
    return output;
}

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

foundation::Result<ServerConfig> ServerConfig::create(
    std::string bindAddress, std::uint16_t port, bool trustProxyClientIp)
{
    if (bindAddress.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The server bind address must not be empty.");
    }
    if (port == 0U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The server port must be in the range 1-65535.");
    }
    if (trustProxyClientIp && bindAddress != "127.0.0.1" && bindAddress != "::1") {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "Trusted proxy client-IP forwarding requires a loopback listener.");
    }
    return ServerConfig{std::move(bindAddress), port, trustProxyClientIp};
}

ServerConfig::ServerConfig(
    std::string bindAddress, std::uint16_t port, bool trustProxyClientIp)
    : m_bindAddress(std::move(bindAddress))
    , m_port(port)
    , m_trustProxyClientIp(trustProxyClientIp)
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

bool ServerConfig::trustProxyClientIp() const noexcept
{
    return m_trustProxyClientIp;
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

OidcConfig::OidcConfig() = default;
OidcConfig::OidcConfig(bool enabled, std::string issuer, std::string keyId,
                       foundation::SecretString signingKey,
                       std::string previousSigningKeysDirectory)
    : m_enabled(enabled), m_issuer(std::move(issuer)), m_keyId(std::move(keyId)),
      m_signingKey(std::move(signingKey)),
      m_previousSigningKeysDirectory(std::move(previousSigningKeysDirectory)) {}
bool OidcConfig::enabled() const noexcept { return m_enabled; }
std::string_view OidcConfig::issuer() const noexcept { return m_issuer; }
std::string_view OidcConfig::keyId() const noexcept { return m_keyId; }
const foundation::SecretString& OidcConfig::signingKey() const noexcept { return m_signingKey; }
std::string_view OidcConfig::previousSigningKeysDirectory() const noexcept
{ return m_previousSigningKeysDirectory; }

GatewayConfig::GatewayConfig(bool enabled, std::string routePrefix,
                             std::string upstreamHost, std::uint16_t upstreamPort,
                             bool upstreamTls, std::string upstreamCaFile)
    : m_enabled(enabled), m_routePrefix(std::move(routePrefix)),
      m_upstreamHost(std::move(upstreamHost)), m_upstreamPort(upstreamPort),
      m_upstreamTls(upstreamTls), m_upstreamCaFile(std::move(upstreamCaFile)) {}

foundation::Result<GatewayConfig> GatewayConfig::create(
    bool enabled, std::string routePrefix, std::string upstreamHost,
    std::uint16_t upstreamPort, bool upstreamTls, std::string upstreamCaFile)
{
    const auto invalidText = [](std::string_view text) {
        return std::ranges::any_of(text, [](char value) {
            const auto byte = static_cast<unsigned char>(value);
            return byte < 0x21U || byte == 0x7FU;
        });
    };
    if (routePrefix.empty()) routePrefix = "/";
    if (!routePrefix.starts_with('/') || routePrefix.starts_with("//")
        || routePrefix.contains('?') || routePrefix.contains('#')
        || invalidText(routePrefix) || (routePrefix.size() > 1U && routePrefix.ends_with('/'))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The gateway route prefix is invalid.");
    }
    if (enabled && (upstreamHost.empty() || upstreamPort == 0U || invalidText(upstreamHost)
                    || upstreamHost.contains('/') || upstreamHost.contains('\\'))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The gateway upstream is invalid.");
    }
    if (!upstreamTls && !upstreamCaFile.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A CA file is only valid for a TLS upstream.");
    }
    return GatewayConfig{enabled, std::move(routePrefix), std::move(upstreamHost),
                         upstreamPort, upstreamTls, std::move(upstreamCaFile)};
}

bool GatewayConfig::enabled() const noexcept { return m_enabled; }
std::string_view GatewayConfig::routePrefix() const noexcept { return m_routePrefix; }
std::string_view GatewayConfig::upstreamHost() const noexcept { return m_upstreamHost; }
std::uint16_t GatewayConfig::upstreamPort() const noexcept { return m_upstreamPort; }
bool GatewayConfig::upstreamTls() const noexcept { return m_upstreamTls; }
std::string_view GatewayConfig::upstreamCaFile() const noexcept { return m_upstreamCaFile; }

DatabaseConfig::DatabaseConfig() = default;
DatabaseConfig::DatabaseConfig(foundation::SecretString connectionString,
                               std::size_t poolSize,
                               std::filesystem::path migrationDirectory)
    : m_connectionString(std::move(connectionString)), m_poolSize(poolSize),
      m_migrationDirectory(std::move(migrationDirectory)) {}
bool DatabaseConfig::enabled() const noexcept { return !m_connectionString.empty(); }
const foundation::SecretString& DatabaseConfig::connectionString() const noexcept
{ return m_connectionString; }
std::size_t DatabaseConfig::poolSize() const noexcept { return m_poolSize; }
const std::filesystem::path& DatabaseConfig::migrationDirectory() const noexcept
{ return m_migrationDirectory; }

RoutePolicyConfig::RoutePolicyConfig(
    std::string pathPrefix, std::vector<std::string> methods,
    std::vector<std::string> requiredRoles, std::string roleMatch,
    std::string minimumAssurance, std::string requiredScope,
    std::string requiredAudience)
    : m_pathPrefix(std::move(pathPrefix)), m_methods(std::move(methods)),
      m_requiredRoles(std::move(requiredRoles)), m_roleMatch(std::move(roleMatch)),
      m_minimumAssurance(std::move(minimumAssurance)),
      m_requiredScope(std::move(requiredScope)),
      m_requiredAudience(std::move(requiredAudience))
{
}

foundation::Result<RoutePolicyConfig> RoutePolicyConfig::create(
    std::string pathPrefix, std::vector<std::string> methods,
    std::vector<std::string> requiredRoles, std::string roleMatch,
    std::string minimumAssurance, std::string requiredScope,
    std::string requiredAudience)
{
    const auto invalidText = [](std::string_view text, std::size_t maximum) {
        return text.empty() || text.size() > maximum
            || std::ranges::any_of(text, [](char value) {
                   const auto byte = static_cast<unsigned char>(value);
                   return byte < 0x21U || byte == 0x7FU;
               });
    };
    constexpr std::string_view allowedMethods[] = {
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};
    if (pathPrefix.empty() || !pathPrefix.starts_with('/')
        || pathPrefix.starts_with("//") || pathPrefix.contains('?')
        || pathPrefix.contains('#') || invalidText(pathPrefix, 2048U)
        || (pathPrefix.size() > 1U && pathPrefix.ends_with('/'))
        || pathPrefix == "/auth" || pathPrefix.starts_with("/auth/")
        || pathPrefix == "/admin" || pathPrefix.starts_with("/admin/")
        || pathPrefix == "/oauth" || pathPrefix.starts_with("/oauth/")
        || pathPrefix == "/login" || pathPrefix.starts_with("/login/")
        || pathPrefix == "/.well-known" || pathPrefix.starts_with("/.well-known/")
        || methods.empty() || methods.size() > std::size(allowedMethods)
        || requiredRoles.empty() || requiredRoles.size() > 16U
        || (roleMatch != "any" && roleMatch != "all")
        || (minimumAssurance != "ial1" && minimumAssurance != "ial2"
            && minimumAssurance != "ial3" && minimumAssurance != "ial4")
        || (!requiredScope.empty() && invalidText(requiredScope, 128U))
        || (!requiredAudience.empty() && invalidText(requiredAudience, 2048U))
        || std::ranges::any_of(methods, [&](const std::string& method) {
               return std::ranges::find(allowedMethods, method)
                   == std::ranges::end(allowedMethods);
           })
        || std::ranges::any_of(requiredRoles, [&](const std::string& role) {
               return invalidText(role, 200U);
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The route policy configuration is invalid.");
    }
    std::ranges::sort(methods);
    std::ranges::sort(requiredRoles);
    if (std::ranges::adjacent_find(methods) != methods.end()
        || std::ranges::adjacent_find(requiredRoles) != requiredRoles.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Route policy methods and roles must be unique.");
    }
    return RoutePolicyConfig{std::move(pathPrefix), std::move(methods),
                             std::move(requiredRoles), std::move(roleMatch),
                             std::move(minimumAssurance), std::move(requiredScope),
                             std::move(requiredAudience)};
}

std::string_view RoutePolicyConfig::pathPrefix() const noexcept
{ return m_pathPrefix; }
const std::vector<std::string>& RoutePolicyConfig::methods() const noexcept
{ return m_methods; }
const std::vector<std::string>& RoutePolicyConfig::requiredRoles() const noexcept
{ return m_requiredRoles; }
std::string_view RoutePolicyConfig::roleMatch() const noexcept
{ return m_roleMatch; }
std::string_view RoutePolicyConfig::minimumAssurance() const noexcept
{ return m_minimumAssurance; }
std::string_view RoutePolicyConfig::requiredScope() const noexcept
{ return m_requiredScope; }
std::string_view RoutePolicyConfig::requiredAudience() const noexcept
{ return m_requiredAudience; }

AuthConfig::AuthConfig(bool enabled, std::string providerId,
                       std::string organizationId, std::string protectedRoutePrefix,
                       std::vector<RoutePolicyConfig> routePolicies)
    : m_enabled(enabled), m_providerId(std::move(providerId)),
      m_organizationId(std::move(organizationId)),
      m_protectedRoutePrefix(std::move(protectedRoutePrefix)),
      m_routePolicies(std::move(routePolicies)) {}

AccountConfig::AccountConfig() = default;

AccountConfig::AccountConfig(
    bool enabled, std::string phoneProviderId, std::string deliveryHost,
    std::uint16_t deliveryPort, bool deliveryTls, std::string deliveryPath,
    std::string deliveryCaFile, foundation::SecretString deliveryAuthorization)
    : m_enabled(enabled), m_phoneProviderId(std::move(phoneProviderId)),
      m_deliveryHost(std::move(deliveryHost)), m_deliveryPort(deliveryPort),
      m_deliveryTls(deliveryTls), m_deliveryPath(std::move(deliveryPath)),
      m_deliveryCaFile(std::move(deliveryCaFile)),
      m_deliveryAuthorization(std::move(deliveryAuthorization))
{
}

bool AccountConfig::enabled() const noexcept { return m_enabled; }
std::string_view AccountConfig::phoneProviderId() const noexcept { return m_phoneProviderId; }
std::string_view AccountConfig::deliveryHost() const noexcept { return m_deliveryHost; }
std::uint16_t AccountConfig::deliveryPort() const noexcept { return m_deliveryPort; }
bool AccountConfig::deliveryTls() const noexcept { return m_deliveryTls; }
std::string_view AccountConfig::deliveryPath() const noexcept { return m_deliveryPath; }
std::string_view AccountConfig::deliveryCaFile() const noexcept { return m_deliveryCaFile; }
const foundation::SecretString& AccountConfig::deliveryAuthorization() const noexcept
{ return m_deliveryAuthorization; }

foundation::Result<AuthConfig> AuthConfig::create(
    bool enabled, std::string providerId, std::string organizationId,
    std::string protectedRoutePrefix,
    std::vector<RoutePolicyConfig> routePolicies)
{
    const auto invalid = [](std::string_view text) {
        return std::ranges::any_of(text, [](char value) {
            const auto byte = static_cast<unsigned char>(value);
            return byte < 0x21U || byte == 0x7FU;
        });
    };
    if (providerId.empty()) providerId = "local";
    if (protectedRoutePrefix.empty()) protectedRoutePrefix = "/";
    if ((enabled && (organizationId.empty() || routePolicies.empty()))
        || (!enabled && !routePolicies.empty()) || invalid(providerId)
        || invalid(organizationId) || !protectedRoutePrefix.starts_with('/')
        || protectedRoutePrefix.starts_with("//") || protectedRoutePrefix.contains('?')
        || protectedRoutePrefix.contains('#') || invalid(protectedRoutePrefix)
        || (protectedRoutePrefix.size() > 1U && protectedRoutePrefix.ends_with('/'))
        || protectedRoutePrefix == "/auth"
        || std::ranges::any_of(routePolicies, [&](const RoutePolicyConfig& policy) {
               return protectedRoutePrefix != "/"
                   && policy.pathPrefix() != protectedRoutePrefix
                   && !policy.pathPrefix().starts_with(protectedRoutePrefix + "/");
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The authentication configuration is invalid.");
    }
    std::vector<std::string> routeKeys;
    for (const RoutePolicyConfig& policy : routePolicies) {
        for (const std::string& method : policy.methods()) {
            routeKeys.emplace_back(method + " " + std::string{policy.pathPrefix()});
        }
    }
    std::ranges::sort(routeKeys);
    if (routeKeys.size() > 256U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "At most 256 protected method routes are allowed.");
    }
    if (std::ranges::adjacent_find(routeKeys) != routeKeys.end()) {
        return foundation::fail(foundation::ErrorCode::AlreadyExists,
                                "A protected route policy is duplicated.");
    }
    return AuthConfig{enabled, std::move(providerId), std::move(organizationId),
                      std::move(protectedRoutePrefix), std::move(routePolicies)};
}
bool AuthConfig::enabled() const noexcept { return m_enabled; }
std::string_view AuthConfig::providerId() const noexcept { return m_providerId; }
std::string_view AuthConfig::organizationId() const noexcept { return m_organizationId; }
std::string_view AuthConfig::protectedRoutePrefix() const noexcept
{ return m_protectedRoutePrefix; }
const std::vector<RoutePolicyConfig>& AuthConfig::routePolicies() const noexcept
{ return m_routePolicies; }

PlatformConfig::PlatformConfig(ServerConfig server, LoggingConfig logging,
                               SecurityConfig security, GatewayConfig gateway,
                               DatabaseConfig database, AuthConfig auth,
                               AccountConfig account, OidcConfig oidc)
    : m_server(std::move(server))
    , m_logging(logging)
    , m_security(std::move(security))
    , m_gateway(std::move(gateway))
    , m_database(std::move(database))
    , m_auth(std::move(auth))
    , m_account(std::move(account))
    , m_oidc(std::move(oidc))
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

    const foundation::Status schema = validateConfigurationSchema(document);
    if (!schema.has_value()) {
        return foundation::fail(schema.error());
    }

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
    bool trustProxyClientIp = document["server"]["trust_proxy_client_ip"].value_or(false);

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
    if (const auto overrideValue = environment.get("OPENPROOF_SERVER_TRUST_PROXY_CLIENT_IP");
        overrideValue.has_value()) {
        auto parsed = parseBoolean(*overrideValue);
        if (!parsed.has_value()) return foundation::fail(parsed.error());
        trustProxyClientIp = parsed.value();
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

    foundation::Result<ServerConfig> server = ServerConfig::create(
        std::move(bindAddress), port, trustProxyClientIp);
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

    bool oidcEnabled = document["oidc"]["enabled"].value_or(false);
    std::string oidcIssuer = document["oidc"]["issuer"].value_or(std::string{});
    std::string oidcKeyId = document["oidc"]["key_id"].value_or(std::string{"openproof-rs256-1"});
    std::string oidcPreviousKeysDirectory = document["oidc"]["previous_signing_keys_directory"]
        .value_or(std::string{});
    foundation::SecretString oidcSigningKey;
    if (const auto reference = document["oidc"]["signing_key"].value<std::string>(); reference.has_value()) {
        auto resolved = resolveSecretReference(*reference, environment);
        if (!resolved) return foundation::fail(resolved.error());
        oidcSigningKey = std::move(resolved).value();
    }
    if (const auto value = environment.get("OPENPROOF_OIDC_ENABLED"); value.has_value()) {
        auto parsed = parseBoolean(*value); if (!parsed) return foundation::fail(parsed.error());
        oidcEnabled = parsed.value();
    }
    if (const auto value = environment.get("OPENPROOF_OIDC_ISSUER"); value.has_value()) oidcIssuer = *value;
    if (const auto value = environment.get("OPENPROOF_OIDC_KEY_ID"); value.has_value()) oidcKeyId = *value;
    if (const auto value = environment.get("OPENPROOF_OIDC_SIGNING_KEY"); value.has_value())
        oidcSigningKey = foundation::SecretString{*value};
    if (const auto value = environment.get("OPENPROOF_OIDC_PREVIOUS_KEYS_DIRECTORY");
        value.has_value()) oidcPreviousKeysDirectory = *value;
    OidcConfig oidc{oidcEnabled, std::move(oidcIssuer), std::move(oidcKeyId),
                    std::move(oidcSigningKey), std::move(oidcPreviousKeysDirectory)};

    const bool gatewayEnabled = document["gateway"]["enabled"].value_or(false);
    std::uint16_t upstreamPortValue = 0U;
    if (const auto configured = document["gateway"]["upstream_port"].value<std::int64_t>();
        configured.has_value()) {
        if (*configured < 1 || *configured > 65535) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The gateway upstream port is invalid.");
        }
        upstreamPortValue = static_cast<std::uint16_t>(*configured);
    }
    auto gateway = GatewayConfig::create(
        gatewayEnabled,
        document["gateway"]["route_prefix"].value_or(std::string{"/"}),
        document["gateway"]["upstream_host"].value_or(std::string{}),
        upstreamPortValue,
        document["gateway"]["upstream_tls"].value_or(true),
        document["gateway"]["upstream_ca_file"].value_or(std::string{}));
    if (!gateway.has_value()) return foundation::fail(gateway.error());

    foundation::SecretString databaseConnection;
    if (const auto reference = document["database"]["connection_string"].value<std::string>();
        reference.has_value()) {
        auto resolved = resolveSecretReference(*reference, environment);
        if (!resolved) return foundation::fail(resolved.error());
        databaseConnection = std::move(resolved).value();
    } else if (const auto direct = environment.get("OPENPROOF_DATABASE_URL");
               direct.has_value()) {
        databaseConnection = foundation::SecretString{*direct};
    }
    std::size_t databasePoolSize = 8U;
    if (const auto configured = document["database"]["pool_size"].value<std::int64_t>();
        configured.has_value()) {
        if (*configured < 1 || *configured > 256) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The database pool size is invalid.");
        }
        databasePoolSize = static_cast<std::size_t>(*configured);
    }
    DatabaseConfig database{
        std::move(databaseConnection), databasePoolSize,
        std::filesystem::path{document["database"]["migration_directory"].value_or(
            std::string{"migrations"})}};
    std::vector<RoutePolicyConfig> routePolicies;
    if (const toml::array* configuredPolicies =
            document["auth"]["route_policies"].as_array();
        configuredPolicies != nullptr) {
        routePolicies.reserve(configuredPolicies->size());
        for (const toml::node& node : *configuredPolicies) {
            const toml::table* configured = node.as_table();
            if (configured == nullptr) {
                return foundation::fail(
                    foundation::ErrorCode::InvalidArgument,
                    "Each route policy must be a TOML table.");
            }
            auto methods = stringArray(*configured, "methods");
            auto roles = stringArray(*configured, "required_roles");
            if (!methods || !roles) {
                return foundation::fail(methods ? roles.error() : methods.error());
            }
            auto policy = RoutePolicyConfig::create(
                (*configured)["path_prefix"].value_or(std::string{}),
                std::move(methods).value(), std::move(roles).value(),
                (*configured)["role_match"].value_or(std::string{"any"}),
                (*configured)["minimum_assurance"].value_or(
                    std::string{"ial1"}),
                (*configured)["required_scope"].value_or(std::string{}),
                (*configured)["required_audience"].value_or(std::string{}));
            if (!policy) return foundation::fail(policy.error());
            routePolicies.push_back(std::move(policy).value());
        }
    }
    auto auth = AuthConfig::create(
        document["auth"]["enabled"].value_or(false),
        document["auth"]["provider_id"].value_or(std::string{"local"}),
        document["auth"]["organization_id"].value_or(std::string{}),
        document["auth"]["protected_route_prefix"].value_or(std::string{"/"}),
        std::move(routePolicies));
    if (!auth) return foundation::fail(auth.error());

    const bool accountEnabledValue = document["account"]["enabled"].value_or(false);
    std::uint16_t accountDeliveryPort = 0U;
    if (const auto configured = document["account"]["delivery_port"].value<std::int64_t>();
        configured.has_value()) {
        if (*configured < 1 || *configured > 65535) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The account delivery port is invalid.");
        }
        accountDeliveryPort = static_cast<std::uint16_t>(*configured);
    }
    foundation::SecretString accountDeliveryAuthorization;
    if (const auto reference = document["account"]["delivery_authorization"].value<std::string>();
        reference.has_value()) {
        auto resolved = resolveSecretReference(*reference, environment);
        if (!resolved) return foundation::fail(resolved.error());
        accountDeliveryAuthorization = std::move(resolved).value();
    }
    AccountConfig account{
        accountEnabledValue,
        document["account"]["phone_provider_id"].value_or(std::string{"phone"}),
        document["account"]["delivery_host"].value_or(std::string{}),
        accountDeliveryPort,
        document["account"]["delivery_tls"].value_or(true),
        document["account"]["delivery_path"].value_or(std::string{"/v1/openproof/verification"}),
        document["account"]["delivery_ca_file"].value_or(std::string{}),
        std::move(accountDeliveryAuthorization)};

    return PlatformConfig{std::move(server).value(), LoggingConfig{level, console},
                          std::move(security), std::move(gateway).value(),
                          std::move(database), std::move(auth).value(), std::move(account),
                          std::move(oidc)};
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

const GatewayConfig& PlatformConfig::gateway() const noexcept { return m_gateway; }
const DatabaseConfig& PlatformConfig::database() const noexcept { return m_database; }
const AuthConfig& PlatformConfig::auth() const noexcept { return m_auth; }
const AccountConfig& PlatformConfig::account() const noexcept { return m_account; }
const OidcConfig& PlatformConfig::oidc() const noexcept { return m_oidc; }

foundation::Status PlatformConfig::validateServerDeployment() const
{
    if (!m_gateway.enabled()) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "The gateway is disabled. Set gateway.enabled=true to run the server.");
    }
    if (m_security.tokenSigningKey().expose().size() < 32U) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "A master signing key of at least 32 bytes is required by the server.");
    }
    if (m_server.bindAddress() != "127.0.0.1" && m_server.bindAddress() != "::1") {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "The built-in listener is plaintext and may only bind to loopback; terminate TLS in a local trusted proxy.");
    }
    if (m_auth.enabled() && !m_database.enabled()) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "Authentication requires a PostgreSQL connection.");
    }
    if (m_account.enabled()
        && (!m_auth.enabled() || !m_database.enabled() || m_account.deliveryHost().empty()
            || m_account.deliveryPort() == 0U || m_account.deliveryPath().empty()
            || m_account.deliveryAuthorization().size() < 16U
            || m_account.phoneProviderId().empty())) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "Consumer account lifecycle requires auth, PostgreSQL and an authenticated delivery webhook.");
    }
    if (m_oidc.enabled()
        && (!m_auth.enabled() || !m_database.enabled() || m_oidc.issuer().empty()
            || m_oidc.keyId().empty() || m_oidc.signingKey().empty())) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "OIDC requires authentication, PostgreSQL, an issuer, key id and RSA signing key.");
    }
    return foundation::ok();
}

}
