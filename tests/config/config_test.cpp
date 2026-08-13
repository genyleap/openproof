#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

import openproof.config;
import openproof.foundation;
import openproof.observability;

namespace fnd = openproof::foundation;
namespace cfg = openproof::config;
namespace obs = openproof::observability;

namespace {

/** @brief A temporary file removed on destruction (TST-005). */
class TemporaryFile final {
public:
    TemporaryFile(std::string_view name, std::string_view contents)
        : m_path(std::filesystem::temp_directory_path() / name)
    {
        std::ofstream stream{m_path, std::ios::binary | std::ios::trunc};
        stream << contents;
    }

    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;
    TemporaryFile(TemporaryFile&&) = delete;
    TemporaryFile& operator=(TemporaryFile&&) = delete;

    ~TemporaryFile()
    {
        std::error_code ignored;
        std::filesystem::remove(m_path, ignored);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept
    {
        return m_path;
    }

private:
    std::filesystem::path m_path;
};

constexpr std::string_view kSampleToml = R"(
[server]
bind_address = "0.0.0.0"
port = 9443

[logging]
level = "debug"
console = false
)";

TEST(ConfigTest, AppliesDefaultsWhenNothingIsConfigured)
{
    const cfg::MapEnvironment environment;

    const auto configuration = cfg::PlatformConfig::loadFromEnvironment(environment);
    ASSERT_TRUE(configuration.has_value());

    EXPECT_EQ(configuration->server().bindAddress(), "127.0.0.1");
    EXPECT_EQ(configuration->server().port(), 8443);
    EXPECT_FALSE(configuration->server().trustProxyClientIp());
    EXPECT_EQ(configuration->logging().level(), obs::LogLevel::Info);
    EXPECT_TRUE(configuration->logging().console());
    EXPECT_TRUE(configuration->security().tokenSigningKey().empty());
    EXPECT_FALSE(configuration->gateway().enabled());
}

TEST(ConfigTest, ReadsTypedValuesFromToml)
{
    const cfg::MapEnvironment environment;

    const auto configuration = cfg::PlatformConfig::loadFromToml(kSampleToml, environment);
    ASSERT_TRUE(configuration.has_value());

    EXPECT_EQ(configuration->server().bindAddress(), "0.0.0.0");
    EXPECT_EQ(configuration->server().port(), 9443);
    EXPECT_EQ(configuration->logging().level(), obs::LogLevel::Debug);
    EXPECT_FALSE(configuration->logging().console());
}

TEST(ConfigTest, ReadsAndValidatesGatewayUpstream)
{
    const cfg::MapEnvironment environment;
    const auto configuration = cfg::PlatformConfig::loadFromToml(R"(
[gateway]
enabled = true
route_prefix = "/api"
upstream_host = "api.internal.example"
upstream_port = 443
upstream_tls = true
upstream_ca_file = "/etc/openproof/ca.pem"
)", environment);
    ASSERT_TRUE(configuration.has_value());
    EXPECT_TRUE(configuration->gateway().enabled());
    EXPECT_EQ(configuration->gateway().routePrefix(), "/api");
    EXPECT_EQ(configuration->gateway().upstreamHost(), "api.internal.example");
    EXPECT_EQ(configuration->gateway().upstreamPort(), 443U);
    EXPECT_TRUE(configuration->gateway().upstreamTls());

    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(
        "[gateway]\nenabled=true\nroute_prefix=\"//evil\"\n"
        "upstream_host=\"host\"\nupstream_port=443\n", environment).has_value());
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(
        "[gateway]\nenabled=true\nupstream_host=\"host/path\"\n"
        "upstream_port=443\n", environment).has_value());
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(
        "[gateway]\nenabled=true\nupstream_host=\"host\"\n"
        "upstream_port=80\nupstream_tls=false\nupstream_ca_file=\"ca.pem\"\n",
        environment).has_value());
}

TEST(ConfigTest, ServerDeploymentRequiresGatewayKeyAndLoopbackListener)
{
    cfg::MapEnvironment environment;
    environment.set("MASTER", "0123456789abcdef0123456789abcdef");
    const auto valid = cfg::PlatformConfig::loadFromToml(R"(
[server]
bind_address = "127.0.0.1"
[security]
token_signing_key = "env:MASTER"
[gateway]
enabled = true
upstream_host = "api.internal"
upstream_port = 443
)", environment);
    ASSERT_TRUE(valid.has_value());
    EXPECT_TRUE(valid->validateServerDeployment().has_value());

    const auto exposed = cfg::PlatformConfig::loadFromToml(R"(
[server]
bind_address = "0.0.0.0"
[security]
token_signing_key = "env:MASTER"
[gateway]
enabled = true
upstream_host = "api.internal"
upstream_port = 443
)", environment);
    ASSERT_TRUE(exposed.has_value());
    EXPECT_FALSE(exposed->validateServerDeployment().has_value());
}

TEST(ConfigTest, AuthDeploymentRequiresDatabaseAndResolvesItsSecretReference)
{
    cfg::MapEnvironment environment;
    environment.set("MASTER", std::string(32U, 'm'));
    environment.set("DATABASE", "host=/tmp dbname=openproof");
    auto configured = cfg::PlatformConfig::loadFromToml(R"(
[server]
bind_address = "127.0.0.1"
port = 8443
[security]
token_signing_key = "env:MASTER"
[gateway]
enabled = true
upstream_host = "127.0.0.1"
upstream_port = 8080
upstream_tls = false
[database]
connection_string = "env:DATABASE"
pool_size = 12
migration_directory = "migrations"
[auth]
enabled = true
provider_id = "local"
organization_id = "org"
protected_route_prefix = "/api"
[[auth.route_policies]]
path_prefix = "/api"
methods = ["GET", "POST"]
required_roles = ["member", "owner"]
role_match = "any"
minimum_assurance = "ial2"
)", environment);
    ASSERT_TRUE(configured);
    EXPECT_TRUE(configured->database().enabled());
    EXPECT_EQ(configured->database().poolSize(), 12U);
    EXPECT_TRUE(configured->auth().enabled());
    EXPECT_EQ(configured->auth().organizationId(), "org");
    ASSERT_EQ(configured->auth().routePolicies().size(), 1U);
    EXPECT_EQ(configured->auth().routePolicies().front().methods(),
              (std::vector<std::string>{"GET", "POST"}));
    EXPECT_EQ(configured->auth().routePolicies().front().minimumAssurance(),
              "ial2");
    EXPECT_TRUE(configured->validateServerDeployment());

    auto missingDatabase = cfg::PlatformConfig::loadFromToml(R"(
[server]
bind_address = "127.0.0.1"
port = 8443
[security]
token_signing_key = "env:MASTER"
[gateway]
enabled = true
upstream_host = "127.0.0.1"
upstream_port = 8080
upstream_tls = false
[auth]
enabled = true
organization_id = "org"
[[auth.route_policies]]
path_prefix = "/"
methods = ["GET"]
required_roles = ["member"]
)", environment);
    ASSERT_TRUE(missingDatabase);
    EXPECT_FALSE(missingDatabase->validateServerDeployment());
}

TEST(ConfigTest, ProtectedAuthenticationRequiresExplicitClosedRoutePolicies)
{
    const cfg::MapEnvironment environment;
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(R"(
[auth]
enabled = true
organization_id = "org"
)", environment));
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(R"(
[auth]
enabled = true
organization_id = "org"
protected_route_prefix = "/api"
[[auth.route_policies]]
path_prefix = "/outside"
methods = ["GET"]
required_roles = ["member"]
)", environment));
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(R"(
[auth]
enabled = true
organization_id = "org"
[[auth.route_policies]]
path_prefix = "/"
methods = ["TRACE"]
required_roles = ["member"]
)", environment));
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(R"(
[auth]
enabled = true
organization_id = "org"
[[auth.route_policies]]
path_prefix = "/"
methods = ["GET"]
required_roles = []
)", environment));
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(R"(
[auth]
enabled = true
organization_id = "org"
[[auth.route_policies]]
path_prefix = "/auth/login"
methods = ["POST"]
required_roles = ["member"]
)", environment));
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(R"(
[auth]
enabled = true
organization_id = "org"
[[auth.route_policies]]
path_prefix = "/api"
methods = ["GET"]
required_roles = ["member"]
unexpected_allow = true
)", environment));
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(R"(
[auth]
enabled = true
organization_id = "org"
[[auth.route_policies]]
path_prefix = "/api"
methods = ["GET"]
required_roles = ["member"]
role_match = true
minimum_assurance = 2
)", environment));
    EXPECT_FALSE(cfg::PlatformConfig::loadFromToml(R"(
[auth]
enabled = true
organization_id = "org"
[[auth.route_policies]]
path_prefix = "/api"
methods = ["GET"]
required_roles = ["member"]
[[auth.route_policies]]
path_prefix = "/api"
methods = ["GET"]
required_roles = ["owner"]
)", environment));
}

TEST(ConfigTest, ReadsFromAFile)
{
    const TemporaryFile file{"openproof_config_test.toml", kSampleToml};
    const cfg::MapEnvironment environment;

    const auto configuration = cfg::PlatformConfig::loadFromFile(file.path(), environment);
    ASSERT_TRUE(configuration.has_value());
    EXPECT_EQ(configuration->server().port(), 9443);
}

TEST(ConfigTest, ReportsAMissingFileWithoutCrashing)
{
    const cfg::MapEnvironment environment;

    const auto configuration = cfg::PlatformConfig::loadFromFile(
        std::filesystem::temp_directory_path() / "openproof_absent_config.toml", environment);

    ASSERT_FALSE(configuration.has_value());
    EXPECT_EQ(configuration.error().code(), fnd::ErrorCode::NotFound);
}

TEST(ConfigTest, EnvironmentOverridesFileValues)
{
    cfg::MapEnvironment environment;
    environment.set("OPENPROOF_SERVER_BIND_ADDRESS", "10.0.0.5");
    environment.set("OPENPROOF_SERVER_PORT", "1234");
    environment.set("OPENPROOF_LOGGING_LEVEL", "error");
    environment.set("OPENPROOF_LOGGING_CONSOLE", "true");

    const auto configuration = cfg::PlatformConfig::loadFromToml(kSampleToml, environment);
    ASSERT_TRUE(configuration.has_value());

    EXPECT_EQ(configuration->server().bindAddress(), "10.0.0.5");
    EXPECT_EQ(configuration->server().port(), 1234);
    EXPECT_EQ(configuration->logging().level(), obs::LogLevel::Error);
    EXPECT_TRUE(configuration->logging().console());
}

TEST(ConfigTest, RejectsMalformedToml)
{
    const cfg::MapEnvironment environment;

    const auto configuration =
        cfg::PlatformConfig::loadFromToml("[server\nport = ", environment);

    ASSERT_FALSE(configuration.has_value());
    EXPECT_EQ(configuration.error().code(), fnd::ErrorCode::InvalidArgument);
    // The client-safe message stays generic; the parser detail is operator-only.
    EXPECT_TRUE(configuration.error().hasInternalDetail());
}

TEST(ConfigTest, RejectsAnOutOfRangePort)
{
    const cfg::MapEnvironment environment;

    const auto fromFile =
        cfg::PlatformConfig::loadFromToml("[server]\nport = 70000\n", environment);
    ASSERT_FALSE(fromFile.has_value());
    EXPECT_EQ(fromFile.error().code(), fnd::ErrorCode::InvalidArgument);

    cfg::MapEnvironment badEnvironment;
    badEnvironment.set("OPENPROOF_SERVER_PORT", "0");
    const auto fromEnvironment = cfg::PlatformConfig::loadFromEnvironment(badEnvironment);
    ASSERT_FALSE(fromEnvironment.has_value());
    EXPECT_EQ(fromEnvironment.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(ConfigTest, RejectsANonNumericPort)
{
    cfg::MapEnvironment environment;
    environment.set("OPENPROOF_SERVER_PORT", "https");

    const auto configuration = cfg::PlatformConfig::loadFromEnvironment(environment);
    ASSERT_FALSE(configuration.has_value());
    EXPECT_EQ(configuration.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(ConfigTest, TrustedProxyClientIpRequiresAnExplicitLoopbackListener)
{
    const cfg::MapEnvironment environment;
    const auto enabled = cfg::PlatformConfig::loadFromToml(
        "[server]\ntrust_proxy_client_ip = true\n", environment);
    ASSERT_TRUE(enabled.has_value());
    EXPECT_TRUE(enabled->server().trustProxyClientIp());

    const auto exposed = cfg::PlatformConfig::loadFromToml(
        "[server]\nbind_address = \"0.0.0.0\"\ntrust_proxy_client_ip = true\n",
        environment);
    ASSERT_FALSE(exposed.has_value());
    EXPECT_EQ(exposed.error().code(), fnd::ErrorCode::InvalidArgument);

    cfg::MapEnvironment overridden;
    overridden.set("OPENPROOF_SERVER_TRUST_PROXY_CLIENT_IP", "true");
    const auto fromEnvironment = cfg::PlatformConfig::loadFromEnvironment(overridden);
    ASSERT_TRUE(fromEnvironment.has_value());
    EXPECT_TRUE(fromEnvironment->server().trustProxyClientIp());
}

TEST(ConfigTest, RejectsWrongTomlTypesInsteadOfSilentlyUsingDefaults)
{
    const cfg::MapEnvironment environment;

    constexpr std::string_view malformedTypes[] = {
        "[server]\nbind_address = 127\n",
        "[server]\nport = \"8443\"\n",
        "[server]\ntrust_proxy_client_ip = \"yes\"\n",
        "[logging]\nlevel = false\n",
        "[logging]\nconsole = \"false\"\n",
        "[security]\ntoken_signing_key = 123\n",
        "[gateway]\nenabled = \"yes\"\n",
        "[gateway]\nupstream_port = \"443\"\n",
        "[gateway]\nupstream_tls = \"true\"\n",
    };

    for (const std::string_view document : malformedTypes) {
        const auto configuration = cfg::PlatformConfig::loadFromToml(document, environment);
        ASSERT_FALSE(configuration.has_value()) << document;
        EXPECT_EQ(configuration.error().code(), fnd::ErrorCode::InvalidArgument) << document;
    }
}

TEST(ConfigTest, RejectsUnknownSectionsAndSettings)
{
    const cfg::MapEnvironment environment;

    const auto unknownSection =
        cfg::PlatformConfig::loadFromToml("[securty]\nenabled = true\n", environment);
    ASSERT_FALSE(unknownSection.has_value());
    EXPECT_EQ(unknownSection.error().code(), fnd::ErrorCode::InvalidArgument);

    const auto unknownSetting =
        cfg::PlatformConfig::loadFromToml("[server]\nprt = 8443\n", environment);
    ASSERT_FALSE(unknownSetting.has_value());
    EXPECT_EQ(unknownSetting.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(ConfigTest, RejectsASectionThatIsNotATable)
{
    const cfg::MapEnvironment environment;

    const auto configuration = cfg::PlatformConfig::loadFromToml("server = true\n", environment);

    ASSERT_FALSE(configuration.has_value());
    EXPECT_EQ(configuration.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(ConfigTest, RejectsAnUnknownLogLevel)
{
    const cfg::MapEnvironment environment;

    const auto configuration =
        cfg::PlatformConfig::loadFromToml("[logging]\nlevel = \"chatty\"\n", environment);

    ASSERT_FALSE(configuration.has_value());
    EXPECT_EQ(configuration.error().code(), fnd::ErrorCode::InvalidArgument);
}

// The central rule of the secret model: configuration holds a reference, never
// the credential itself.
TEST(SecretReferenceTest, RejectsAnInlineLiteral)
{
    const cfg::MapEnvironment environment;

    const auto resolved = cfg::resolveSecretReference("hunter2-actual-secret", environment);

    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error().code(), fnd::ErrorCode::InvalidArgument);
    // The rejected text must not be echoed back: doing so would copy an inlined
    // credential straight into the logs.
    EXPECT_EQ(resolved.error().message().find("hunter2"), std::string_view::npos);
    EXPECT_EQ(resolved.error().internalDetail().find("hunter2"), std::string_view::npos);
}

TEST(SecretReferenceTest, ResolvesAnEnvironmentReference)
{
    cfg::MapEnvironment environment;
    environment.set("OPENPROOF_TEST_SIGNING_KEY", "s3cr3t-material");

    const auto resolved =
        cfg::resolveSecretReference("env:OPENPROOF_TEST_SIGNING_KEY", environment);

    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->expose(), "s3cr3t-material");
}

TEST(SecretReferenceTest, ReportsAnUnsetEnvironmentReference)
{
    const cfg::MapEnvironment environment;

    const auto resolved = cfg::resolveSecretReference("env:OPENPROOF_NOT_SET", environment);

    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error().code(), fnd::ErrorCode::FailedPrecondition);
}

TEST(SecretReferenceTest, RejectsAReferenceWithNoTarget)
{
    const cfg::MapEnvironment environment;

    EXPECT_FALSE(cfg::resolveSecretReference("env:", environment).has_value());
    EXPECT_FALSE(cfg::resolveSecretReference("file:", environment).has_value());
}

TEST(SecretReferenceTest, ResolvesAFileReferenceAndStripsOneTrailingNewline)
{
    const TemporaryFile file{"openproof_secret_test.key", "file-based-secret\n"};
    const cfg::MapEnvironment environment;

    const auto resolved =
        cfg::resolveSecretReference("file:" + file.path().string(), environment);

    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->expose(), "file-based-secret");
}

TEST(SecretReferenceTest, ReportsAMissingSecretFile)
{
    const cfg::MapEnvironment environment;

    const auto resolved = cfg::resolveSecretReference(
        "file:" + (std::filesystem::temp_directory_path() / "openproof_absent.key").string(),
        environment);

    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error().code(), fnd::ErrorCode::NotFound);
}

TEST(ConfigTest, LoadsASigningKeyThroughASecretReference)
{
    cfg::MapEnvironment environment;
    environment.set("OPENPROOF_TOKEN_SIGNING_KEY", "signing-key-material");

    const auto configuration = cfg::PlatformConfig::loadFromToml(
        "[security]\ntoken_signing_key = \"env:OPENPROOF_TOKEN_SIGNING_KEY\"\n", environment);

    ASSERT_TRUE(configuration.has_value());
    EXPECT_FALSE(configuration->security().tokenSigningKey().empty());
    EXPECT_EQ(configuration->security().tokenSigningKey().expose(), "signing-key-material");
}

TEST(ConfigTest, LoadsPreviousOidcVerificationKeyDirectory)
{
    const cfg::MapEnvironment environment;
    const auto configuration = cfg::PlatformConfig::loadFromToml(R"(
[oidc]
previous_signing_keys_directory = "/run/openproof/previous-oidc-keys"
)", environment);

    ASSERT_TRUE(configuration.has_value());
    EXPECT_EQ(configuration->oidc().previousSigningKeysDirectory(),
              "/run/openproof/previous-oidc-keys");
}

TEST(ConfigTest, FailsToLoadWhenAnInlineSecretIsUsed)
{
    const cfg::MapEnvironment environment;

    const auto configuration = cfg::PlatformConfig::loadFromToml(
        "[security]\ntoken_signing_key = \"literal-secret\"\n", environment);

    ASSERT_FALSE(configuration.has_value());
    EXPECT_EQ(configuration.error().code(), fnd::ErrorCode::InvalidArgument);
}

TEST(EnvironmentTest, MapEnvironmentReportsPresenceAccurately)
{
    cfg::MapEnvironment environment;
    environment.set("PRESENT", "value");

    EXPECT_EQ(environment.get("PRESENT"), "value");
    EXPECT_FALSE(environment.get("ABSENT").has_value());

    environment.set("PRESENT", "replaced");
    EXPECT_EQ(environment.get("PRESENT"), "replaced");
}

}
