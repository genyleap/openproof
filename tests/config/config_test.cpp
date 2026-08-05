#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

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
    EXPECT_EQ(configuration->logging().level(), obs::LogLevel::Info);
    EXPECT_TRUE(configuration->logging().console());
    EXPECT_TRUE(configuration->security().tokenSigningKey().empty());
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
