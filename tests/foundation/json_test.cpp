#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <string>

import openproof.foundation;

namespace fnd = openproof::foundation;

namespace {

// Built from parts so that no universal-character-name appears in this source.
const std::string kUnicodeEscapePrefix = std::string{'\\'} + "u00";

TEST(JsonTest, EscapesRequiredCharacters)
{
    EXPECT_EQ(fnd::escapeJsonString(R"(a"b)"), R"(a\"b)");
    EXPECT_EQ(fnd::escapeJsonString(R"(a\b)"), R"(a\\b)");
    EXPECT_EQ(fnd::escapeJsonString("a\nb"), R"(a\nb)");
    EXPECT_EQ(fnd::escapeJsonString("a\tb"), R"(a\tb)");
    EXPECT_EQ(fnd::escapeJsonString("a\rb"), R"(a\rb)");
    EXPECT_EQ(fnd::escapeJsonString("a\bb"), R"(a\bb)");
    EXPECT_EQ(fnd::escapeJsonString("a\fb"), R"(a\fb)");
}

TEST(JsonTest, EscapesOtherControlCharactersAsUnicode)
{
    EXPECT_EQ(fnd::escapeJsonString(std::string{'\x01'}), kUnicodeEscapePrefix + "01");
    EXPECT_EQ(fnd::escapeJsonString(std::string{'\x1f'}), kUnicodeEscapePrefix + "1f");
}

TEST(JsonTest, PassesThroughPrintableAndUtf8Bytes)
{
    const std::string utf8 = "caf\xc3\xa9";
    EXPECT_EQ(fnd::escapeJsonString(utf8), utf8);
    EXPECT_EQ(fnd::escapeJsonString("plain text 123"), "plain text 123");
}

TEST(JsonTest, WritesEmptyObject)
{
    const fnd::JsonObjectWriter writer;
    EXPECT_TRUE(writer.empty());
    EXPECT_EQ(writer.build(), "{}");
}

TEST(JsonTest, WritesTypedValues)
{
    fnd::JsonObjectWriter writer;
    writer.add("text", "value")
        .add("number", std::int64_t{-12})
        .add("flag", true)
        .add("ratio", 0.5)
        .addNull("missing");

    EXPECT_EQ(writer.build(),
              R"({"text":"value","number":-12,"flag":true,"ratio":0.5,"missing":null})");
}

// A string literal must not select the bool overload; that trap silently turns
// every logged string into "true".
TEST(JsonTest, StringLiteralDoesNotBecomeBoolean)
{
    fnd::JsonObjectWriter writer;
    writer.add("key", "false");
    EXPECT_EQ(writer.build(), R"({"key":"false"})");
}

TEST(JsonTest, NestsObjects)
{
    fnd::JsonObjectWriter inner;
    inner.add("code", "NOT_FOUND");

    fnd::JsonObjectWriter outer;
    outer.add("error", inner);

    EXPECT_EQ(outer.build(), R"({"error":{"code":"NOT_FOUND"}})");
}

TEST(JsonTest, NonFiniteNumbersBecomeNull)
{
    fnd::JsonObjectWriter writer;
    writer.add("infinity", std::numeric_limits<double>::infinity());
    writer.add("nan", std::numeric_limits<double>::quiet_NaN());

    EXPECT_EQ(writer.build(), R"({"infinity":null,"nan":null})");
}

// The writer has no raw-value entry point, so a hostile key or value cannot
// break out of its own string and inject structure.
TEST(JsonTest, HostileKeysAndValuesCannotInjectStructure)
{
    fnd::JsonObjectWriter writer;
    writer.add(R"(key","injected":"yes)", R"(value","also":"injected)");

    EXPECT_EQ(writer.build(),
              R"({"key\",\"injected\":\"yes":"value\",\"also\":\"injected"})");
}

}
