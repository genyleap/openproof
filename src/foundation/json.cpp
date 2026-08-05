module;

#include <cmath>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

module openproof.foundation;

namespace openproof::foundation {

namespace {

constexpr std::string_view kHexDigits = "0123456789abcdef";

void appendUnicodeEscape(std::string& out, unsigned char character)
{
    out.append("\\u00");
    out.push_back(kHexDigits[(character >> 4U) & 0x0FU]);
    out.push_back(kHexDigits[character & 0x0FU]);
}

}

std::string escapeJsonString(std::string_view value)
{
    std::string out;
    out.reserve(value.size() + (value.size() / 8U) + 2U);

    for (const char raw : value) {
        const auto character = static_cast<unsigned char>(raw);
        switch (character) {
        case '"':
            out.append("\\\"");
            break;
        case '\\':
            out.append("\\\\");
            break;
        case '\b':
            out.append("\\b");
            break;
        case '\f':
            out.append("\\f");
            break;
        case '\n':
            out.append("\\n");
            break;
        case '\r':
            out.append("\\r");
            break;
        case '\t':
            out.append("\\t");
            break;
        default:
            if (character < 0x20U) {
                appendUnicodeEscape(out, character);
            } else {
                out.push_back(raw);
            }
            break;
        }
    }

    return out;
}

void JsonObjectWriter::beginEntry(std::string_view key)
{
    // An unnamed entry would produce {"":...}, which is legal JSON but means a
    // caller lost a field name somewhere upstream.
    contract_assert(!key.empty());

    if (!m_body.empty()) {
        m_body.push_back(',');
    }
    m_body.push_back('"');
    m_body.append(escapeJsonString(key));
    m_body.append("\":");
}

JsonObjectWriter& JsonObjectWriter::add(std::string_view key, std::string_view value)
{
    beginEntry(key);
    m_body.push_back('"');
    m_body.append(escapeJsonString(value));
    m_body.push_back('"');
    return *this;
}

JsonObjectWriter& JsonObjectWriter::add(std::string_view key, const char* value)
{
    return add(key, value == nullptr ? std::string_view{} : std::string_view{value});
}

JsonObjectWriter& JsonObjectWriter::add(std::string_view key, std::int64_t value)
{
    beginEntry(key);
    m_body.append(std::format("{}", value));
    return *this;
}

JsonObjectWriter& JsonObjectWriter::add(std::string_view key, bool value)
{
    beginEntry(key);
    m_body.append(value ? "true" : "false");
    return *this;
}

JsonObjectWriter& JsonObjectWriter::add(std::string_view key, double value)
{
    beginEntry(key);
    if (std::isfinite(value)) {
        m_body.append(std::format("{}", value));
    } else {
        m_body.append("null");
    }
    return *this;
}

JsonObjectWriter& JsonObjectWriter::add(std::string_view key, const JsonObjectWriter& nested)
{
    beginEntry(key);
    m_body.append(nested.build());
    return *this;
}

JsonObjectWriter& JsonObjectWriter::addNull(std::string_view key)
{
    beginEntry(key);
    m_body.append("null");
    return *this;
}

bool JsonObjectWriter::empty() const noexcept
{
    return m_body.empty();
}

std::string JsonObjectWriter::build() const
{
    std::string out;
    out.reserve(m_body.size() + 2U);
    out.push_back('{');
    out.append(m_body);
    out.push_back('}');
    return out;
}

}
