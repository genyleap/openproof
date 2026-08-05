module;

#include <cstdint>
#include <string>
#include <string_view>

export module openproof.foundation:json;

export namespace openproof::foundation {

/**
 * @brief Escapes @p value as a JSON string body, without the surrounding quotes.
 *
 * Escapes the two characters JSON requires (quotation mark and reverse solidus)
 * and every control character below U+0020, using the short forms where RFC 8259
 * defines them and \\u00XX otherwise. Bytes at or above 0x80 are passed through
 * unchanged, so a well-formed UTF-8 input produces well-formed UTF-8 output.
 *
 * @warning The function does not validate UTF-8. Callers that accept untrusted
 *          bytes should validate encoding before logging or returning them.
 */
[[nodiscard]] std::string escapeJsonString(std::string_view value);

/**
 * @brief Builds a single JSON object incrementally.
 *
 * The platform writes JSON in two places where correctness matters more than
 * convenience: the client error envelope and structured log records. Both need
 * escaping and neither needs parsing, so the project owns a small writer rather
 * than taking a dependency for output alone.
 *
 * There is deliberately no "raw value" entry point. Every value passes through
 * escaping or a numeric formatter, which removes JSON injection as a class of
 * defect in log and error output.
 *
 * @note Not thread-safe. Instances are short-lived and owned by one writer.
 */
class JsonObjectWriter final {
public:
    JsonObjectWriter() = default;

    /** @brief Adds a string entry. */
    JsonObjectWriter& add(std::string_view key, std::string_view value);

    /**
     * @brief Adds a string entry from a string literal.
     *
     * Present so that a literal argument does not select the @c bool overload,
     * which is the classic silent-wrong-output trap in this API shape.
     */
    JsonObjectWriter& add(std::string_view key, const char* value);

    /** @brief Adds a signed integer entry. */
    JsonObjectWriter& add(std::string_view key, std::int64_t value);

    /** @brief Adds a boolean entry. */
    JsonObjectWriter& add(std::string_view key, bool value);

    /**
     * @brief Adds a floating-point entry.
     *
     * JSON cannot represent NaN or infinity; those values are written as null.
     */
    JsonObjectWriter& add(std::string_view key, double value);

    /** @brief Adds a nested object entry. */
    JsonObjectWriter& add(std::string_view key, const JsonObjectWriter& nested);

    /** @brief Adds an explicit null entry. */
    JsonObjectWriter& addNull(std::string_view key);

    /** @brief Returns true when no entry has been added. */
    [[nodiscard]] bool empty() const noexcept;

    /** @brief Returns the complete JSON object, including the enclosing braces. */
    [[nodiscard]] std::string build() const;

private:
    void beginEntry(std::string_view key);

    std::string m_body;
};

}
