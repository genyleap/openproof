module;

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

export module openproof.observability:log;

import openproof.foundation;

export namespace openproof::observability {

/** @brief Severity of a log record, ordered from least to most severe. */
enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
};

/** @brief Returns the lowercase wire name of @p level, for example "warn". */
[[nodiscard]] std::string_view logLevelName(LogLevel level) noexcept;

/**
 * @brief Parses a configured level name, case-insensitively.
 * @return The level, or std::nullopt when @p text names no level.
 */
[[nodiscard]] std::optional<LogLevel> parseLogLevel(std::string_view text) noexcept;

/**
 * @brief One typed key/value pair attached to a log record.
 *
 * The value is a closed set of primitive types (API-004). This is the
 * mechanism that makes redaction structural rather than advisory: there is no
 * overload accepting an arbitrary type, and openproof::foundation::Secret has no
 * conversion to any of the accepted types and no formatter. A caller therefore
 * cannot log a credential by mistake -- the attempt does not compile.
 */
class LogField final {
public:
    /** @brief A string-valued field. */
    [[nodiscard]] static LogField text(std::string name, std::string value);

    /** @brief A signed-integer-valued field. */
    [[nodiscard]] static LogField integer(std::string name, std::int64_t value);

    /** @brief A boolean-valued field. */
    [[nodiscard]] static LogField boolean(std::string name, bool value);

    /** @brief A floating-point-valued field. */
    [[nodiscard]] static LogField real(std::string name, double value);

    /**
     * @brief A field that is explicitly present but has no value.
     *
     * Represented by std::monostate rather than by omitting the field. "The
     * device identifier was absent" and "nobody looked for a device identifier"
     * are different facts during an incident investigation, and a log schema
     * that cannot distinguish them loses that difference permanently.
     */
    [[nodiscard]] static LogField null(std::string name);

    [[nodiscard]] std::string_view name() const noexcept;

    /** @brief Returns whether this field carries no value. */
    [[nodiscard]] bool isNull() const noexcept;

    /** @brief Appends this field to @p writer under its own name. */
    void writeTo(foundation::JsonObjectWriter& writer) const;

private:
    // std::monostate leads the alternative list so that a default-constructed
    // Value is the explicit "no value" state rather than an empty string.
    using Value = std::variant<std::monostate, std::string, std::int64_t, bool, double>;

    LogField(std::string name, Value value);

    std::string m_name;
    Value m_value;
};

/**
 * @brief Correlation identifiers carried on every record a logger emits.
 *
 * Attached to a logger rather than passed at each call site, so that a request
 * handler cannot emit a record that is impossible to correlate.
 */
class LogContext final {
public:
    LogContext() = default;

    LogContext& withRequestId(foundation::RequestId id);
    LogContext& withCorrelationId(foundation::CorrelationId id);

    [[nodiscard]] const std::optional<foundation::RequestId>& requestId() const noexcept;
    [[nodiscard]] const std::optional<foundation::CorrelationId>& correlationId() const noexcept;

private:
    std::optional<foundation::RequestId> m_requestId;
    std::optional<foundation::CorrelationId> m_correlationId;
};

/**
 * @brief Destination for rendered log records.
 *
 * Implementations receive one complete JSON record per call, without a trailing
 * newline. Splitting rendering from transport keeps the record format identical
 * across console, file and future collector transports.
 *
 * @note Implementations must be safe to call from multiple threads.
 */
class LogSink {
public:
    LogSink(const LogSink&) = delete;
    LogSink& operator=(const LogSink&) = delete;
    LogSink(LogSink&&) = delete;
    LogSink& operator=(LogSink&&) = delete;

    virtual ~LogSink() = default;

    /** @brief Writes one complete record. */
    virtual void write(std::string_view record) = 0;

protected:
    LogSink() = default;
};

/**
 * @brief Writes records to standard output, one JSON object per line.
 * @note Thread-safe; writes are serialized.
 */
class ConsoleLogSink final : public LogSink {
public:
    void write(std::string_view record) override;

private:
    std::mutex m_mutex;
};

/**
 * @brief Retains records in memory so tests can assert on what was logged.
 *
 * Also useful as a diagnostic buffer. Records accumulate until @ref clear().
 *
 * @note Thread-safe.
 */
class MemoryLogSink final : public LogSink {
public:
    void write(std::string_view record) override;

    [[nodiscard]] std::vector<std::string> records() const;
    [[nodiscard]] std::size_t size() const;
    void clear();

private:
    mutable std::mutex m_mutex;
    std::vector<std::string> m_records;
};

/**
 * @brief Renders structured records and hands them to a sink.
 *
 * Every record is a single JSON object with a fixed envelope -- timestamp,
 * level, message, and correlation identifiers -- plus caller-supplied fields
 * nested under "fields" so that a caller can never shadow an envelope key.
 *
 * Time comes from an injected ClockSource so that record timestamps are
 * deterministic under test.
 *
 * @note Thread-safe, given a thread-safe sink. Copies share the sink and clock.
 */
class Logger final {
public:
    /**
     * @param sink         Destination for rendered records. Must not be null.
     * @param clock        Time source for record timestamps. Must not be null.
     * @param minimumLevel Records below this level are dropped without rendering.
     */
    Logger(std::shared_ptr<LogSink> sink,
           std::shared_ptr<const foundation::ClockSource> clock,
           LogLevel minimumLevel);

    /** @brief Returns true when a record at @p level would be emitted. */
    [[nodiscard]] bool isEnabled(LogLevel level) const noexcept;

    /** @brief Emits one record. */
    void log(LogLevel level, std::string_view message,
             std::span<const LogField> fields = {}) const;

    void trace(std::string_view message, std::span<const LogField> fields = {}) const;
    void debug(std::string_view message, std::span<const LogField> fields = {}) const;
    void info(std::string_view message, std::span<const LogField> fields = {}) const;
    void warn(std::string_view message, std::span<const LogField> fields = {}) const;
    void error(std::string_view message, std::span<const LogField> fields = {}) const;
    void critical(std::string_view message, std::span<const LogField> fields = {}) const;

    /**
     * @brief Emits a record describing @p failure.
     *
     * The client-safe message and the operator-only detail are recorded in
     * separate fields, so an operator sees the diagnostic context that the
     * client response deliberately withholds.
     */
    void logError(LogLevel level, const foundation::Error& failure,
                  std::span<const LogField> fields = {}) const;

    /** @brief Returns a copy of this logger that stamps @p context on every record. */
    [[nodiscard]] Logger withContext(LogContext context) const;

    [[nodiscard]] LogLevel minimumLevel() const noexcept;

private:
    std::shared_ptr<LogSink> m_sink;
    std::shared_ptr<const foundation::ClockSource> m_clock;
    LogLevel m_minimumLevel;
    LogContext m_context;
};

}
