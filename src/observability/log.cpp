module;

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <print>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

module openproof.observability;

namespace openproof::observability {

namespace {

[[nodiscard]] std::string toLowerAscii(std::string_view text)
{
    std::string out{text};
    std::ranges::transform(out, out.begin(), [](char character) {
        if (character >= 'A' && character <= 'Z') {
            return static_cast<char>(character - 'A' + 'a');
        }
        return character;
    });
    return out;
}

}

std::string_view logLevelName(LogLevel level) noexcept
{
    switch (level) {
    case LogLevel::Trace:
        return "trace";
    case LogLevel::Debug:
        return "debug";
    case LogLevel::Info:
        return "info";
    case LogLevel::Warn:
        return "warn";
    case LogLevel::Error:
        return "error";
    case LogLevel::Critical:
        return "critical";
    }
    return "info";
}

std::optional<LogLevel> parseLogLevel(std::string_view text) noexcept
{
    const std::string normalized = toLowerAscii(text);
    if (normalized == "trace") {
        return LogLevel::Trace;
    }
    if (normalized == "debug") {
        return LogLevel::Debug;
    }
    if (normalized == "info") {
        return LogLevel::Info;
    }
    if (normalized == "warn" || normalized == "warning") {
        return LogLevel::Warn;
    }
    if (normalized == "error") {
        return LogLevel::Error;
    }
    if (normalized == "critical" || normalized == "fatal") {
        return LogLevel::Critical;
    }
    return std::nullopt;
}

LogField::LogField(std::string name, Value value)
    : m_name(std::move(name))
    , m_value(std::move(value))
{
}

LogField LogField::text(std::string name, std::string value)
{
    return LogField{std::move(name), Value{std::in_place_type<std::string>, std::move(value)}};
}

LogField LogField::integer(std::string name, std::int64_t value)
{
    return LogField{std::move(name), Value{std::in_place_type<std::int64_t>, value}};
}

LogField LogField::boolean(std::string name, bool value)
{
    return LogField{std::move(name), Value{std::in_place_type<bool>, value}};
}

LogField LogField::real(std::string name, double value)
{
    return LogField{std::move(name), Value{std::in_place_type<double>, value}};
}

LogField LogField::null(std::string name)
{
    return LogField{std::move(name), Value{std::in_place_type<std::monostate>}};
}

std::string_view LogField::name() const noexcept
{
    return m_name;
}

bool LogField::isNull() const noexcept
{
    return std::holds_alternative<std::monostate>(m_value);
}

void LogField::writeTo(foundation::JsonObjectWriter& writer) const
{
    std::visit(
        [this, &writer](const auto& value) {
            using ValueType = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<ValueType, std::monostate>) {
                writer.addNull(m_name);
            } else if constexpr (std::is_same_v<ValueType, std::string>) {
                writer.add(m_name, std::string_view{value});
            } else {
                writer.add(m_name, value);
            }
        },
        m_value);
}

LogContext& LogContext::withRequestId(foundation::RequestId id)
{
    m_requestId = std::move(id);
    return *this;
}

LogContext& LogContext::withCorrelationId(foundation::CorrelationId id)
{
    m_correlationId = std::move(id);
    return *this;
}

const std::optional<foundation::RequestId>& LogContext::requestId() const noexcept
{
    return m_requestId;
}

const std::optional<foundation::CorrelationId>& LogContext::correlationId() const noexcept
{
    return m_correlationId;
}

void ConsoleLogSink::write(std::string_view record)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    std::println("{}", record);
}

void MemoryLogSink::write(std::string_view record)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    m_records.emplace_back(record);
}

std::vector<std::string> MemoryLogSink::records() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_records;
}

std::size_t MemoryLogSink::size() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_records.size();
}

void MemoryLogSink::clear()
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    m_records.clear();
}

Logger::Logger(std::shared_ptr<LogSink> sink,
               std::shared_ptr<const foundation::ClockSource> clock,
               LogLevel minimumLevel)
    : m_sink(std::move(sink))
    , m_clock(std::move(clock))
    , m_minimumLevel(minimumLevel)
{
    // A logger without a sink or clock cannot fulfil its contract, and silently
    // dropping records would hide the very events this platform exists to
    // record. ERR-002: a violated construction invariant is an exception.
    if (m_sink == nullptr) {
        throw std::invalid_argument{"Logger requires a non-null sink."};
    }
    if (m_clock == nullptr) {
        throw std::invalid_argument{"Logger requires a non-null clock source."};
    }
}

bool Logger::isEnabled(LogLevel level) const noexcept
{
    return static_cast<int>(level) >= static_cast<int>(m_minimumLevel);
}

LogLevel Logger::minimumLevel() const noexcept
{
    return m_minimumLevel;
}

void Logger::log(LogLevel level, std::string_view message,
                 std::span<const LogField> fields) const
{
    if (!isEnabled(level)) {
        return;
    }

    foundation::JsonObjectWriter record;
    record.add("timestamp", foundation::toIso8601(m_clock->now()));
    record.add("level", logLevelName(level));
    record.add("message", message);

    if (m_context.requestId().has_value()) {
        record.add("request_id", m_context.requestId()->value());
    }
    if (m_context.correlationId().has_value()) {
        record.add("correlation_id", m_context.correlationId()->value());
    }

    if (!fields.empty()) {
        // Caller fields are nested so that they can never shadow an envelope
        // key such as "level" or "timestamp".
        foundation::JsonObjectWriter nested;
        for (const LogField& field : fields) {
            field.writeTo(nested);
        }
        record.add("fields", nested);
    }

    m_sink->write(record.build());
}

void Logger::trace(std::string_view message, std::span<const LogField> fields) const
{
    log(LogLevel::Trace, message, fields);
}

void Logger::debug(std::string_view message, std::span<const LogField> fields) const
{
    log(LogLevel::Debug, message, fields);
}

void Logger::info(std::string_view message, std::span<const LogField> fields) const
{
    log(LogLevel::Info, message, fields);
}

void Logger::warn(std::string_view message, std::span<const LogField> fields) const
{
    log(LogLevel::Warn, message, fields);
}

void Logger::error(std::string_view message, std::span<const LogField> fields) const
{
    log(LogLevel::Error, message, fields);
}

void Logger::critical(std::string_view message, std::span<const LogField> fields) const
{
    log(LogLevel::Critical, message, fields);
}

void Logger::logError(LogLevel level, const foundation::Error& failure,
                      std::span<const LogField> fields) const
{
    if (!isEnabled(level)) {
        return;
    }

    std::vector<LogField> combined;
    combined.reserve(fields.size() + 2U);
    combined.emplace_back(
        LogField::text("error_code", std::string{foundation::errorCodeName(failure.code())}));
    if (failure.hasInternalDetail()) {
        combined.emplace_back(
            LogField::text("error_detail", std::string{failure.internalDetail()}));
    }
    for (const LogField& field : fields) {
        combined.push_back(field);
    }

    log(level, failure.message(), combined);
}

Logger Logger::withContext(LogContext context) const
{
    Logger copy{*this};
    copy.m_context = std::move(context);
    return copy;
}

}
