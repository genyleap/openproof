module;

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.telemetry;

import openproof.security;

namespace openproof::telemetry {
namespace {

[[nodiscard]] bool validMetricName(std::string_view name) noexcept
{
    if (name.empty()) return false;
    const auto first = name.front();
    if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')
          || first == '_' || first == ':')) return false;
    return std::ranges::all_of(name.substr(1U), [](char value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
            || (value >= '0' && value <= '9') || value == '_' || value == ':';
    });
}

[[nodiscard]] bool validLabelName(std::string_view name) noexcept
{
    if (name.empty() || name.starts_with("__")) return false;
    const auto first = name.front();
    if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')
          || first == '_')) return false;
    return std::ranges::all_of(name.substr(1U), [](char value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
            || (value >= '0' && value <= '9') || value == '_';
    });
}

[[nodiscard]] foundation::Status validateLabels(const Labels& labels)
{
    if (labels.size() > 16U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A metric has too many labels.");
    }
    for (const auto& [name, value] : labels) {
        if (!validLabelName(name) || value.size() > 200U
            || value.contains('\n') || value.contains('\r')) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "A metric label is invalid.");
        }
    }
    return foundation::ok();
}

[[nodiscard]] std::string escapeLabel(std::string_view value)
{
    std::string output;
    for (char symbol : value) {
        if (symbol == '\\' || symbol == '"') output.push_back('\\');
        output.push_back(symbol);
    }
    return output;
}

[[nodiscard]] std::string labelText(const Labels& labels)
{
    if (labels.empty()) return {};
    std::string output{"{"};
    bool first = true;
    for (const auto& [name, value] : labels) {
        if (!first) output.push_back(',');
        first = false;
        output.append(name).append("=\"").append(escapeLabel(value)).push_back('"');
    }
    output.push_back('}');
    return output;
}

[[nodiscard]] std::string seriesKey(std::string_view name, const Labels& labels)
{ return std::string{name} + labelText(labels); }

[[nodiscard]] bool lowercaseHex(std::string_view value) noexcept
{
    return std::ranges::all_of(value, [](char symbol) {
        return (symbol >= '0' && symbol <= '9') || (symbol >= 'a' && symbol <= 'f');
    });
}

[[nodiscard]] bool allZero(std::string_view value) noexcept
{ return std::ranges::all_of(value, [](char symbol) { return symbol == '0'; }); }

[[nodiscard]] foundation::Result<std::string> randomHex(std::size_t bytes)
{
    auto random = security::randomBytes(bytes);
    if (!random.has_value()) return foundation::fail(random.error());
    return foundation::toHex(random.value());
}

}

MetricRegistry::MetricRegistry(std::size_t maximumSeries)
    : m_maximumSeries(maximumSeries) {}

foundation::Status MetricRegistry::increment(std::string name, Labels labels, double amount)
{
    const auto labelStatus = validateLabels(labels);
    if (!validMetricName(name) || !labelStatus.has_value()
        || !std::isfinite(amount) || amount < 0.0) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The counter update is invalid.");
    }
    const std::string key = seriesKey(name, labels);
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto existingType = m_metricTypes.find(name);
    if (existingType != m_metricTypes.end() && existingType->second != 'c') {
        return foundation::fail(foundation::ErrorCode::Conflict,
                                "A histogram already uses this metric family.");
    }
    auto found = m_counters.find(key);
    if (found == m_counters.end()) {
        if (m_counters.size() + m_histograms.size() >= m_maximumSeries) {
            return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                    "The metric series limit has been reached.");
        }
        found = m_counters.emplace(key, Counter{std::move(name), std::move(labels), 0.0}).first;
        m_metricTypes.insert_or_assign(found->second.name, 'c');
    }
    found->second.value += amount;
    return foundation::ok();
}

foundation::Status MetricRegistry::observe(
    std::string name, std::vector<double> buckets, double value, Labels labels)
{
    const auto labelStatus = validateLabels(labels);
    if (!validMetricName(name) || !labelStatus.has_value() || labels.contains("le")
        || !std::isfinite(value)
        || buckets.empty() || !std::ranges::is_sorted(buckets)
        || std::ranges::any_of(buckets, [](double boundary) { return !std::isfinite(boundary); })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The histogram observation is invalid.");
    }
    buckets.erase(std::unique(buckets.begin(), buckets.end()), buckets.end());
    const std::string key = seriesKey(name, labels);
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto existingType = m_metricTypes.find(name);
    if (existingType != m_metricTypes.end() && existingType->second != 'h') {
        return foundation::fail(foundation::ErrorCode::Conflict,
                                "A counter already uses this metric family.");
    }
    auto found = m_histograms.find(key);
    if (found == m_histograms.end()) {
        if (m_counters.size() + m_histograms.size() >= m_maximumSeries) {
            return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                    "The metric series limit has been reached.");
        }
        const std::size_t bucketCount = buckets.size();
        found = m_histograms.emplace(key, Histogram{
            std::move(name), std::move(labels), std::move(buckets),
            std::vector<std::uint64_t>(bucketCount, 0U), 0U, 0.0}).first;
        m_metricTypes.insert_or_assign(found->second.name, 'h');
    } else if (found->second.boundaries != buckets) {
        return foundation::fail(foundation::ErrorCode::Conflict,
                                "Histogram bucket boundaries cannot change.");
    }
    Histogram& histogram = found->second;
    for (std::size_t index = 0U; index < histogram.boundaries.size(); ++index) {
        if (value <= histogram.boundaries[index]) ++histogram.counts[index];
    }
    ++histogram.totalCount;
    histogram.sum += value;
    return foundation::ok();
}

std::string MetricRegistry::prometheus() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    std::string output;
    for (const auto& [key, counter] : m_counters) {
        static_cast<void>(key);
        output.append(counter.name).append(labelText(counter.labels)).push_back(' ');
        output.append(std::format("{}\n", counter.value));
    }
    for (const auto& [key, histogram] : m_histograms) {
        static_cast<void>(key);
        for (std::size_t index = 0U; index < histogram.boundaries.size(); ++index) {
            Labels labels = histogram.labels;
            labels.emplace("le", std::format("{}", histogram.boundaries[index]));
            output.append(histogram.name).append("_bucket").append(labelText(labels))
                .append(" ").append(std::to_string(histogram.counts[index])).push_back('\n');
        }
        Labels infinite = histogram.labels;
        infinite.emplace("le", "+Inf");
        output.append(histogram.name).append("_bucket").append(labelText(infinite))
            .append(" ").append(std::to_string(histogram.totalCount)).push_back('\n');
        output.append(histogram.name).append("_sum").append(labelText(histogram.labels))
            .append(" ").append(std::format("{}", histogram.sum)).push_back('\n');
        output.append(histogram.name).append("_count").append(labelText(histogram.labels))
            .append(" ").append(std::to_string(histogram.totalCount)).push_back('\n');
    }
    return output;
}

std::size_t MetricRegistry::seriesCount() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_counters.size() + m_histograms.size();
}

TraceContext::TraceContext(std::string traceId, std::string spanId, bool sampled)
    : m_traceId(std::move(traceId)), m_spanId(std::move(spanId)), m_sampled(sampled) {}

foundation::Result<TraceContext> TraceContext::parseTraceParent(std::string_view value)
{
    if (value.size() != 55U || value[2] != '-' || value[35] != '-' || value[52] != '-'
        || value.substr(0U, 2U) != "00") {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The traceparent header is invalid.");
    }
    const std::string_view trace = value.substr(3U, 32U);
    const std::string_view span = value.substr(36U, 16U);
    const std::string_view flags = value.substr(53U, 2U);
    if (!lowercaseHex(trace) || !lowercaseHex(span) || !lowercaseHex(flags)
        || allZero(trace) || allZero(span)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The traceparent header is invalid.");
    }
    const bool sampled = (flags[1] == '1' || flags[1] == '3' || flags[1] == '5'
                          || flags[1] == '7' || flags[1] == '9' || flags[1] == 'b'
                          || flags[1] == 'd' || flags[1] == 'f');
    return TraceContext{std::string{trace}, std::string{span}, sampled};
}

foundation::Result<TraceContext> TraceContext::generate(bool sampled)
{
    auto trace = randomHex(16U);
    auto span = randomHex(8U);
    if (!trace) return foundation::fail(trace.error());
    if (!span) return foundation::fail(span.error());
    return TraceContext{std::move(trace).value(), std::move(span).value(), sampled};
}

std::string TraceContext::traceParent() const
{ return std::string{"00-"} + m_traceId + "-" + m_spanId + (m_sampled ? "-01" : "-00"); }
std::string_view TraceContext::traceId() const noexcept { return m_traceId; }
std::string_view TraceContext::spanId() const noexcept { return m_spanId; }
bool TraceContext::sampled() const noexcept { return m_sampled; }

SpanRecord::SpanRecord(TraceContext context, std::optional<std::string> parentSpanId,
                       std::string name, foundation::Instant startedAt,
                       foundation::Instant endedAt, std::string outcome, Labels attributes)
    : m_context(std::move(context)), m_parentSpanId(std::move(parentSpanId)),
      m_name(std::move(name)), m_startedAt(startedAt), m_endedAt(endedAt),
      m_outcome(std::move(outcome)), m_attributes(std::move(attributes)) {}
const TraceContext& SpanRecord::context() const noexcept { return m_context; }
const std::optional<std::string>& SpanRecord::parentSpanId() const noexcept { return m_parentSpanId; }
std::string_view SpanRecord::name() const noexcept { return m_name; }
foundation::Instant SpanRecord::startedAt() const noexcept { return m_startedAt; }
foundation::Instant SpanRecord::endedAt() const noexcept { return m_endedAt; }
std::string_view SpanRecord::outcome() const noexcept { return m_outcome; }
const Labels& SpanRecord::attributes() const noexcept { return m_attributes; }

void InMemorySpanSink::record(SpanRecord span)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    m_spans.push_back(std::move(span));
}
std::vector<SpanRecord> InMemorySpanSink::spans() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_spans;
}

Span::Span(const foundation::ClockSource& clock, SpanSink& sink,
           TraceContext context, std::optional<std::string> parentSpanId,
           std::string name, foundation::Instant startedAt, Labels attributes)
    : m_clock(&clock), m_sink(&sink), m_context(std::move(context)),
      m_parentSpanId(std::move(parentSpanId)), m_name(std::move(name)),
      m_startedAt(startedAt), m_attributes(std::move(attributes)) {}

Span::Span(Span&& other) noexcept
    : m_clock(std::exchange(other.m_clock, nullptr)),
      m_sink(std::exchange(other.m_sink, nullptr)), m_context(std::move(other.m_context)),
      m_parentSpanId(std::move(other.m_parentSpanId)), m_name(std::move(other.m_name)),
      m_startedAt(other.m_startedAt), m_attributes(std::move(other.m_attributes)) {}

Span& Span::operator=(Span&& other) noexcept
{
    if (this != &other) {
        finish("abandoned");
        m_clock = std::exchange(other.m_clock, nullptr);
        m_sink = std::exchange(other.m_sink, nullptr);
        m_context = std::move(other.m_context);
        m_parentSpanId = std::move(other.m_parentSpanId);
        m_name = std::move(other.m_name);
        m_startedAt = other.m_startedAt;
        m_attributes = std::move(other.m_attributes);
    }
    return *this;
}

Span::~Span() { finish("abandoned"); }
const TraceContext& Span::context() const noexcept { return m_context.value(); }
void Span::end(std::string outcome) { finish(std::move(outcome)); }

void Span::finish(std::string outcome) noexcept
{
    if (m_clock == nullptr || m_sink == nullptr || !m_context.has_value()) return;
    try {
        m_sink->record(SpanRecord{std::move(m_context).value(), std::move(m_parentSpanId),
            std::move(m_name), m_startedAt, m_clock->now(), std::move(outcome),
            std::move(m_attributes)});
    } catch (...) {
        // Telemetry must not change application control flow.
    }
    m_clock = nullptr;
    m_sink = nullptr;
}

Tracer::Tracer(const foundation::ClockSource& clock, SpanSink& sink)
    : m_clock(&clock), m_sink(&sink) {}

foundation::Result<Span> Tracer::start(
    std::string name, std::optional<TraceContext> parent, Labels attributes)
{
    const auto labelsStatus = validateLabels(attributes);
    if (name.empty() || name.size() > 200U || !labelsStatus.has_value()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The span is invalid.");
    }
    std::optional<std::string> parentSpan;
    foundation::Result<TraceContext> generated = TraceContext::generate(false);
    if (parent.has_value()) {
        parentSpan = std::string{parent->spanId()};
        auto spanId = randomHex(8U);
        if (!spanId.has_value()) return foundation::fail(spanId.error());
        generated = TraceContext{std::string{parent->traceId()},
                                 std::move(spanId).value(), parent->sampled()};
    }
    if (!generated.has_value()) return foundation::fail(generated.error());
    return Span{*m_clock, *m_sink, std::move(generated).value(), std::move(parentSpan),
                std::move(name), m_clock->now(), std::move(attributes)};
}

}
