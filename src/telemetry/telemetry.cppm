module;

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

export module openproof.telemetry;

import openproof.foundation;

export namespace openproof::telemetry {

using Labels = std::map<std::string, std::string, std::less<>>;

/** In-process metrics registry with a hard series-cardinality ceiling. */
class MetricRegistry final {
public:
    explicit MetricRegistry(std::size_t maximumSeries);
    [[nodiscard]] foundation::Status increment(
        std::string name, Labels labels = {}, double amount = 1.0);
    [[nodiscard]] foundation::Status observe(
        std::string name, std::vector<double> buckets, double value,
        Labels labels = {});
    [[nodiscard]] std::string prometheus() const;
    [[nodiscard]] std::size_t seriesCount() const;
private:
    struct Counter final {
        std::string name;
        Labels labels;
        double value{};
    };
    struct Histogram final {
        std::string name;
        Labels labels;
        std::vector<double> boundaries;
        std::vector<std::uint64_t> counts;
        std::uint64_t totalCount{};
        double sum{};
    };
    std::size_t m_maximumSeries;
    mutable std::mutex m_mutex;
    std::map<std::string, Counter> m_counters;
    std::map<std::string, Histogram> m_histograms;
    std::map<std::string, char, std::less<>> m_metricTypes;
};

class TraceContext final {
public:
    [[nodiscard]] static foundation::Result<TraceContext>
    parseTraceParent(std::string_view value);
    [[nodiscard]] static foundation::Result<TraceContext> generate(bool sampled);
    [[nodiscard]] std::string traceParent() const;
    [[nodiscard]] std::string_view traceId() const noexcept;
    [[nodiscard]] std::string_view spanId() const noexcept;
    [[nodiscard]] bool sampled() const noexcept;
private:
    friend class Tracer;
    TraceContext(std::string traceId, std::string spanId, bool sampled);
    std::string m_traceId;
    std::string m_spanId;
    bool m_sampled{};
};

class SpanRecord final {
public:
    SpanRecord(TraceContext context, std::optional<std::string> parentSpanId,
               std::string name, foundation::Instant startedAt,
               foundation::Instant endedAt, std::string outcome, Labels attributes);
    [[nodiscard]] const TraceContext& context() const noexcept;
    [[nodiscard]] const std::optional<std::string>& parentSpanId() const noexcept;
    [[nodiscard]] std::string_view name() const noexcept;
    [[nodiscard]] foundation::Instant startedAt() const noexcept;
    [[nodiscard]] foundation::Instant endedAt() const noexcept;
    [[nodiscard]] std::string_view outcome() const noexcept;
    [[nodiscard]] const Labels& attributes() const noexcept;
private:
    TraceContext m_context;
    std::optional<std::string> m_parentSpanId;
    std::string m_name;
    foundation::Instant m_startedAt{};
    foundation::Instant m_endedAt{};
    std::string m_outcome;
    Labels m_attributes;
};

class SpanSink {
public:
    SpanSink(const SpanSink&) = delete;
    SpanSink& operator=(const SpanSink&) = delete;
    virtual ~SpanSink() = default;
    virtual void record(SpanRecord span) = 0;
protected:
    SpanSink() = default;
};

class InMemorySpanSink final : public SpanSink {
public:
    void record(SpanRecord span) override;
    [[nodiscard]] std::vector<SpanRecord> spans() const;
private:
    mutable std::mutex m_mutex;
    std::vector<SpanRecord> m_spans;
};

class Span final {
public:
    Span(const Span&) = delete;
    Span& operator=(const Span&) = delete;
    Span(Span&& other) noexcept;
    Span& operator=(Span&& other) noexcept;
    ~Span();
    [[nodiscard]] const TraceContext& context() const noexcept;
    void end(std::string outcome = "ok");
private:
    friend class Tracer;
    Span(const foundation::ClockSource& clock, SpanSink& sink,
         TraceContext context, std::optional<std::string> parentSpanId,
         std::string name, foundation::Instant startedAt, Labels attributes);
    void finish(std::string outcome) noexcept;
    const foundation::ClockSource* m_clock{};
    SpanSink* m_sink{};
    std::optional<TraceContext> m_context;
    std::optional<std::string> m_parentSpanId;
    std::string m_name;
    foundation::Instant m_startedAt{};
    Labels m_attributes;
};

class Tracer final {
public:
    Tracer(const foundation::ClockSource& clock, SpanSink& sink);
    [[nodiscard]] foundation::Result<Span>
    start(std::string name, std::optional<TraceContext> parent = std::nullopt,
          Labels attributes = {});
private:
    const foundation::ClockSource* m_clock;
    SpanSink* m_sink;
};

}
