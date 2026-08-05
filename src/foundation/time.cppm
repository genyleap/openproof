module;

#include <atomic>
#include <chrono>
#include <string>

export module openproof.foundation:time;

export namespace openproof::foundation {

/** @brief The platform's duration unit. Millisecond resolution is sufficient
 *         for token lifetimes, challenge expiry and session windows. */
using Duration = std::chrono::milliseconds;

/** @brief A point in time on the system clock, at millisecond resolution. */
using Instant = std::chrono::sys_time<Duration>;

/**
 * @brief Formats @p instant as RFC 3339 UTC with milliseconds,
 *        for example "2026-08-04T09:30:00.000Z".
 *
 * Used for log records and audit events, which must be comparable across hosts.
 */
[[nodiscard]] std::string toIso8601(Instant instant);

/**
 * @brief The source of current time.
 *
 * Time is injected rather than read from a global, for two reasons. Security
 * behaviour that depends on time -- challenge expiry, nonce windows, token
 * lifetime, idle timeout -- must be testable deterministically (TST-004). And a
 * subsystem that reads the clock directly cannot be exercised at a boundary
 * without sleeping, which produces slow and flaky tests.
 */
class ClockSource {
public:
    ClockSource(const ClockSource&) = delete;
    ClockSource& operator=(const ClockSource&) = delete;
    ClockSource(ClockSource&&) = delete;
    ClockSource& operator=(ClockSource&&) = delete;

    virtual ~ClockSource() = default;

    /** @brief Returns the current instant. */
    [[nodiscard]] virtual Instant now() const noexcept = 0;

protected:
    ClockSource() = default;
};

/**
 * @brief The production clock, reading the system clock.
 * @note Thread-safe.
 */
class SystemClockSource final : public ClockSource {
public:
    [[nodiscard]] Instant now() const noexcept override;
};

/**
 * @brief A clock advanced explicitly by the caller, for deterministic tests.
 * @note Thread-safe.
 */
class ManualClockSource final : public ClockSource {
public:
    explicit ManualClockSource(Instant start) noexcept;

    [[nodiscard]] Instant now() const noexcept override;

    /** @brief Moves the clock forward by @p delta. */
    void advance(Duration delta) noexcept;

    /** @brief Sets the clock to @p instant. */
    void set(Instant instant) noexcept;

private:
    std::atomic<Instant> m_now;
};

}
