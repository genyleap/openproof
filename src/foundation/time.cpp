module;

#include <atomic>
#include <chrono>
#include <format>
#include <string>

module openproof.foundation;

namespace openproof::foundation {

std::string toIso8601(Instant instant)
{
    const auto dayBoundary = std::chrono::floor<std::chrono::days>(instant);
    const std::chrono::year_month_day date{dayBoundary};
    const std::chrono::hh_mm_ss<Duration> timeOfDay{instant - dayBoundary};

    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                       static_cast<int>(date.year()),
                       static_cast<unsigned>(date.month()),
                       static_cast<unsigned>(date.day()),
                       timeOfDay.hours().count(),
                       timeOfDay.minutes().count(),
                       timeOfDay.seconds().count(),
                       timeOfDay.subseconds().count());
}

Instant SystemClockSource::now() const noexcept
{
    return std::chrono::time_point_cast<Duration>(std::chrono::system_clock::now());
}

ManualClockSource::ManualClockSource(Instant start) noexcept
    : m_now(start)
{
}

Instant ManualClockSource::now() const noexcept
{
    return m_now.load(std::memory_order_acquire);
}

void ManualClockSource::advance(Duration delta) noexcept
{
    Instant current = m_now.load(std::memory_order_acquire);
    while (!m_now.compare_exchange_weak(current, current + delta, std::memory_order_acq_rel,
                                        std::memory_order_acquire)) {
        // compare_exchange_weak refreshed `current`; retry with the new value.
    }
}

void ManualClockSource::set(Instant instant) noexcept
{
    m_now.store(instant, std::memory_order_release);
}

}
