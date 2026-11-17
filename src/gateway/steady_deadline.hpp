#pragma once

#include <chrono>
#include <stdexcept>

// Transport-only monotonic deadline arithmetic. Kept independent of the
// OpenProof named modules so this exact function can be compiled and tested
// without rebuilding the heavyweight Beast/TLS module.
namespace openproof::gateway::http::detail {

[[nodiscard]] inline std::chrono::steady_clock::time_point
saturatingSteadyDeadline(std::chrono::milliseconds timeout)
{
    using Clock = std::chrono::steady_clock;
    if (timeout <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument{"The upstream timeout must be positive"};
    }
    // First check for overflow during milliseconds -> native-clock ticks.
    // On the supported platforms the steady clock uses nanosecond ticks,
    // so milliseconds::max() is not representable as a Clock::duration.
    const auto longestDelay =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::duration::max());
    if (timeout >= longestDelay) return Clock::time_point::max();
    const auto delay = std::chrono::duration_cast<Clock::duration>(timeout);
    const auto now = Clock::now();
    // Subtraction is safe because delay is nonnegative and representable.
    // Do not evaluate now + delay until it is proven to fit.
    const auto latestStart = Clock::time_point::max() - delay;
    return now >= latestStart ? Clock::time_point::max() : now + delay;
}

} // namespace openproof::gateway::http::detail
