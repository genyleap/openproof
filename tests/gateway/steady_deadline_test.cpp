#include "../../src/gateway/steady_deadline.hpp"

#include <chrono>
#include <cstdio>
#include <stdexcept>

int main()
{
    using namespace std::chrono;
    using Clock = steady_clock;
    using openproof::gateway::http::detail::saturatingSteadyDeadline;

    // This is the same helper compiled by the production proxy. A huge
    // millisecond duration cannot wrap the underlying nanosecond clock.
    if (saturatingSteadyDeadline(milliseconds::max())
        != Clock::time_point::max()) {
        std::fputs("Extreme timeout overflowed the monotonic clock\n", stderr);
        return 1;
    }
    const auto maximumConvertible =
        duration_cast<milliseconds>(Clock::duration::max());
    if (saturatingSteadyDeadline(maximumConvertible)
        != Clock::time_point::max()) {
        std::fputs("Clock-boundary timeout did not saturate\n", stderr);
        return 2;
    }
    for (const auto value : {milliseconds{1}, milliseconds{125},
                             milliseconds{2000}}) {
        const auto before = Clock::now();
        const auto deadline = saturatingSteadyDeadline(value);
        const auto after = Clock::now();
        if (deadline < before + value || deadline > after + value) {
            std::fputs("Normal deadline did not preserve its budget\n", stderr);
            return 3;
        }
    }
    for (const auto invalid : {milliseconds{0}, milliseconds{-1}}) {
        try {
            (void)saturatingSteadyDeadline(invalid);
        } catch (const std::invalid_argument&) {
            continue;
        }
        std::fputs("Nonpositive timeout was accepted\n", stderr);
        return 4;
    }
    std::puts("PASS: saturated and finite monotonic deadlines");
    return 0;
}
