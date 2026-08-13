module;

#include <cstdio>
#include <cstdlib>
#include <string_view>

module openproof.foundation;

namespace openproof::foundation {

void requireInvariant(bool condition, std::string_view detail) noexcept
{
    if (condition) {
        return;
    }

    std::fputs("OpenProof invariant violation", stderr);
    if (!detail.empty()) {
        std::fputs(": ", stderr);
        std::fwrite(detail.data(), 1U, detail.size(), stderr);
    }
    std::fputc('\n', stderr);
    std::fflush(stderr);
    std::abort();
}

}
