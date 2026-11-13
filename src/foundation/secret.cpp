module;

#include <atomic>
#include <cstddef>
#include <string>

module openproof.foundation;

namespace openproof::foundation {

void wipeMovedFromString(std::string& source, std::size_t originalSize) noexcept
{
    // The standard guarantees only a valid, unspecified moved-from string.
    // A moved short string commonly has size()==0 while its SSO character
    // array still contains the original credential. Re-expose exactly the
    // original length before secure wiping; never write past a string's size.
    if (source.size() < originalSize && originalSize <= source.capacity()) {
        try {
            source.resize(originalSize);
        } catch (...) {
            // Best effort on unusual allocators/implementations. No-throw
            // cleanup must not terminate during another exception's unwind.
        }
    }
    secureWipe(source.data(), source.size());
    source.clear();
}

void secureWipe(void* data, const std::size_t size) noexcept
{
    // Documented as @pre on the declaration and enforced here: GCC 16.1.0
    // silently drops a precondition attached to a declaration whose definition
    // is out-of-line in a module implementation unit.
    foundation::requireInvariant(size == 0U || data != nullptr, "secureWipe received a null pointer with non-zero size");

    if (data == nullptr || size == 0U) {
        return;
    }

    // The write goes through a volatile view so the compiler may not treat it as
    // a dead store into a buffer that is about to be released, and the signal
    // fence prevents the loop from being reordered past the end of the object's
    // lifetime.
    auto* cursor = static_cast<volatile unsigned char*>(data);
    for (std::size_t index = 0; index < size; ++index) {
        cursor[index] = 0U;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

}
