module;

#include <atomic>
#include <cstddef>

module openproof.foundation;

namespace openproof::foundation {

void secureWipe(void* data, const std::size_t size) noexcept
{
    // Documented as @pre on the declaration and enforced here: GCC 16.1.0
    // silently drops a precondition attached to a declaration whose definition
    // is out-of-line in a module implementation unit.
    contract_assert(size == 0U || data != nullptr);

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
