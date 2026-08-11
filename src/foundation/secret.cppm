module;

#include <concepts>
#include <cstddef>
#include <string>
#include <type_traits>
#include <utility>

export module openproof.foundation:secret;

export namespace openproof::foundation {

/**
 * @brief Overwrites @p size bytes at @p data so that the write cannot be elided.
 *
 * A plain memset over a buffer that is about to die is dead-store-eliminated by
 * every optimizing compiler. This function performs the write through a volatile
 * view and issues a barrier so the store survives.
 *
 * @warning Best-effort. It cannot recover copies the runtime already made: a
 *          reallocated std::string, a swapped page, or a core dump may still
 *          hold the value. Wiping reduces the exposure window; it is not a
 *          guarantee of erasure.
 *
 * @pre @p data is non-null whenever @p size is non-zero. A null pointer with a
 *      non-zero length would mean a caller believes it is erasing a credential
 *      that is not there -- a silent no-op is the wrong answer to that.
 *      Enforced by contract_assert in the definition rather than by `pre` on
 *      this declaration: GCC 16.1.0 silently drops a precondition attached to a
 *      declaration whose definition is out-of-line in a module implementation
 *      unit (verified by reduced test case).
 */
void secureWipe(void* data, std::size_t size) noexcept;

/**
 * @brief Types whose storage can be wiped in place before destruction.
 */
template <typename T>
concept ContiguouslyWipeable = requires(T& value) {
    { value.data() };
    { value.size() } -> std::convertible_to<std::size_t>;
};

/**
 * @brief A value that must never reach a log, an error message, or a response.
 *
 * Redaction here is a property of the type, not a convention the caller has to
 * remember. The class deliberately provides:
 *
 *   - no @c operator<<,
 *   - no @c std::formatter specialization,
 *   - no implicit conversion to the wrapped type,
 *   - no comparison operators.
 *
 * Consequently `logger.info("k", secret)` and `std::format("{}", secret)` are
 * compile errors rather than a production incident. Reading the value requires
 * the deliberately conspicuous @ref expose().
 *
 * Comparisons are omitted on purpose: comparing a credential with @c == is
 * timing-observable. Use the constant-time comparison in openproof::security.
 *
 * The type is move-only (RES-004) so that a credential is not duplicated by an
 * accidental copy; @ref clone() makes duplication explicit where it is needed.
 *
 * @tparam T The wrapped value type, typically std::string.
 * @note Not thread-safe. A Secret has one owner at a time.
 */
template <typename T>
class Secret final {
public:
    /** @brief Constructs an empty secret. */
    Secret() = default;

    /** @brief Takes ownership of @p value. */
    explicit Secret(T value) noexcept(std::is_nothrow_move_constructible_v<T>)
        : m_value(std::move(value))
    {
    }

    // C++26 delete-with-reason: the diagnostic explains the rule instead of
    // just reporting that the function is deleted, so the fix is obvious at the
    // point of misuse.
    Secret(const Secret&) = delete("a secret must not be duplicated implicitly; call clone() when duplication is genuinely intended");
    Secret& operator=(const Secret&) = delete("a secret must not be duplicated implicitly; call clone() when duplication is genuinely intended");

    Secret(Secret&& other) noexcept(std::is_nothrow_move_constructible_v<T>)
        : m_value(std::move(other.m_value))
    {
        other.wipe();
    }

    Secret& operator=(Secret&& other) noexcept(std::is_nothrow_move_assignable_v<T>)
    {
        if (this != &other) {
            wipe();
            m_value = std::move(other.m_value);
            other.wipe();
        }
        return *this;
    }

    ~Secret()
    {
        wipe();
    }

    /**
     * @brief Returns the wrapped value.
     *
     * Named to be conspicuous at the call site and in review. Every use is a
     * place where a credential leaves its protective wrapper, so keep the
     * resulting reference's lifetime as short as possible and never store it.
     */
    [[nodiscard]] const T& expose() const noexcept
    {
        return m_value;
    }

    /** @brief Returns the length of the wrapped value without exposing it. */
    [[nodiscard]] std::size_t size() const noexcept
        requires ContiguouslyWipeable<T>
    {
        return m_value.size();
    }

    /** @brief Returns true when no value is held. */
    [[nodiscard]] bool empty() const noexcept
        requires ContiguouslyWipeable<T>
    {
        return m_value.empty();
    }

    /** @brief Explicitly duplicates the secret, since copying is disabled. */
    [[nodiscard]] Secret clone() const
    {
        return Secret{T{m_value}};
    }

private:
    void wipe() noexcept
    {
        if constexpr (ContiguouslyWipeable<T>) {
            if (m_value.size() != 0U) {
                secureWipe(static_cast<void*>(m_value.data()),
                           m_value.size() * sizeof(*m_value.data()));
            }
        }

        if constexpr (requires(T& value) { value.clear(); }) {
            m_value.clear();
        } else {
            m_value = T{};
        }
    }

    T m_value{};
};

/** @brief The common case: a secret string such as a client secret or API key. */
using SecretString = Secret<std::string>;

}
