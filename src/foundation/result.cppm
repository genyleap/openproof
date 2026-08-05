module;

#include <expected>
#include <string>
#include <utility>

export module openproof.foundation:result;

import :error;

export namespace openproof::foundation {

/**
 * @brief The platform's return type for an operation that can fail recoverably.
 *
 * ERR-001: recoverable, expected failures are values, not exceptions. Exceptions
 * remain reserved for violated invariants and genuinely exceptional subsystem
 * failures.
 *
 * Every Result-returning function is [[nodiscard]] by construction of
 * std::expected, so a discarded failure is a compile-time diagnostic rather than
 * a silently swallowed error (ERR-004).
 */
template <typename T>
using Result = std::expected<T, Error>;

/**
 * @brief A Result carrying no value; the return type of a fallible command.
 */
using Status = Result<void>;

/** @brief Returns a successful Status. */
[[nodiscard]] inline Status ok() noexcept
{
    return Status{};
}

/**
 * @brief Builds a failure value assignable to any Result.
 *
 * std::unexpected converts implicitly to Result<T> for every T, so a function
 * can return `fail(...)` regardless of its success type.
 */
[[nodiscard]] inline std::unexpected<Error> fail(Error error)
{
    return std::unexpected<Error>{std::move(error)};
}

/** @brief Builds a failure using the client-safe default message for @p code. */
[[nodiscard]] inline std::unexpected<Error> fail(ErrorCode code)
{
    return std::unexpected<Error>{Error{code}};
}

/** @brief Builds a failure with an explicit client-safe message. */
[[nodiscard]] inline std::unexpected<Error> fail(ErrorCode code, std::string message)
{
    return std::unexpected<Error>{Error{code, std::move(message)}};
}

/**
 * @brief Builds a failure with a client-safe message and an operator-only detail.
 *
 * @param internalDetail Never serialized to a client. Must not contain credentials.
 */
[[nodiscard]] inline std::unexpected<Error>
fail(ErrorCode code, std::string message, std::string internalDetail)
{
    return std::unexpected<Error>{Error{code, std::move(message), std::move(internalDetail)}};
}

}
