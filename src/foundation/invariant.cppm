module;

#include <string_view>

export module openproof.foundation:invariant;

export namespace openproof::foundation {

/**
 * @brief Enforces an internal program invariant in production builds.
 *
 * This is not an input-validation primitive. Callers must use Result for
 * attacker-controlled or otherwise expected invalid input. A failed invariant
 * means OpenProof's own state or control flow is inconsistent, so execution
 * terminates rather than continuing an authorization decision from corrupted
 * assumptions.
 */
void requireInvariant(bool condition, std::string_view detail) noexcept;

}
