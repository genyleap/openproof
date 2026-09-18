module;

#include <cstdint>
#include <string_view>

export module openproof.identity.provider:assurance;

export namespace openproof::identity::provider {

/**
 * @brief How strongly an identity has been established.
 *
 * Not every authentication method deserves the same trust, so the platform
 * refuses to treat them as interchangeable. A policy states the level an
 * operation requires; a provider states the level it believes it achieved.
 *
 * Levels are ordered, and the exact mapping from method to level is deliberately
 * configuration, not code: which providers may claim which level is an operator
 * decision reviewed against the deployment's risk posture.
 */
enum class AssuranceLevel : std::uint8_t {
    Ial0 = 0, ///< Unverified. An anonymous or self-asserted subject.
    Ial1 = 1, ///< A basic authenticated identity, single factor.
    Ial2 = 2, ///< Strong authentication, typically multi-factor.
    Ial3 = 3, ///< Cryptographically verified, phishing-resistant, multi-factor.
    Ial4 = 4, ///< Externally or physically verified identity.
};

/** @brief Returns the stable wire name of @p level, for example "ial2". */
[[nodiscard]] std::string_view assuranceLevelName(AssuranceLevel level) noexcept;

/**
 * @brief Returns whether @p actual satisfies @p required.
 *
 * Provided so that no call site writes its own comparison; an inverted operator
 * in an ad-hoc check silently downgrades every protected operation behind it.
 */
// No contract here on purpose: this function is defined inline in a module
// interface unit, and GCC 16.1.0 emits an undefined __tu_has_violation into
// every consumer that instantiates such a function. The invariant it would
// state -- that Ial0 never satisfies a non-zero requirement -- is covered by
// AssuranceTest instead.
[[nodiscard]] constexpr bool meetsAssurance(const AssuranceLevel actual, const AssuranceLevel required) noexcept
{
    return static_cast<std::uint8_t>(actual) >= static_cast<std::uint8_t>(required);
}

/**
 * @brief A category of authentication evidence, usable as a bitmask.
 */
enum class AuthenticationFactor : std::uint8_t {
    None = 0U,
    Knowledge = 1U << 0U,  ///< Something the subject knows, such as a password.
    Possession = 1U << 1U, ///< Something the subject holds, such as a key or device.
    Inherence = 1U << 2U,  ///< Something the subject is, such as a biometric.
};

[[nodiscard]] constexpr AuthenticationFactor operator|(AuthenticationFactor left, AuthenticationFactor right) noexcept
{
    return static_cast<AuthenticationFactor>(static_cast<std::uint8_t>(left) | static_cast<std::uint8_t>(right));
}

[[nodiscard]] constexpr AuthenticationFactor operator&(AuthenticationFactor left, AuthenticationFactor right) noexcept
{
    return static_cast<AuthenticationFactor>(static_cast<std::uint8_t>(left) & static_cast<std::uint8_t>(right));
}

/** @brief Returns whether @p set includes every factor in @p wanted. */
[[nodiscard]] constexpr bool containsFactor(AuthenticationFactor set, AuthenticationFactor wanted) noexcept
{
    return (set & wanted) == wanted;
}

/**
 * @brief What an authentication attempt actually demonstrated.
 *
 * Distinct from AssuranceLevel: strength records the mechanics of the exchange
 * (which factor categories were exercised, whether the exchange was
 * phishing-resistant), while assurance is the trust conclusion drawn from them.
 * A policy may require either, and requiring phishing resistance for
 * administrative operations is a different constraint from requiring two
 * factors.
 */
class AuthenticationStrength final {
public:
    /** @brief Constructs a strength demonstrating no factors. */
    AuthenticationStrength() = default;

    /**
     * @param factors            Factor categories actually exercised.
     * @param phishingResistant  True only when the exchange binds to the origin,
     *                           as WebAuthn and wallet signatures over a bound
     *                           domain do. A one-time code sent over SMS does not.
     */
    AuthenticationStrength(AuthenticationFactor factors, bool phishingResistant) noexcept;

    [[nodiscard]] AuthenticationFactor factors() const noexcept;

    /** @brief Returns whether at least two distinct factor categories were used. */
    [[nodiscard]] bool isMultiFactor() const noexcept;

    [[nodiscard]] bool isPhishingResistant() const noexcept;

private:
    AuthenticationFactor m_factors{AuthenticationFactor::None};
    bool m_phishingResistant{false};
};

}
