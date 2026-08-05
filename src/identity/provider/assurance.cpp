module;

#include <bit>
#include <cstdint>
#include <string_view>

module openproof.identity.provider;

namespace openproof::identity::provider {

std::string_view assuranceLevelName(AssuranceLevel level) noexcept
{
    switch (level) {
    case AssuranceLevel::Ial0:
        return "ial0";
    case AssuranceLevel::Ial1:
        return "ial1";
    case AssuranceLevel::Ial2:
        return "ial2";
    case AssuranceLevel::Ial3:
        return "ial3";
    case AssuranceLevel::Ial4:
        return "ial4";
    }
    return "ial0";
}

AuthenticationStrength::AuthenticationStrength(AuthenticationFactor factors,
                                               bool phishingResistant) noexcept
    : m_factors(factors)
    , m_phishingResistant(phishingResistant)
{
}

AuthenticationFactor AuthenticationStrength::factors() const noexcept
{
    return m_factors;
}

bool AuthenticationStrength::isMultiFactor() const noexcept
{
    return std::popcount(static_cast<std::uint8_t>(m_factors)) >= 2;
}

bool AuthenticationStrength::isPhishingResistant() const noexcept
{
    return m_phishingResistant;
}

}
