module;

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

module openproof.identity.provider;

namespace openproof::identity::provider {

CredentialValue::CredentialValue(std::string value)
    : m_value(std::move(value))
{
}

CredentialValue::CredentialValue(CredentialValue&& other) noexcept
    : m_value(std::move(other.m_value))
{
    other.wipe();
}

CredentialValue& CredentialValue::operator=(CredentialValue&& other) noexcept
{
    if (this != &other) {
        wipe();
        m_value = std::move(other.m_value);
        other.wipe();
    }
    return *this;
}

CredentialValue::~CredentialValue()
{
    wipe();
}

const std::string& CredentialValue::expose() const noexcept
{
    return m_value;
}

bool CredentialValue::empty() const noexcept
{
    return m_value.empty();
}

void CredentialValue::wipe() noexcept
{
    if (!m_value.empty()) {
        foundation::secureWipe(m_value.data(), m_value.size());
        m_value.clear();
    }
}

std::string_view claimNameKey(ClaimName name) noexcept
{
    switch (name) {
    case ClaimName::Email:
        return "email";
    case ClaimName::EmailVerified:
        return "email_verified";
    case ClaimName::PhoneNumber:
        return "phone_number";
    case ClaimName::PhoneNumberVerified:
        return "phone_number_verified";
    case ClaimName::DisplayName:
        return "display_name";
    case ClaimName::PreferredUsername:
        return "preferred_username";
    case ClaimName::Locale:
        return "locale";
    case ClaimName::PictureUrl:
        return "picture_url";
    }
    return "unknown";
}

void VerifiedClaims::set(ClaimName name, std::string value)
{
    m_claims.insert_or_assign(std::string{claimNameKey(name)}, std::move(value));
}

void VerifiedClaims::setExtension(std::string key, std::string value)
{
    m_claims.insert_or_assign(std::move(key), std::move(value));
}

std::optional<std::string_view> VerifiedClaims::get(ClaimName name) const
{
    return getExtension(claimNameKey(name));
}

std::optional<std::string_view> VerifiedClaims::getExtension(std::string_view key) const
{
    const auto position = m_claims.find(key);
    if (position == m_claims.end()) {
        return std::nullopt;
    }
    return std::string_view{position->second};
}

bool VerifiedClaims::isTrue(ClaimName name) const
{
    const std::optional<std::string_view> value = get(name);
    return value.has_value() && (*value == "true" || *value == "1");
}

bool VerifiedClaims::empty() const noexcept
{
    return m_claims.empty();
}

std::size_t VerifiedClaims::size() const noexcept
{
    return m_claims.size();
}

const AttributeMap& VerifiedClaims::all() const noexcept
{
    return m_claims;
}

void ProviderEvidence::add(std::string key, std::string value)
{
    m_attributes.insert_or_assign(std::move(key), std::move(value));
}

std::optional<std::string_view> ProviderEvidence::get(std::string_view key) const
{
    const auto position = m_attributes.find(key);
    if (position == m_attributes.end()) {
        return std::nullopt;
    }
    return std::string_view{position->second};
}

bool ProviderEvidence::empty() const noexcept
{
    return m_attributes.empty();
}

const AttributeMap& ProviderEvidence::all() const noexcept
{
    return m_attributes;
}

AuthenticationOutcome::AuthenticationOutcome(ProviderId provider, ExternalSubject subject,
                                             VerifiedClaims claims,
                                             AssuranceLevel claimedAssurance,
                                             AuthenticationStrength strength,
                                             ProviderEvidence evidence,
                                             foundation::Instant verifiedAt)
    : m_provider(std::move(provider))
    , m_subject(std::move(subject))
    , m_claims(std::move(claims))
    , m_claimedAssurance(claimedAssurance)
    , m_strength(strength)
    , m_evidence(std::move(evidence))
    , m_verifiedAt(verifiedAt)
{
}

foundation::Result<AuthenticationOutcome>
AuthenticationOutcome::create(ProviderId provider, ExternalSubject subject, VerifiedClaims claims,
                              AssuranceLevel claimedAssurance, AuthenticationStrength strength,
                              ProviderEvidence evidence, foundation::Instant verifiedAt)
{
    if (provider.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An authentication outcome must name its provider.");
    }
    if (subject.empty()) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "An authentication outcome must carry a subject identifier.",
            "A provider returned an outcome with an empty external subject; accepting it "
            "would bind a session to no identity.");
    }

    return AuthenticationOutcome{std::move(provider),  std::move(subject),
                                 std::move(claims),    claimedAssurance,
                                 strength,             std::move(evidence),
                                 verifiedAt};
}

const ProviderId& AuthenticationOutcome::provider() const noexcept
{
    return m_provider;
}

const ExternalSubject& AuthenticationOutcome::subject() const noexcept
{
    return m_subject;
}

const VerifiedClaims& AuthenticationOutcome::claims() const noexcept
{
    return m_claims;
}

AssuranceLevel AuthenticationOutcome::claimedAssurance() const noexcept
{
    return m_claimedAssurance;
}

const AuthenticationStrength& AuthenticationOutcome::strength() const noexcept
{
    return m_strength;
}

const ProviderEvidence& AuthenticationOutcome::evidence() const noexcept
{
    return m_evidence;
}

foundation::Instant AuthenticationOutcome::verifiedAt() const noexcept
{
    return m_verifiedAt;
}

}
