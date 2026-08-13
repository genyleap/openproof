module;

#include <string>
#include <string_view>
#include <optional>
#include <vector>

export module openproof.oidc:service;

import openproof.client;
import openproof.foundation;
import openproof.identity.profile;
import openproof.oauth;
import openproof.security;
import openproof.token;

export namespace openproof::oidc {

/** @brief Validated OpenID Provider issuer identifier. */
class Issuer final {
public:
    Issuer(const Issuer& other);
    Issuer(Issuer&& other);
    Issuer& operator=(const Issuer& other);
    Issuer& operator=(Issuer&& other);
    ~Issuer();

    [[nodiscard]] static foundation::Result<Issuer> create(std::string value);
    [[nodiscard]] std::string_view value() const noexcept;
private:
    explicit Issuer(std::string value);
    std::string m_value;
};

class OidcPolicy final {
public:
    OidcPolicy(const OidcPolicy& other);
    OidcPolicy(OidcPolicy&& other);
    OidcPolicy& operator=(const OidcPolicy& other);
    OidcPolicy& operator=(OidcPolicy&& other);
    ~OidcPolicy();

    [[nodiscard]] static foundation::Result<OidcPolicy>
    create(foundation::Duration idTokenLifetime);
    [[nodiscard]] foundation::Duration idTokenLifetime() const noexcept;
private:
    explicit OidcPolicy(foundation::Duration idTokenLifetime);
    foundation::Duration m_idTokenLifetime{};
};

/** Public verification-only RSA key retained during a signing-key overlap. */
class PublishedVerificationJwk final {
public:
    PublishedVerificationJwk(const PublishedVerificationJwk& other);
    PublishedVerificationJwk(PublishedVerificationJwk&& other);
    PublishedVerificationJwk& operator=(const PublishedVerificationJwk& other);
    PublishedVerificationJwk& operator=(PublishedVerificationJwk&& other);
    ~PublishedVerificationJwk();

    [[nodiscard]] static foundation::Result<PublishedVerificationJwk>
    create(std::string_view publicKeyPem, std::string keyId);
private:
    friend class OpenIdProvider;
    explicit PublishedVerificationJwk(std::string json);
    std::string m_json;
};

/** @brief OIDC Core service for discovery, JWKS, ID Token and UserInfo. */
class OpenIdProvider final {
public:
    OpenIdProvider(Issuer issuer, const foundation::ClockSource& clock,
                   security::RsaSha256Signer signer,
                   identity::profile::IdentityProfileRepository& profiles,
                   OidcPolicy policy,
                   std::vector<PublishedVerificationJwk> publishedVerificationJwks = {});

    [[nodiscard]] std::string discoveryDocument() const;
    [[nodiscard]] foundation::Result<std::string> jwksDocument() const;
    [[nodiscard]] foundation::Result<std::string>
    issueIdToken(const oauth::RedeemedAuthorization& authorization) const;
    /** @brief Signs a JARM authorization response for one OAuth client. */
    [[nodiscard]] foundation::Result<std::string> issueAuthorizationResponse(
        const client::ClientId& clientId, std::optional<std::string_view> code,
        std::optional<std::string_view> state,
        std::optional<std::string_view> error = std::nullopt) const;
    [[nodiscard]] foundation::Result<std::string>
    userInfo(const token::TokenClaims& claims) const;
    [[nodiscard]] std::string_view issuer() const noexcept;

private:
    Issuer m_issuer;
    const foundation::ClockSource* m_clock;
    security::RsaSha256Signer m_signer;
    std::vector<PublishedVerificationJwk> m_publishedVerificationJwks;
    identity::profile::IdentityProfileRepository* m_profiles;
    OidcPolicy m_policy;
};

}
