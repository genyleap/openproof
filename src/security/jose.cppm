module;

#include <memory>
#include <string>
#include <string_view>

export module openproof.security:jose;

import openproof.foundation;

export namespace openproof::security {

/**
 * @brief OpenSSL-backed RSA SHA-256 signer for OIDC ID Tokens.
 *
 * The private key never crosses this cryptographic adapter as a general string.
 * Callers provide it as SecretString and only compact JWS plus the public JWK
 * are exposed. RSA keys shorter than 2048 bits are rejected.
 */
class RsaSha256Signer final {
public:
    [[nodiscard]] static foundation::Result<RsaSha256Signer>
    create(foundation::SecretString privateKeyPem, std::string keyId);

    RsaSha256Signer(const RsaSha256Signer&) = delete;
    RsaSha256Signer& operator=(const RsaSha256Signer&) = delete;
    RsaSha256Signer(RsaSha256Signer&&) noexcept;
    RsaSha256Signer& operator=(RsaSha256Signer&&) noexcept;
    ~RsaSha256Signer();

    [[nodiscard]] foundation::Result<std::string>
    signJwt(std::string_view payloadJson) const;
    [[nodiscard]] foundation::Result<std::string> publicJwkJson() const;
    [[nodiscard]] std::string_view keyId() const noexcept;

private:
    class Implementation;
    explicit RsaSha256Signer(std::unique_ptr<Implementation> implementation);
    std::unique_ptr<Implementation> m_implementation;
};

/** @brief Decoded components of a compact JWS after a successful RS256 verification. */
class VerifiedCompactJws final {
public:
    VerifiedCompactJws(std::string headerJson, std::string payloadJson);
    [[nodiscard]] std::string_view headerJson() const noexcept;
    [[nodiscard]] std::string_view payloadJson() const noexcept;
private:
    std::string m_headerJson;
    std::string m_payloadJson;
};

/**
 * @brief Verifies a compact JWS with a pinned RSA public key using RSASSA-PKCS1-v1_5 SHA-256.
 *
 * Algorithm and key-id policy remain the caller's responsibility; this primitive
 * never selects a key from attacker-controlled JOSE metadata.
 */
/**
 * @brief Validates that a PEM value is an RSA public key suitable for RS256 verification.
 *
 * The key must parse as a public key and contain at least 2048 RSA bits.
 */
[[nodiscard]] foundation::Status validateRs256PublicKey(std::string_view publicKeyPem);

/** Converts a validated RSA public PEM into one publishable RS256 JWK. */
[[nodiscard]] foundation::Result<std::string> rsaPublicJwkJson(
    std::string_view publicKeyPem, std::string keyId);

[[nodiscard]] foundation::Result<VerifiedCompactJws> verifyRs256Jwt(
    std::string_view publicKeyPem, std::string_view compactJwt);

/**
 * @brief Verifies an RS256 compact JWS with an inline RSA JWK.
 *
 * The modulus and exponent must use canonical base64url encoding. The function
 * validates the RSA key before signature verification and never accepts private
 * JWK material.
 */
[[nodiscard]] foundation::Result<VerifiedCompactJws> verifyRs256Jwk(
    std::string_view modulusBase64Url, std::string_view exponentBase64Url,
    std::string_view compactJwt);

/** @brief Computes the RFC 7638 SHA-256 thumbprint of a canonical RSA JWK. */
[[nodiscard]] foundation::Result<std::string> rsaJwkThumbprint(
    std::string_view modulusBase64Url, std::string_view exponentBase64Url);

}
