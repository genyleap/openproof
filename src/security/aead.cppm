module;

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

export module openproof.security:aead;

import openproof.foundation;

export namespace openproof::security {

/** Exact 256-bit key for authenticated encryption of credentials at rest. */
class AeadKey final {
public:
    [[nodiscard]] static foundation::Result<AeadKey>
    create(foundation::SecretString key);
    AeadKey(const AeadKey&) = delete;
    AeadKey& operator=(const AeadKey&) = delete;
    AeadKey(AeadKey&&) noexcept = default;
    AeadKey& operator=(AeadKey&&) noexcept = default;
private:
    friend foundation::Result<std::vector<std::byte>> sealAes256Gcm(
        const AeadKey&, const foundation::SecretString&, std::string_view);
    friend foundation::Result<foundation::SecretString> openAes256Gcm(
        const AeadKey&, std::span<const std::byte>, std::string_view);
    explicit AeadKey(foundation::SecretString key);
    foundation::SecretString m_key;
};

/** Envelope is nonce(12) || ciphertext || authentication-tag(16). */
[[nodiscard]] foundation::Result<std::vector<std::byte>>
sealAes256Gcm(const AeadKey& key, const foundation::SecretString& plaintext,
              std::string_view associatedData);

[[nodiscard]] foundation::Result<foundation::SecretString>
openAes256Gcm(const AeadKey& key, std::span<const std::byte> envelope,
              std::string_view associatedData);

}

