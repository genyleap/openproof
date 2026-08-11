module;

#include <algorithm>
#include <climits>
#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

#include <openssl/evp.h>

module openproof.security;

namespace openproof::security {
namespace {

constexpr std::size_t kNonceBytes = 12U;
constexpr std::size_t kTagBytes = 16U;
constexpr std::size_t kMaximumPlaintextBytes = 4096U;

struct ContextDeleter final {
    void operator()(EVP_CIPHER_CTX* context) const noexcept
    {
        if (context != nullptr) EVP_CIPHER_CTX_free(context);
    }
};
using Context = std::unique_ptr<EVP_CIPHER_CTX, ContextDeleter>;

[[nodiscard]] unsigned char* octets(std::byte* data) noexcept
{
    return reinterpret_cast<unsigned char*>(data);
}

[[nodiscard]] const unsigned char* octets(const std::byte* data) noexcept
{
    return reinterpret_cast<const unsigned char*>(data);
}

[[nodiscard]] foundation::Error cryptographicFailure(std::string detail)
{
    return foundation::Error{foundation::ErrorCode::Internal,
                             "An internal error occurred.", std::move(detail)};
}

}

AeadKey::AeadKey(foundation::SecretString key) : m_key(std::move(key)) {}

foundation::Result<AeadKey> AeadKey::create(foundation::SecretString key)
{
    if (key.expose().size() != 32U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An authenticated-encryption key must contain exactly 32 bytes.");
    }
    return AeadKey{std::move(key)};
}

foundation::Result<std::vector<std::byte>> sealAes256Gcm(
    const AeadKey& key, const foundation::SecretString& plaintext,
    std::string_view associatedData)
{
    if (plaintext.empty() || plaintext.expose().size() > kMaximumPlaintextBytes
        || associatedData.size() > kMaximumPlaintextBytes
        || plaintext.expose().size() > static_cast<std::size_t>(INT_MAX)
        || associatedData.size() > static_cast<std::size_t>(INT_MAX)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The authenticated-encryption input is invalid.");
    }
    auto nonce = randomBytes(kNonceBytes);
    if (!nonce.has_value()) return foundation::fail(nonce.error());
    Context context{EVP_CIPHER_CTX_new()};
    if (!context) return foundation::fail(cryptographicFailure("EVP context allocation failed."));
    const auto* keyBytes = reinterpret_cast<const unsigned char*>(key.m_key.expose().data());
    if (EVP_EncryptInit_ex2(context.get(), EVP_aes_256_gcm(), keyBytes,
                            octets(nonce->data()), nullptr) != 1) {
        return foundation::fail(cryptographicFailure("AES-GCM initialization failed."));
    }
    int written = 0;
    if (!associatedData.empty()
        && EVP_EncryptUpdate(context.get(), nullptr, &written,
            reinterpret_cast<const unsigned char*>(associatedData.data()),
            static_cast<int>(associatedData.size())) != 1) {
        return foundation::fail(cryptographicFailure("AES-GCM AAD processing failed."));
    }
    std::vector<std::byte> envelope(kNonceBytes + plaintext.expose().size() + kTagBytes);
    std::ranges::copy(nonce.value(), envelope.begin());
    if (EVP_EncryptUpdate(context.get(), octets(envelope.data() + kNonceBytes), &written,
            reinterpret_cast<const unsigned char*>(plaintext.expose().data()),
            static_cast<int>(plaintext.expose().size())) != 1
        || written != static_cast<int>(plaintext.expose().size())) {
        return foundation::fail(cryptographicFailure("AES-GCM encryption failed."));
    }
    int finalBytes = 0;
    if (EVP_EncryptFinal_ex(context.get(),
            octets(envelope.data() + kNonceBytes + plaintext.expose().size()),
            &finalBytes) != 1 || finalBytes != 0
        || EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
            static_cast<int>(kTagBytes),
            octets(envelope.data() + kNonceBytes + plaintext.expose().size())) != 1) {
        return foundation::fail(cryptographicFailure("AES-GCM finalization failed."));
    }
    return envelope;
}

foundation::Result<foundation::SecretString> openAes256Gcm(
    const AeadKey& key, std::span<const std::byte> envelope,
    std::string_view associatedData)
{
    if (envelope.size() <= kNonceBytes + kTagBytes
        || envelope.size() > kNonceBytes + kMaximumPlaintextBytes + kTagBytes
        || associatedData.size() > kMaximumPlaintextBytes
        || associatedData.size() > static_cast<std::size_t>(INT_MAX)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The encrypted credential envelope is invalid.");
    }
    const std::size_t ciphertextBytes = envelope.size() - kNonceBytes - kTagBytes;
    Context context{EVP_CIPHER_CTX_new()};
    if (!context) return foundation::fail(cryptographicFailure("EVP context allocation failed."));
    const auto* keyBytes = reinterpret_cast<const unsigned char*>(key.m_key.expose().data());
    if (EVP_DecryptInit_ex2(context.get(), EVP_aes_256_gcm(), keyBytes,
                            octets(envelope.data()), nullptr) != 1) {
        return foundation::fail(cryptographicFailure("AES-GCM initialization failed."));
    }
    int written = 0;
    if (!associatedData.empty()
        && EVP_DecryptUpdate(context.get(), nullptr, &written,
            reinterpret_cast<const unsigned char*>(associatedData.data()),
            static_cast<int>(associatedData.size())) != 1) {
        return foundation::fail(cryptographicFailure("AES-GCM AAD processing failed."));
    }
    std::string plaintext(ciphertextBytes, '\0');
    if (EVP_DecryptUpdate(context.get(),
            reinterpret_cast<unsigned char*>(plaintext.data()), &written,
            octets(envelope.data() + kNonceBytes),
            static_cast<int>(ciphertextBytes)) != 1
        || written != static_cast<int>(ciphertextBytes)
        || EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(kTagBytes),
            const_cast<unsigned char*>(octets(envelope.data() + kNonceBytes + ciphertextBytes))) != 1) {
        foundation::secureWipe(plaintext.data(), plaintext.size());
        return foundation::fail(cryptographicFailure("AES-GCM decryption setup failed."));
    }
    int finalBytes = 0;
    if (EVP_DecryptFinal_ex(context.get(),
            reinterpret_cast<unsigned char*>(plaintext.data()) + written,
            &finalBytes) != 1 || finalBytes != 0) {
        foundation::secureWipe(plaintext.data(), plaintext.size());
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed,
                                "Encrypted credential authentication failed.");
    }
    return foundation::SecretString{std::move(plaintext)};
}

}
