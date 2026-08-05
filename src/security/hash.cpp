module;

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

#include <openssl/crypto.h>
#include <openssl/evp.h>

module openproof.security;

namespace openproof::security {

namespace {

/**
 * Reinterprets a byte span as the octet pointer the C cryptographic API takes.
 *
 * SYN-006 justification: std::byte and unsigned char are narrow character types
 * permitted to alias any object representation, so this is the defined way to
 * pass a byte buffer to a C interface. Confined to this adapter boundary.
 */
[[nodiscard]] const unsigned char* asOctets(std::span<const std::byte> data) noexcept
{
    return reinterpret_cast<const unsigned char*>(data.data());
}

[[nodiscard]] std::span<const std::byte> asBytes(std::string_view text) noexcept
{
    return std::as_bytes(std::span{text.data(), text.size()});
}

}

foundation::Result<Sha256Digest> sha256(std::span<const std::byte> data)
{
    Sha256Digest digest{};
    unsigned int digestLength = 0;

    const int status = EVP_Digest(data.empty() ? nullptr : asOctets(data),
                                  data.size(),
                                  reinterpret_cast<unsigned char*>(digest.data()),
                                  &digestLength,
                                  EVP_sha256(),
                                  nullptr);

    if (status != 1 || digestLength != digest.size()) {
        return foundation::fail(
            foundation::ErrorCode::Internal,
            std::string{foundation::defaultErrorMessage(foundation::ErrorCode::Internal)},
            "SHA-256 computation failed in the cryptographic provider.");
    }

    return digest;
}

foundation::Result<Sha256Digest> sha256(std::string_view data)
{
    return sha256(asBytes(data));
}

bool constantTimeEquals(std::span<const std::byte> left,
                        std::span<const std::byte> right) noexcept
{
    if (left.size() != right.size()) {
        return false;
    }
    if (left.empty()) {
        return true;
    }
    return CRYPTO_memcmp(asOctets(left), asOctets(right), left.size()) == 0;
}

bool constantTimeEquals(std::string_view left, std::string_view right) noexcept
{
    return constantTimeEquals(asBytes(left), asBytes(right));
}

}
