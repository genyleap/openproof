module;

#include <cstddef>
#include <limits>
#include <string>
#include <vector>

#include <openssl/rand.h>

module openproof.security;

namespace openproof::security {

foundation::Result<std::vector<std::byte>> randomBytes(std::size_t count)
{
    if (count == 0U) {
        return std::vector<std::byte>{};
    }

    if (count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Requested random byte count is too large.");
    }

    std::vector<std::byte> buffer(count);

    // SYN-006 justification: the C API writes raw octets. std::byte and
    // unsigned char are both narrow character types permitted to alias any
    // object representation, so this is the defined way to hand a byte buffer
    // to a C interface. The cast is confined to this adapter boundary and no
    // reinterpreted pointer escapes the function.
    const int status = RAND_bytes(reinterpret_cast<unsigned char*>(buffer.data()),
                                  static_cast<int>(count));
    if (status != 1) {
        // Fail loudly. A weaker fallback source here would silently undermine
        // every nonce and session identifier in the platform.
        return foundation::fail(
            foundation::ErrorCode::Internal,
            std::string{foundation::defaultErrorMessage(foundation::ErrorCode::Internal)},
            "The cryptographic random number generator failed.");
    }

    return buffer;
}

foundation::Result<std::string> randomTokenBase64Url(std::size_t byteCount)
{
    const auto bytes = randomBytes(byteCount);
    if (!bytes.has_value()) {
        return foundation::fail(bytes.error());
    }
    return foundation::toBase64Url(bytes.value());
}

}
