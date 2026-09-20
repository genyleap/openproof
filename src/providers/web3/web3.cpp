module;

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/json.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ssl.h>

module openproof.provider.web3;

import openproof.security;

namespace openproof::provider::web3 {
namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace json = boost::json;
namespace idp = identity::provider;
using Tcp = asio::ip::tcp;

constexpr std::size_t kMaximumRpcResponse = 2U * 1024U * 1024U;
constexpr std::string_view kWalletStatement{"Sign in to OpenProof with your Ethereum account."};
constexpr std::string_view kFarcasterStatement{"Farcaster Auth"};
constexpr std::string_view kErc1271Magic{"0x1626ba7e"};
constexpr std::uint64_t kOptimismMainnetChainId = 10U;
constexpr std::uint64_t kFarcasterAuthAddressKeyType = 2U;

constexpr std::string_view kUniversalSignatureValidatorByteCode{
    "0x608060405234801561001057600080fd5b5060405161069438038061069483398101604081905261002f9161051e565b600061003c8484"
    "84610048565b9050806000526001601ff35b60007f6492649264926492649264926492649264926492649264926492649264926492610074"
    "8361040c565b036101e7576000606080848060200190518101906100929190610577565b60405192955090935091506000906001600160a0"
    "1b038516906100b69085906105dd565b6000604051808303816000865af19150503d80600081146100f3576040519150601f19603f3d0116"
    "82016040523d82523d6000602084013e6100f8565b606091505b50509050876001600160a01b03163b600003610160578061016057604051"
    "62461bcd60e51b815260206004820152601e60248201527f5369676e617475726556616c696461746f723a206465706c6f796d656e740000"
    "60448201526064015b60405180910390fd5b604051630b135d3f60e11b808252906001600160a01b038a1690631626ba7e90610190908b90"
    "87906004016105f9565b602060405180830381865afa1580156101ad573d6000803e3d6000fd5b505050506040513d601f19601f82011682"
    "0180604052508101906101d19190610633565b6001600160e01b03191614945050505050610405565b6001600160a01b0384163b1561027a"
    "57604051630b135d3f60e11b808252906001600160a01b03861690631626ba7e9061022790879087906004016105f9565b60206040518083"
    "0381865afa158015610244573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906102689190610633"
    "565b6001600160e01b031916149050610405565b81516041146102df5760405162461bcd60e51b815260206004820152603a602482015260"
    "008051602061067483398151915260448201527f3a20696e76616c6964207369676e6174757265206c656e67746800000000000060648201"
    "52608401610157565b6102e7610425565b5060208201516040808401518451859392600091859190811061030c5761030c61065d565b0160"
    "20015160f81c9050601b811480159061032b57508060ff16601c14155b1561038c5760405162461bcd60e51b815260206004820152603b60"
    "2482015260008051602061067483398151915260448201527f3a20696e76616c6964207369676e617475726520762076616c756500000000"
    "006064820152608401610157565b60408051600081526020810180835289905260ff83169181019190915260608101849052608081018390"
    "526001600160a01b0389169060019060a0016020604051602081039080840390855afa1580156103ea573d6000803e3d6000fd5b50505060"
    "2060405103516001600160a01b0316149450505050505b9392505050565b600060208251101561041d57600080fd5b508051015190565b60"
    "405180606001604052806003906020820280368337509192915050565b6001600160a01b038116811461045857600080fd5b50565b634e48"
    "7b7160e01b600052604160045260246000fd5b60005b8381101561048c578181015183820152602001610474565b50506000910152565b60"
    "0082601f8301126104a657600080fd5b81516001600160401b038111156104bf576104bf61045b565b604051601f8201601f19908116603f"
    "011681016001600160401b03811182821017156104ed576104ed61045b565b60405281815283820160200185101561050557600080fd5b61"
    "0516826020830160208701610471565b949350505050565b60008060006060848603121561053357600080fd5b835161053e81610443565b"
    "6020850151604086015191945092506001600160401b0381111561056157600080fd5b61056d86828701610495565b915050925092509256"
    "5b60008060006060848603121561058c57600080fd5b835161059781610443565b60208501519093506001600160401b038111156105b357"
    "600080fd5b6105bf86828701610495565b604086015190935090506001600160401b0381111561056157600080fd5b600082516105ef8184"
    "60208701610471565b9190910192915050565b828152604060208201526000825180604084015261061e816060850160208701610471565b"
    "601f01601f1916919091016060019392505050565b60006020828403121561064557600080fd5b81516001600160e01b0319811681146104"
    "0557600080fd5b634e487b7160e01b600052603260045260246000fdfe5369676e617475726556616c696461746f72237265636f76657253"
    "69676e6572"
};

struct HttpsUrl final {
    std::string host;
    std::string port{"443"};
    std::string target{"/"};
};

[[nodiscard]] foundation::Error authenticationFailure(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

[[nodiscard]] bool safeText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] bool validDomain(std::string_view value) noexcept
{
    if (!safeText(value, 253U) || value.contains('/') || value.contains('@')
        || value.contains('\\') || value.starts_with('.') || value.ends_with('.')) {
        return false;
    }
    return std::ranges::all_of(value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return std::isalnum(byte) != 0 || symbol == '.' || symbol == '-' || symbol == ':';
    });
}

[[nodiscard]] bool validHttpsHost(std::string_view value) noexcept
{
    if (!safeText(value, 253U) || value.starts_with('.') || value.ends_with('.')
        || value.contains("..") || value.contains(':')) {
        return false;
    }
    return std::ranges::all_of(value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return std::isalnum(byte) != 0 || symbol == '.' || symbol == '-';
    });
}

[[nodiscard]] foundation::Result<HttpsUrl> parseHttpsUrl(std::string_view raw)
{
    constexpr std::string_view prefix{"https://"};
    if (!raw.starts_with(prefix) || raw.size() > 4096U || raw.contains('#')
        || raw.contains('\\')
        || std::ranges::any_of(raw, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte <= 0x20U || byte == 0x7FU;
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A Web3 endpoint must be a structurally valid HTTPS URL.");
    }

    raw.remove_prefix(prefix.size());
    const auto slash = raw.find('/');
    const auto query = raw.find('?');
    const auto authorityEnd = std::min(
        slash == std::string_view::npos ? raw.size() : slash,
        query == std::string_view::npos ? raw.size() : query);
    const auto authority = raw.substr(0U, authorityEnd);
    if (authority.empty() || authority.contains('@')
        || authority.contains('[') || authority.contains(']')) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A Web3 endpoint has an invalid HTTPS authority.");
    }

    HttpsUrl output;
    std::string_view host = authority;
    if (const auto colon = authority.rfind(':'); colon != std::string_view::npos) {
        if (authority.find(':') != colon) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "A Web3 endpoint has an invalid HTTPS authority.");
        }
        host = authority.substr(0U, colon);
        const auto portText = authority.substr(colon + 1U);
        unsigned int port{};
        const auto parsed = std::from_chars(
            portText.data(), portText.data() + portText.size(), port);
        if (portText.empty() || parsed.ec != std::errc{}
            || parsed.ptr != portText.data() + portText.size()
            || port == 0U || port > 65535U) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "A Web3 endpoint has an invalid HTTPS port.");
        }
        output.port = std::string{portText};
    }
    if (!validHttpsHost(host)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A Web3 endpoint has an invalid HTTPS host.");
    }
    output.host = std::string{host};

    if (authorityEnd < raw.size()) {
        if (raw[authorityEnd] == '/') {
            output.target = std::string{raw.substr(authorityEnd)};
        } else {
            output.target = "/";
            output.target.append(raw.substr(authorityEnd));
        }
    }
    return output;
}

[[nodiscard]] bool isHex(char value) noexcept
{
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')
        || (value >= 'A' && value <= 'F');
}

[[nodiscard]] unsigned int hexNibble(char value) noexcept
{
    if (value >= '0' && value <= '9') return static_cast<unsigned int>(value - '0');
    if (value >= 'a' && value <= 'f') return 10U + static_cast<unsigned int>(value - 'a');
    return 10U + static_cast<unsigned int>(value - 'A');
}

[[nodiscard]] std::optional<std::vector<std::byte>> decodeHex(std::string_view value)
{
    if (value.starts_with("0x")) value.remove_prefix(2U);
    if ((value.size() % 2U) != 0U || !std::ranges::all_of(value, isHex)) return std::nullopt;
    std::vector<std::byte> output(value.size() / 2U);
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = static_cast<std::byte>(
            (hexNibble(value[index * 2U]) << 4U) | hexNibble(value[index * 2U + 1U]));
    }
    return output;
}

[[nodiscard]] std::string encodeHex(std::span<const std::byte> input, bool prefix = true)
{
    constexpr char alphabet[] = "0123456789abcdef";
    std::string output;
    output.reserve(input.size() * 2U + (prefix ? 2U : 0U));
    if (prefix) output.append("0x");
    for (const std::byte value : input) {
        const auto byte = std::to_integer<unsigned int>(value);
        output.push_back(alphabet[(byte >> 4U) & 0x0FU]);
        output.push_back(alphabet[byte & 0x0FU]);
    }
    return output;
}

[[nodiscard]] std::optional<std::string> normalizeAddress(std::string_view value)
{
    if (value.size() != 42U || !value.starts_with("0x")
        || !std::ranges::all_of(value.substr(2U), isHex)) return std::nullopt;
    std::string output{value};
    std::ranges::transform(output, output.begin(), [](unsigned char symbol) {
        return static_cast<char>(std::tolower(symbol));
    });
    return output;
}

[[nodiscard]] constexpr std::uint64_t rotateLeft64(
    std::uint64_t value, unsigned int shift) noexcept
{
    return shift == 0U ? value : std::rotl(value, static_cast<int>(shift));
}

void keccakF1600(std::array<std::uint64_t, 25>& state) noexcept
{
    constexpr std::array<std::uint64_t, 24> roundConstants{
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL};
    constexpr std::array<unsigned int, 25> rotation{
         0U,  1U, 62U, 28U, 27U,
        36U, 44U,  6U, 55U, 20U,
         3U, 10U, 43U, 25U, 39U,
        41U, 45U, 15U, 21U,  8U,
        18U,  2U, 61U, 56U, 14U};

    for (const std::uint64_t roundConstant : roundConstants) {
        std::array<std::uint64_t, 5> columns{};
        for (std::size_t x = 0U; x < 5U; ++x) {
            columns[x] = state[x] ^ state[x + 5U] ^ state[x + 10U]
                ^ state[x + 15U] ^ state[x + 20U];
        }
        std::array<std::uint64_t, 5> delta{};
        for (std::size_t x = 0U; x < 5U; ++x) {
            delta[x] = columns[(x + 4U) % 5U]
                ^ rotateLeft64(columns[(x + 1U) % 5U], 1U);
        }
        for (std::size_t y = 0U; y < 5U; ++y) {
            for (std::size_t x = 0U; x < 5U; ++x) {
                state[x + 5U * y] ^= delta[x];
            }
        }

        std::array<std::uint64_t, 25> permuted{};
        for (std::size_t y = 0U; y < 5U; ++y) {
            for (std::size_t x = 0U; x < 5U; ++x) {
                const std::size_t targetX = y;
                const std::size_t targetY = (2U * x + 3U * y) % 5U;
                permuted[targetX + 5U * targetY]
                    = rotateLeft64(state[x + 5U * y], rotation[x + 5U * y]);
            }
        }

        for (std::size_t y = 0U; y < 5U; ++y) {
            for (std::size_t x = 0U; x < 5U; ++x) {
                state[x + 5U * y] = permuted[x + 5U * y]
                    ^ ((~permuted[(x + 1U) % 5U + 5U * y])
                        & permuted[(x + 2U) % 5U + 5U * y]);
            }
        }
        state[0] ^= roundConstant;
    }
}

[[nodiscard]] constexpr std::uint64_t loadLittleEndian64(
    std::span<const std::byte, 8> input) noexcept
{
    std::uint64_t value{};
    for (std::size_t index = 0U; index < 8U; ++index) {
        value |= static_cast<std::uint64_t>(
            std::to_integer<unsigned int>(input[index])) << (index * 8U);
    }
    return value;
}

[[nodiscard]] std::array<std::byte, 32> keccak256Raw(
    std::span<const std::byte> input)
{
    constexpr std::size_t rateBytes = 136U;
    std::array<std::uint64_t, 25> state{};

    auto absorb = [&state](std::span<const std::byte, rateBytes> block) {
        for (std::size_t lane = 0U; lane < rateBytes / 8U; ++lane) {
            const auto laneBytes = block.subspan(lane * 8U, 8U);
            std::array<std::byte, 8> copy{};
            std::ranges::copy(laneBytes, copy.begin());
            state[lane] ^= loadLittleEndian64(copy);
        }
        keccakF1600(state);
    };

    while (input.size() >= rateBytes) {
        std::array<std::byte, rateBytes> block{};
        std::ranges::copy(input.first(rateBytes), block.begin());
        absorb(block);
        input = input.subspan(rateBytes);
    }

    std::array<std::byte, rateBytes> finalBlock{};
    std::ranges::copy(input, finalBlock.begin());
    finalBlock[input.size()] ^= std::byte{0x01};
    finalBlock.back() ^= std::byte{0x80};
    absorb(finalBlock);

    std::array<std::byte, 32> digest{};
    for (std::size_t index = 0U; index < digest.size(); ++index) {
        digest[index] = static_cast<std::byte>(
            (state[index / 8U] >> ((index % 8U) * 8U)) & 0xffU);
    }
    return digest;
}

[[nodiscard]] foundation::Result<std::array<std::byte, 32>> keccak256(
    std::span<const std::byte> input)
{
    static const bool selfTestPassed = [] {
        const auto empty = keccak256Raw({});
        constexpr std::string_view hello{"hello"};
        const auto helloDigest = keccak256Raw(
            std::as_bytes(std::span{hello.data(), hello.size()}));
        return encodeHex(empty, false)
                == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
            && encodeHex(helloDigest, false)
                == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";
    }();
    if (!selfTestPassed) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "The built-in Keccak-256 self-test failed.");
    }
    return keccak256Raw(input);
}

[[nodiscard]] foundation::Result<std::array<std::byte, 32>> keccak256(std::string_view input)
{
    return keccak256(std::as_bytes(std::span{input.data(), input.size()}));
}

[[nodiscard]] foundation::Result<std::array<std::byte, 32>> ethereumMessageHash(
    std::string_view message)
{
    std::string prefix;
    prefix.reserve(1U + std::string_view{"Ethereum Signed Message:\n"}.size() + 20U);
    prefix.push_back(static_cast<char>(0x19));
    prefix.append("Ethereum Signed Message:\n");
    prefix.append(std::to_string(message.size()));
    std::vector<std::byte> material;
    material.reserve(prefix.size() + message.size());
    const auto prefixBytes = std::as_bytes(std::span{prefix.data(), prefix.size()});
    const auto messageBytes = std::as_bytes(std::span{message.data(), message.size()});
    material.insert(material.end(), prefixBytes.begin(), prefixBytes.end());
    material.insert(material.end(), messageBytes.begin(), messageBytes.end());
    return keccak256(material);
}

struct BnDeleter { void operator()(BIGNUM* value) const noexcept { BN_free(value); } };
struct BnCtxDeleter { void operator()(BN_CTX* value) const noexcept { BN_CTX_free(value); } };
struct GroupDeleter { void operator()(EC_GROUP* value) const noexcept { EC_GROUP_free(value); } };
struct PointDeleter { void operator()(EC_POINT* value) const noexcept { EC_POINT_free(value); } };
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;
using GroupPtr = std::unique_ptr<EC_GROUP, GroupDeleter>;
using PointPtr = std::unique_ptr<EC_POINT, PointDeleter>;

[[nodiscard]] foundation::Result<std::string> recoverAddress(
    std::span<const std::byte, 32> digest, std::string_view signatureText)
{
    auto decoded = decodeHex(signatureText);
    if (!decoded || decoded->size() != 65U) {
        return foundation::fail(authenticationFailure("The Ethereum signature has an invalid encoding."));
    }
    const unsigned int rawV = std::to_integer<unsigned int>((*decoded)[64]);
    int recoveryId{};
    if (rawV == 27U || rawV == 28U) recoveryId = static_cast<int>(rawV - 27U);
    else if (rawV <= 1U) recoveryId = static_cast<int>(rawV);
    else return foundation::fail(authenticationFailure("The Ethereum recovery identifier is invalid."));

    GroupPtr group{EC_GROUP_new_by_curve_name(NID_secp256k1)};
    BnCtxPtr context{BN_CTX_new()};
    if (!group || !context) return foundation::fail(foundation::ErrorCode::Internal);
    BnPtr order{BN_new()};
    BnPtr prime{BN_new()};
    BnPtr a{BN_new()};
    BnPtr b{BN_new()};
    if (!order || !prime || !a || !b
        || EC_GROUP_get_order(group.get(), order.get(), context.get()) != 1
        || EC_GROUP_get_curve(group.get(), prime.get(), a.get(), b.get(), context.get()) != 1) {
        return foundation::fail(foundation::ErrorCode::Internal);
    }
    BnPtr r{BN_bin2bn(reinterpret_cast<const unsigned char*>(decoded->data()), 32, nullptr)};
    BnPtr s{BN_bin2bn(reinterpret_cast<const unsigned char*>(decoded->data() + 32), 32, nullptr)};
    BnPtr e{BN_bin2bn(reinterpret_cast<const unsigned char*>(digest.data()), 32, nullptr)};
    if (!r || !s || !e || BN_is_zero(r.get()) || BN_is_zero(s.get())
        || BN_cmp(r.get(), order.get()) >= 0 || BN_cmp(s.get(), order.get()) >= 0) {
        return foundation::fail(authenticationFailure("The Ethereum signature scalars are invalid."));
    }
    BnPtr halfOrder{BN_dup(order.get())};
    if (!halfOrder || BN_rshift1(halfOrder.get(), halfOrder.get()) != 1
        || BN_cmp(s.get(), halfOrder.get()) > 0) {
        return foundation::fail(authenticationFailure("The Ethereum signature is not canonical low-s form."));
    }
    if (BN_cmp(r.get(), prime.get()) >= 0) {
        return foundation::fail(authenticationFailure("The Ethereum signature recovery point is invalid."));
    }
    PointPtr rPoint{EC_POINT_new(group.get())};
    PointPtr nTimesR{EC_POINT_new(group.get())};
    PointPtr sTimesR{EC_POINT_new(group.get())};
    PointPtr eTimesG{EC_POINT_new(group.get())};
    PointPtr sum{EC_POINT_new(group.get())};
    PointPtr publicKey{EC_POINT_new(group.get())};
    if (!rPoint || !nTimesR || !sTimesR || !eTimesG || !sum || !publicKey
        || EC_POINT_set_compressed_coordinates(group.get(), rPoint.get(), r.get(), recoveryId,
                                                context.get()) != 1
        || EC_POINT_mul(group.get(), nTimesR.get(), nullptr, rPoint.get(), order.get(), context.get()) != 1
        || EC_POINT_is_at_infinity(group.get(), nTimesR.get()) != 1) {
        return foundation::fail(authenticationFailure("The Ethereum signature recovery point is invalid."));
    }
    BnPtr eReduced{BN_new()};
    BnPtr negativeE{BN_new()};
    BnPtr inverseR{BN_mod_inverse(nullptr, r.get(), order.get(), context.get())};
    if (!eReduced || !negativeE || !inverseR
        || BN_nnmod(eReduced.get(), e.get(), order.get(), context.get()) != 1
        || BN_mod_sub(negativeE.get(), order.get(), eReduced.get(), order.get(), context.get()) != 1
        || EC_POINT_mul(group.get(), sTimesR.get(), nullptr, rPoint.get(), s.get(), context.get()) != 1
        || EC_POINT_mul(group.get(), eTimesG.get(), negativeE.get(), nullptr, nullptr, context.get()) != 1
        || EC_POINT_add(group.get(), sum.get(), sTimesR.get(), eTimesG.get(), context.get()) != 1
        || EC_POINT_mul(group.get(), publicKey.get(), nullptr, sum.get(), inverseR.get(), context.get()) != 1) {
        return foundation::fail(authenticationFailure("The Ethereum public key could not be recovered."));
    }
    std::array<unsigned char, 65> publicBytes{};
    const std::size_t written = EC_POINT_point2oct(
        group.get(), publicKey.get(), POINT_CONVERSION_UNCOMPRESSED,
        publicBytes.data(), publicBytes.size(), context.get());
    if (written != publicBytes.size() || publicBytes[0] != 0x04U) {
        return foundation::fail(authenticationFailure("The recovered Ethereum public key is malformed."));
    }
    const auto publicSpan = std::span{reinterpret_cast<const std::byte*>(publicBytes.data() + 1U), 64U};
    auto addressDigest = keccak256(publicSpan);
    if (!addressDigest) return foundation::fail(addressDigest.error());
    return encodeHex(std::span{addressDigest->data() + 12U, 20U});
}

struct RpcResponse final { json::value result; };

[[nodiscard]] foundation::Result<RpcResponse> rpc(
    std::string_view endpoint, std::string_view method, json::array parameters,
    std::string_view caFile, const foundation::SecretString& authorization)
{
    auto parsed = parseHttpsUrl(endpoint);
    if (!parsed) return foundation::fail(parsed.error());
    json::object body;
    body["jsonrpc"] = "2.0";
    body["id"] = 1;
    body["method"] = method;
    body["params"] = std::move(parameters);
    try {
        asio::io_context io;
        asio::ssl::context tls{asio::ssl::context::tls_client};
        tls.set_verify_mode(asio::ssl::verify_peer);
        if (caFile.empty()) tls.set_default_verify_paths();
        else tls.load_verify_file(std::string{caFile});
        Tcp::resolver resolver{io};
        beast::ssl_stream<beast::tcp_stream> stream{io, tls};
        std::string hostname{parsed->host};
        if (SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                     static_cast<long>(TLSEXT_NAMETYPE_host_name), hostname.data()) <= 0L) {
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "The Web3 RPC TLS peer could not be configured.");
        }
        stream.set_verify_callback(asio::ssl::host_name_verification(parsed->host));
        auto endpoints = resolver.resolve(parsed->host, parsed->port);
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds{10});
        beast::get_lowest_layer(stream).connect(endpoints);
        stream.handshake(asio::ssl::stream_base::client);
        http::request<http::string_body> request{http::verb::post, parsed->target, 11};
        std::string hostHeader{parsed->host};
        if (parsed->port != "443") {
            hostHeader.push_back(':');
            hostHeader.append(parsed->port);
        }
        request.set(http::field::host, hostHeader);
        request.set(http::field::user_agent, "OpenProof/1");
        request.set(http::field::accept, "application/json");
        request.set(http::field::content_type, "application/json");
        request.set(http::field::cache_control, "no-store");
        if (!authorization.expose().empty()) {
            request.set(http::field::authorization, authorization.expose());
        }
        request.body() = json::serialize(body);
        request.prepare_payload();
        http::write(stream, request);
        beast::flat_buffer buffer;
        http::response_parser<http::string_body> parser;
        parser.body_limit(kMaximumRpcResponse);
        http::read(stream, buffer, parser);
        auto response = parser.release();
        beast::error_code ignored;
        stream.shutdown(ignored);
        if (response.result_int() != 200U) {
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "The Web3 RPC endpoint returned a non-success status.");
        }
        boost::system::error_code parseError;
        auto decoded = json::parse(response.body(), parseError);
        if (parseError || !decoded.is_object()) {
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "The Web3 RPC response is malformed.");
        }
        const auto& object = decoded.as_object();
        if (object.if_contains("error") != nullptr) {
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "The Web3 RPC endpoint reported an error.");
        }
        const auto* result = object.if_contains("result");
        if (result == nullptr) {
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "The Web3 RPC response has no result.");
        }
        return RpcResponse{*result};
    } catch (...) {
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "The Web3 RPC HTTPS request failed.");
    }
}

[[nodiscard]] foundation::Result<std::string> rpcString(
    std::string_view endpoint, std::string_view method, json::array parameters,
    std::string_view caFile, const foundation::SecretString& authorization)
{
    auto response = rpc(endpoint, method, std::move(parameters), caFile, authorization);
    if (!response || !response->result.is_string()) {
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "The Web3 RPC result is not a string.");
    }
    return std::string{response->result.as_string()};
}

[[nodiscard]] std::string uint256Hex(std::uint64_t value)
{
    std::array<std::byte, 32> bytes{};
    for (std::size_t index = 0U; index < 8U; ++index) {
        bytes[31U - index] = static_cast<std::byte>((value >> (index * 8U)) & 0xFFU);
    }
    return encodeHex(bytes, false);
}

[[nodiscard]] foundation::Result<std::string> functionSelector(std::string_view signature)
{
    auto digest = keccak256(signature);
    if (!digest) return foundation::fail(digest.error());
    return encodeHex(std::span{digest->data(), 4U}, false);
}

[[nodiscard]] foundation::Result<bool> rpcChainMatches(
    std::string_view endpoint, std::uint64_t expected, std::string_view caFile,
    const foundation::SecretString& authorization)
{
    auto chain = rpcString(endpoint, "eth_chainId", {}, caFile, authorization);
    if (!chain || !chain->starts_with("0x") || chain->size() > 34U) {
        return foundation::fail(chain ? foundation::Error{foundation::ErrorCode::Unavailable}
                                      : chain.error());
    }
    std::uint64_t parsed{};
    const auto text = std::string_view{*chain}.substr(2U);
    const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed, 16);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return foundation::fail(foundation::ErrorCode::Unavailable);
    }
    return parsed == expected;
}


[[nodiscard]] foundation::Result<bool> universalSignatureValid(
    std::string_view endpoint, std::string_view address,
    std::span<const std::byte, 32> digest, std::string_view signature,
    std::string_view caFile, const foundation::SecretString& authorization)
{
    auto signatureBytes = decodeHex(signature);
    if (!signatureBytes || signatureBytes->empty() || signatureBytes->size() > 8192U) {
        return foundation::fail(authenticationFailure(
            "The universal signature encoding is invalid."));
    }
    std::string data{kUniversalSignatureValidatorByteCode};
    data.append(24U, '0');
    data.append(address.substr(2U));
    data.append(encodeHex(digest, false));
    data.append(uint256Hex(96U));
    data.append(uint256Hex(signatureBytes->size()));
    data.append(encodeHex(*signatureBytes, false));
    const std::size_t remainder = signatureBytes->size() % 32U;
    if (remainder != 0U) data.append((32U - remainder) * 2U, '0');

    json::object call;
    call["data"] = std::move(data);
    auto result = rpcString(endpoint, "eth_call",
        json::array{std::move(call), "latest"}, caFile, authorization);
    if (!result) return foundation::fail(result.error());
    if (!result->starts_with("0x") || result->size() > 66U) {
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "The universal signature verifier returned malformed data.");
    }
    std::string_view value{*result};
    value.remove_prefix(2U);
    while (value.size() > 1U && value.front() == '0') value.remove_prefix(1U);
    return value == "1";
}

[[nodiscard]] foundation::Result<bool> contractWalletValid(
    std::string_view endpoint, std::string_view address,
    std::span<const std::byte, 32> digest, std::string_view signature,
    std::string_view caFile, const foundation::SecretString& authorization)
{
    // Match the verifier used by Farcaster AuthKit/viem. The deployless
    // ERC-6492 validator handles EOAs, deployed ERC-1271 wallets, and
    // counterfactual smart accounts without persisting any deployment.
    auto universal = universalSignatureValid(
        endpoint, address, digest, signature, caFile, authorization);
    if (universal) return universal.value();

    // Preserve the previous direct paths as a compatibility fallback for RPC
    // providers that do not permit contract-creation eth_call simulations.
    auto code = rpcString(endpoint, "eth_getCode", json::array{address, "latest"}, caFile, authorization);
    if (!code) return foundation::fail(code.error());
    const bool contract = *code != "0x" && *code != "0x0" && *code != "0x00";
    if (!contract) {
        auto recovered = recoverAddress(digest, signature);
        if (!recovered) return foundation::fail(recovered.error());
        return security::constantTimeEquals(*recovered, address);
    }

    auto signatureBytes = decodeHex(signature);
    if (!signatureBytes || signatureBytes->empty() || signatureBytes->size() > 4096U) {
        return foundation::fail(authenticationFailure("The ERC-1271 signature encoding is invalid."));
    }
    auto selector = functionSelector("isValidSignature(bytes32,bytes)");
    if (!selector) return foundation::fail(selector.error());
    std::string data{"0x"};
    data.append(*selector);
    data.append(encodeHex(digest, false));
    data.append(uint256Hex(64U));
    data.append(uint256Hex(signatureBytes->size()));
    data.append(encodeHex(*signatureBytes, false));
    const std::size_t remainder = signatureBytes->size() % 32U;
    if (remainder != 0U) data.append((32U - remainder) * 2U, '0');
    json::object call;
    call["to"] = address;
    call["data"] = std::move(data);
    auto result = rpcString(endpoint, "eth_call", json::array{std::move(call), "latest"}, caFile, authorization);
    if (!result) return foundation::fail(result.error());
    std::string lowered = *result;
    std::ranges::transform(lowered, lowered.begin(), [](unsigned char symbol) {
        return static_cast<char>(std::tolower(symbol));
    });
    return lowered.starts_with(kErc1271Magic);
}

[[nodiscard]] foundation::Result<std::uint64_t> farcasterIdOf(
    std::string_view endpoint, std::string_view registry, std::string_view address,
    std::string_view caFile, const foundation::SecretString& authorization)
{
    auto selector = functionSelector("idOf(address)");
    if (!selector) return foundation::fail(selector.error());
    std::string data{"0x"};
    data.append(*selector);
    data.append(24U, '0');
    data.append(address.substr(2U));
    json::object call;
    call["to"] = registry;
    call["data"] = std::move(data);
    auto result = rpcString(endpoint, "eth_call", json::array{std::move(call), "latest"}, caFile, authorization);
    if (!result || !result->starts_with("0x") || result->size() > 66U) {
        return foundation::fail(result ? foundation::Error{foundation::ErrorCode::Unavailable}
                                       : result.error());
    }
    std::uint64_t value{};
    std::string_view text{*result};
    text.remove_prefix(2U);
    while (text.size() > 16U && text.front() == '0') text.remove_prefix(1U);
    if (text.size() > 16U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The Farcaster FID exceeds the supported 64-bit range.");
    }
    if (text.empty()) return std::uint64_t{0};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return foundation::fail(foundation::ErrorCode::Unavailable);
    }
    return value;
}

[[nodiscard]] foundation::Result<std::uint64_t> abiUint64(
    std::string_view result, std::size_t word)
{
    if (!result.starts_with("0x")) return foundation::fail(foundation::ErrorCode::Unavailable);
    result.remove_prefix(2U);
    const std::size_t begin = word * 64U;
    if (result.size() < begin + 64U) return foundation::fail(foundation::ErrorCode::Unavailable);
    std::string_view text = result.substr(begin, 64U);
    while (text.size() > 16U && text.front() == '0') text.remove_prefix(1U);
    if (text.size() > 16U) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    std::uint64_t value{};
    if (text.empty()) return value;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return foundation::fail(foundation::ErrorCode::Unavailable);
    }
    return value;
}

[[nodiscard]] foundation::Result<bool> farcasterAuthAddressValid(
    std::string_view endpoint, std::string_view registry, std::uint64_t fid,
    std::string_view address, std::string_view caFile,
    const foundation::SecretString& authorization)
{
    auto selector = functionSelector("keyDataOf(uint256,bytes)");
    if (!selector) return foundation::fail(selector.error());
    std::string data{"0x"};
    data.append(*selector);
    data.append(uint256Hex(fid));
    data.append(uint256Hex(64U));
    data.append(uint256Hex(32U));
    data.append(24U, '0');
    data.append(address.substr(2U));
    json::object call;
    call["to"] = registry;
    call["data"] = std::move(data);
    auto result = rpcString(endpoint, "eth_call", json::array{std::move(call), "latest"},
                            caFile, authorization);
    if (!result) return foundation::fail(result.error());
    auto state = abiUint64(*result, 0U);
    auto keyType = abiUint64(*result, 1U);
    if (!state || !keyType) return foundation::fail(state ? keyType.error() : state.error());
    return state.value() == 1U && keyType.value() == kFarcasterAuthAddressKeyType;
}

[[nodiscard]] std::optional<std::string_view> publicParameter(
    const idp::AttributeMap& values, std::string_view name)
{
    const auto found = values.find(name);
    if (found == values.end()) return std::nullopt;
    return found->second;
}

[[nodiscard]] std::optional<std::string_view> credential(
    const idp::SecretAttributeMap& values, std::string_view name)
{
    const auto found = values.find(name);
    if (found == values.end()) return std::nullopt;
    return found->second.expose();
}

[[nodiscard]] foundation::Result<std::uint64_t> parseDecimal(
    std::string_view text, std::uint64_t maximum = UINT64_MAX)
{
    if (text.empty() || text.size() > 20U) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    std::uint64_t value{};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || value > maximum) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    return value;
}

[[nodiscard]] foundation::Result<std::int64_t> challengeTimestamp(
    const idp::ChallengeId& challenge, std::string_view prefix)
{
    std::string_view value = challenge.value();
    if (!value.starts_with(prefix)) return foundation::fail(authenticationFailure("The Web3 challenge identifier is invalid."));
    value.remove_prefix(prefix.size());
    const auto separator = value.find('_');
    if (separator == std::string_view::npos) return foundation::fail(authenticationFailure("The Web3 challenge identifier is invalid."));
    std::int64_t milliseconds{};
    const auto timestamp = value.substr(0U, separator);
    const auto parsed = std::from_chars(timestamp.data(), timestamp.data() + timestamp.size(), milliseconds, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != timestamp.data() + timestamp.size() || milliseconds < 0) {
        return foundation::fail(authenticationFailure("The Web3 challenge timestamp is invalid."));
    }
    return milliseconds;
}

[[nodiscard]] foundation::Result<std::uint64_t> walletChallengeChainId(
    const idp::ChallengeId& challenge)
{
    constexpr std::string_view prefix{"siwe_"};
    std::string_view value = challenge.value();
    if (!value.starts_with(prefix)) {
        return foundation::fail(authenticationFailure("The SIWE challenge identifier is invalid."));
    }
    value.remove_prefix(prefix.size());
    const auto timestampSeparator = value.find('_');
    if (timestampSeparator == std::string_view::npos) {
        return foundation::fail(authenticationFailure("The SIWE challenge identifier is invalid."));
    }
    value.remove_prefix(timestampSeparator + 1U);
    const auto chainSeparator = value.find('_');
    if (chainSeparator == std::string_view::npos) {
        return foundation::fail(authenticationFailure("The SIWE challenge identifier is invalid."));
    }
    std::uint64_t chainId{};
    const auto chainText = value.substr(0U, chainSeparator);
    const auto parsed = std::from_chars(
        chainText.data(), chainText.data() + chainText.size(), chainId, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != chainText.data() + chainText.size()
        || chainId == 0U) {
        return foundation::fail(authenticationFailure("The SIWE challenge chain id is invalid."));
    }
    return chainId;
}

[[nodiscard]] foundation::Result<std::string> challengeNonce(
    const foundation::SecretString& key, const idp::ChallengeId& challenge)
{
    auto digest = security::hmacSha256(key, std::string{"openproof/siwe/nonce/v1:"} + std::string{challenge.value()});
    if (!digest) return foundation::fail(digest.error());
    return encodeHex(std::span{digest->data(), 16U}, false);
}

[[nodiscard]] foundation::Result<idp::ChallengeId> makeChallengeId(
    std::string_view prefix, foundation::Instant now)
{
    auto random = security::randomTokenBase64Url(18U);
    if (!random) return foundation::fail(random.error());
    const auto milliseconds = now.time_since_epoch().count();
    return idp::ChallengeId{std::string{prefix} + std::to_string(milliseconds) + "_" + std::move(random).value()};
}

[[nodiscard]] foundation::Result<idp::ChallengeId> makeWalletChallengeId(
    foundation::Instant now, std::uint64_t chainId)
{
    auto random = security::randomTokenBase64Url(18U);
    if (!random) return foundation::fail(random.error());
    const auto milliseconds = now.time_since_epoch().count();
    return idp::ChallengeId{
        "siwe_" + std::to_string(milliseconds) + "_" + std::to_string(chainId)
        + "_" + std::move(random).value()};
}

[[nodiscard]] std::string buildSiweMessage(
    std::string_view domain, std::string_view address, std::string_view statement,
    std::string_view uri, std::uint64_t chainId, std::string_view nonce,
    foundation::Instant issuedAt, foundation::Instant expiresAt)
{
    std::string output;
    output.reserve(768U);
    output.append(domain);
    output.append(" wants you to sign in with your Ethereum account:\n");
    output.append(address);
    output.append("\n\n");
    output.append(statement);
    output.append("\n\nURI: ");
    output.append(uri);
    output.append("\nVersion: 1\nChain ID: ");
    output.append(std::to_string(chainId));
    output.append("\nNonce: ");
    output.append(nonce);
    output.append("\nIssued At: ");
    output.append(foundation::toIso8601(issuedAt));
    output.append("\nExpiration Time: ");
    output.append(foundation::toIso8601(expiresAt));
    return output;
}

[[nodiscard]] std::string buildFarcasterMessage(
    std::string_view domain, std::string_view address, std::string_view uri,
    std::string_view nonce, foundation::Instant issuedAt,
    foundation::Instant expiresAt, std::uint64_t fid)
{
    std::string output = buildSiweMessage(
        domain, address, kFarcasterStatement, uri, kOptimismMainnetChainId,
        nonce, issuedAt, expiresAt);
    output.append("\nResources:\n- farcaster://fid/");
    output.append(std::to_string(fid));
    return output;
}

struct ParsedSiwe final {
    std::string address;
    std::uint64_t chainId{};
};

[[nodiscard]] foundation::Result<ParsedSiwe> validateSiweMessage(
    std::string_view message, const idp::ChallengeId& challenge,
    std::string_view challengePrefix, std::string_view domain, std::string_view uri,
    std::string_view statement, const foundation::SecretString& derivationKey,
    foundation::Duration lifetime, foundation::Instant now)
{
    if (message.empty() || message.size() > 8192U || message.contains('\r')) {
        return foundation::fail(authenticationFailure("The SIWE message encoding is invalid."));
    }
    std::vector<std::string_view> lines;
    std::size_t begin = 0U;
    while (begin <= message.size()) {
        const auto end = message.find('\n', begin);
        lines.push_back(message.substr(begin, end == std::string_view::npos ? message.size() - begin : end - begin));
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    constexpr std::string_view chainLabel{"Chain ID: "};
    if (lines.size() != 11U
        || lines[0] != std::string{domain} + " wants you to sign in with your Ethereum account:"
        || lines[2] != "" || lines[3] != statement || lines[4] != ""
        || lines[5] != std::string{"URI: "} + std::string{uri}
        || lines[6] != "Version: 1" || !lines[7].starts_with(chainLabel)) {
        return foundation::fail(authenticationFailure("The SIWE message is not bound to this relying party."));
    }
    std::uint64_t chainId{};
    const auto chainText = lines[7].substr(chainLabel.size());
    const auto chainParsed = std::from_chars(
        chainText.data(), chainText.data() + chainText.size(), chainId, 10);
    if (chainParsed.ec != std::errc{} || chainParsed.ptr != chainText.data() + chainText.size()
        || chainId == 0U) {
        return foundation::fail(authenticationFailure("The SIWE chain id is invalid."));
    }
    auto boundChain = walletChallengeChainId(challenge);
    if (!boundChain || boundChain.value() != chainId) {
        return foundation::fail(authenticationFailure("The SIWE chain id is not bound to this challenge."));
    }
    auto address = normalizeAddress(lines[1]);
    if (!address) return foundation::fail(authenticationFailure("The SIWE address is invalid."));
    auto nonce = challengeNonce(derivationKey, challenge);
    auto timestamp = challengeTimestamp(challenge, challengePrefix);
    if (!nonce || !timestamp) return foundation::fail(nonce ? timestamp.error() : nonce.error());
    const foundation::Instant issuedAt{foundation::Duration{timestamp.value()}};
    const foundation::Instant expiresAt = issuedAt + lifetime;
    if (lines[8] != std::string{"Nonce: "} + nonce.value()
        || lines[9] != std::string{"Issued At: "} + foundation::toIso8601(issuedAt)
        || lines[10] != std::string{"Expiration Time: "} + foundation::toIso8601(expiresAt)) {
        return foundation::fail(authenticationFailure("The SIWE challenge binding is invalid."));
    }
    if (now >= expiresAt) {
        return foundation::fail(authenticationFailure("The SIWE time window is expired."));
    }
    return ParsedSiwe{std::move(*address), chainId};
}

[[nodiscard]] std::optional<unsigned int> fixedDecimal(
    std::string_view text, std::size_t begin, std::size_t count)
{
    if (begin + count > text.size()) return std::nullopt;
    unsigned int value{};
    const auto part = text.substr(begin, count);
    const auto parsed = std::from_chars(part.data(), part.data() + part.size(), value, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != part.data() + part.size()) return std::nullopt;
    return value;
}

[[nodiscard]] std::optional<foundation::Instant> parseSiweInstant(std::string_view text)
{
    const bool milliseconds = text.size() == 24U;
    if ((text.size() != 20U && !milliseconds)
        || text[4] != '-' || text[7] != '-' || text[10] != 'T'
        || text[13] != ':' || text[16] != ':' || text.back() != 'Z'
        || (milliseconds && text[19] != '.')) return std::nullopt;
    const auto year = fixedDecimal(text, 0U, 4U);
    const auto month = fixedDecimal(text, 5U, 2U);
    const auto day = fixedDecimal(text, 8U, 2U);
    const auto hour = fixedDecimal(text, 11U, 2U);
    const auto minute = fixedDecimal(text, 14U, 2U);
    const auto second = fixedDecimal(text, 17U, 2U);
    const auto fraction = milliseconds ? fixedDecimal(text, 20U, 3U)
                                       : std::optional<unsigned int>{0U};
    if (!year || !month || !day || !hour || !minute || !second || !fraction
        || *hour > 23U || *minute > 59U || *second > 59U) return std::nullopt;
    const std::chrono::year_month_day date{
        std::chrono::year{static_cast<int>(*year)},
        std::chrono::month{*month}, std::chrono::day{*day}};
    if (!date.ok()) return std::nullopt;
    const auto value = std::chrono::sys_days{date} + std::chrono::hours{*hour}
        + std::chrono::minutes{*minute} + std::chrono::seconds{*second}
        + std::chrono::milliseconds{*fraction};
    return std::chrono::time_point_cast<foundation::Duration>(value);
}

struct ParsedFarcasterSiwe final {
    std::string address;
    std::uint64_t fid{};
};

[[nodiscard]] foundation::Result<ParsedFarcasterSiwe> validateFarcasterMessage(
    std::string_view message, const idp::ChallengeId& challenge,
    std::string_view domain, std::string_view uri,
    const foundation::SecretString& derivationKey, foundation::Duration lifetime,
    foundation::Instant now)
{
    if (message.empty() || message.size() > 8192U || message.contains('\r')) {
        return foundation::fail(authenticationFailure("The SIWF message encoding is invalid."));
    }
    std::vector<std::string_view> lines;
    std::size_t begin = 0U;
    while (begin <= message.size()) {
        const auto end = message.find('\n', begin);
        lines.push_back(message.substr(begin,
            end == std::string_view::npos ? message.size() - begin : end - begin));
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    const bool acceptedStatement = lines.size() > 3U
        && (lines[3] == kFarcasterStatement || lines[3] == "Farcaster Connect");
    if (lines.size() < 13U
        || lines[0] != std::string{domain} + " wants you to sign in with your Ethereum account:"
        || lines[2] != "" || !acceptedStatement || lines[4] != ""
        || lines[5] != std::string{"URI: "} + std::string{uri}
        || lines[6] != "Version: 1" || lines[7] != "Chain ID: 10") {
        return foundation::fail(authenticationFailure(
            "The SIWF message is not a Farcaster FIP-11 message for this relying party."));
    }
    std::optional<std::size_t> resourcesIndex;
    for (std::size_t index = 10U; index < lines.size(); ++index) {
        if (lines[index] == "Resources:") {
            if (resourcesIndex.has_value()) {
                return foundation::fail(authenticationFailure(
                    "The SIWF message contains duplicate resource sections."));
            }
            resourcesIndex = index;
        }
    }
    if (!resourcesIndex || *resourcesIndex + 1U >= lines.size()) {
        return foundation::fail(authenticationFailure(
            "The SIWF message is missing Farcaster resources."));
    }
    auto address = normalizeAddress(lines[1]);
    constexpr std::string_view resourcePrefix{"- farcaster://fid/"};
    constexpr std::string_view legacyResourcePrefix{"- farcaster://fids/"};
    std::optional<std::uint64_t> fid;
    for (std::size_t index = *resourcesIndex + 1U; index < lines.size(); ++index) {
        const auto resource = lines[index];
        const auto prefix = resource.starts_with(resourcePrefix)
            ? resourcePrefix
            : (resource.starts_with(legacyResourcePrefix) ? legacyResourcePrefix
                                                          : std::string_view{});
        if (prefix.empty()) continue;
        std::string_view text = resource.substr(prefix.size());
        if (text.ends_with('/')) text.remove_suffix(1U);
        auto parsedFid = parseDecimal(text);
        if (!parsedFid || parsedFid.value() == 0U || fid.has_value()) {
            return foundation::fail(authenticationFailure("The SIWF Farcaster FID is invalid."));
        }
        fid = parsedFid.value();
    }
    if (!address || !fid.has_value()) {
        return foundation::fail(authenticationFailure("The SIWF signer or FID resource is invalid."));
    }
    auto nonce = challengeNonce(derivationKey, challenge);
    auto timestamp = challengeTimestamp(challenge, "fcsiwf_");
    constexpr std::string_view nonceLabel{"Nonce: "};
    constexpr std::string_view issuedLabel{"Issued At: "};
    constexpr std::string_view expirationLabel{"Expiration Time: "};
    constexpr std::string_view notBeforeLabel{"Not Before: "};
    constexpr std::string_view requestIdLabel{"Request ID: "};
    if (!nonce || !timestamp || !lines[8].starts_with(nonceLabel)
        || lines[8].substr(nonceLabel.size()) != nonce.value()
        || !lines[9].starts_with(issuedLabel)) {
        return foundation::fail(authenticationFailure("The SIWF challenge binding is invalid."));
    }
    std::optional<std::string_view> expirationText;
    for (std::size_t index = 10U; index < *resourcesIndex; ++index) {
        if (lines[index].starts_with(expirationLabel)) {
            if (expirationText.has_value()) {
                return foundation::fail(authenticationFailure(
                    "The SIWF message contains duplicate expiration fields."));
            }
            expirationText = lines[index].substr(expirationLabel.size());
            continue;
        }
        if (lines[index].starts_with(notBeforeLabel)
            || lines[index].starts_with(requestIdLabel)) {
            continue;
        }
        return foundation::fail(authenticationFailure(
            "The SIWF message contains an unsupported optional field."));
    }
    if (!expirationText.has_value()) {
        return foundation::fail(authenticationFailure(
            "The SIWF message is missing its expiration time."));
    }
    const auto issuedAt = parseSiweInstant(lines[9].substr(issuedLabel.size()));
    const auto expiresAt = parseSiweInstant(*expirationText);
    const foundation::Instant challengeStart{foundation::Duration{timestamp.value()}};
    const foundation::Instant challengeEnd = challengeStart + lifetime;
    constexpr auto clockSkew = std::chrono::minutes{1};
    if (!issuedAt || !expiresAt || *issuedAt < challengeStart - clockSkew
        || *issuedAt > now + clockSkew || *expiresAt != challengeEnd
        || *expiresAt <= *issuedAt || now >= challengeEnd) {
        return foundation::fail(authenticationFailure("The SIWF time window is invalid."));
    }
    return ParsedFarcasterSiwe{std::move(*address), *fid};
}

class RpcFarcasterChainVerifier final : public FarcasterChainVerifier {
public:
    explicit RpcFarcasterChainVerifier(const FarcasterProviderConfig& config)
        : m_config(&config) {}

    [[nodiscard]] foundation::Result<bool> chainMatches() override
    {
        return rpcChainMatches(m_config->rpcEndpoint(), m_config->chainId(),
                               m_config->caFile(), m_config->authorizationHeader());
    }

    [[nodiscard]] foundation::Result<bool> verifySignature(
        std::string_view address, std::string_view message,
        std::string_view signature) override
    {
        auto digest = ethereumMessageHash(message);
        if (!digest) return foundation::fail(digest.error());
        return contractWalletValid(m_config->rpcEndpoint(), address, digest.value(), signature,
                                   m_config->caFile(), m_config->authorizationHeader());
    }

    [[nodiscard]] foundation::Result<std::optional<FarcasterSignerKind>>
    authorizeSigner(std::uint64_t fid, std::string_view address) override
    {
        auto custodyFid = farcasterIdOf(m_config->rpcEndpoint(),
            m_config->idRegistryAddress(), address, m_config->caFile(),
            m_config->authorizationHeader());
        if (!custodyFid) return foundation::fail(custodyFid.error());
        if (custodyFid.value() == fid) return FarcasterSignerKind::Custody;
        if (m_config->keyRegistryAddress().empty()) {
            return std::optional<FarcasterSignerKind>{};
        }
        auto valid = farcasterAuthAddressValid(m_config->rpcEndpoint(),
            m_config->keyRegistryAddress(), fid, address, m_config->caFile(),
            m_config->authorizationHeader());
        if (!valid) return foundation::fail(valid.error());
        if (valid.value()) return FarcasterSignerKind::AuthAddress;
        return std::optional<FarcasterSignerKind>{};
    }

private:
    const FarcasterProviderConfig* m_config;
};

} // namespace

WalletProviderConfig::WalletProviderConfig(
    std::string domain, std::string uri,
    std::map<std::uint64_t, std::string> rpcEndpoints,
    foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime, std::string caFile,
    foundation::SecretString authorizationHeader)
    : m_domain(std::move(domain)), m_uri(std::move(uri)),
      m_rpcEndpoints(std::move(rpcEndpoints)), m_derivationKey(std::move(derivationKey)),
      m_challengeLifetime(challengeLifetime), m_caFile(std::move(caFile)),
      m_authorizationHeader(std::move(authorizationHeader)) {}

foundation::Result<WalletProviderConfig> WalletProviderConfig::create(
    std::string domain, std::string uri,
    std::map<std::uint64_t, std::string> rpcEndpoints,
    foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime, std::string caFile,
    foundation::SecretString authorizationHeader)
{
    if (!validDomain(domain) || !parseHttpsUrl(uri)
        || derivationKey.expose().size() < 32U
        || challengeLifetime < std::chrono::seconds{30}
        || challengeLifetime > std::chrono::minutes{15}) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The Ethereum wallet provider configuration is invalid.");
    }
    for (const auto& [chainId, endpoint] : rpcEndpoints) {
        if (chainId == 0U || !parseHttpsUrl(endpoint)) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "An Ethereum smart-wallet RPC mapping is invalid.");
        }
    }
    return WalletProviderConfig{std::move(domain), std::move(uri),
        std::move(rpcEndpoints), std::move(derivationKey), challengeLifetime,
        std::move(caFile), std::move(authorizationHeader)};
}

foundation::Result<WalletProviderConfig> WalletProviderConfig::create(
    std::string domain, std::string uri, std::uint64_t chainId,
    std::string rpcEndpoint, foundation::SecretString derivationKey,
    foundation::Duration challengeLifetime, std::string caFile,
    foundation::SecretString authorizationHeader)
{
    if (chainId == 0U || rpcEndpoint.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The Ethereum wallet RPC configuration is invalid.");
    }
    std::map<std::uint64_t, std::string> endpoints;
    endpoints.emplace(chainId, std::move(rpcEndpoint));
    return create(std::move(domain), std::move(uri), std::move(endpoints),
                  std::move(derivationKey), challengeLifetime,
                  std::move(caFile), std::move(authorizationHeader));
}

std::string_view WalletProviderConfig::domain() const noexcept { return m_domain; }
std::string_view WalletProviderConfig::uri() const noexcept { return m_uri; }
std::optional<std::string_view> WalletProviderConfig::rpcEndpoint(
    std::uint64_t chainId) const noexcept
{
    const auto found = m_rpcEndpoints.find(chainId);
    if (found == m_rpcEndpoints.end()) return std::nullopt;
    return found->second;
}
const foundation::SecretString& WalletProviderConfig::derivationKey() const noexcept { return m_derivationKey; }
foundation::Duration WalletProviderConfig::challengeLifetime() const noexcept { return m_challengeLifetime; }
std::string_view WalletProviderConfig::caFile() const noexcept { return m_caFile; }
const foundation::SecretString& WalletProviderConfig::authorizationHeader() const noexcept { return m_authorizationHeader; }

class WalletAuthenticationProvider::Implementation final {
public:
    Implementation(WalletProviderConfig value, const foundation::ClockSource& source)
        : config(std::move(value)), clock(&source) {}
    WalletProviderConfig config;
    const foundation::ClockSource* clock;
};

WalletAuthenticationProvider::WalletAuthenticationProvider(
    WalletProviderConfig config, const foundation::ClockSource& clock)
    : m_implementation(std::make_unique<Implementation>(std::move(config), clock)) {}
WalletAuthenticationProvider::~WalletAuthenticationProvider() = default;
idp::ProviderId WalletAuthenticationProvider::id() const { return idp::ProviderId{"ethereum-wallet"}; }
idp::InteractionModel WalletAuthenticationProvider::interactionModel() const noexcept { return idp::InteractionModel::ChallengeResponse; }
idp::AssuranceLevel WalletAuthenticationProvider::maximumClaimableAssurance() const noexcept { return idp::AssuranceLevel::Ial1; }

foundation::Result<idp::AuthenticationChallenge>
WalletAuthenticationProvider::beginAuthentication(const idp::AuthenticationRequest& request)
{
    if (request.provider() != id()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    const auto addressValue = publicParameter(request.parameters(), "address");
    const auto chainValue = publicParameter(request.parameters(), "chain_id");
    auto address = addressValue ? normalizeAddress(*addressValue) : std::nullopt;
    if (!address || !chainValue) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Wallet authentication requires a valid Ethereum address and chain id.");
    }
    auto chainId = parseDecimal(*chainValue);
    if (!chainId || chainId.value() == 0U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Wallet authentication requires a valid Ethereum address and chain id.");
    }
    const auto now = m_implementation->clock->now();
    auto challengeId = makeWalletChallengeId(now, chainId.value());
    if (!challengeId) return foundation::fail(challengeId.error());
    auto nonce = challengeNonce(m_implementation->config.derivationKey(), challengeId.value());
    if (!nonce) return foundation::fail(nonce.error());
    idp::AuthenticationChallenge challenge{challengeId.value(), now + m_implementation->config.challengeLifetime()};
    challenge.setParameter("message", buildSiweMessage(
        m_implementation->config.domain(), *address, kWalletStatement,
        m_implementation->config.uri(), chainId.value(), nonce.value(),
        now, now + m_implementation->config.challengeLifetime()));
    challenge.setParameter("address", *address);
    challenge.setParameter("chain_id", std::to_string(chainId.value()));
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome>
WalletAuthenticationProvider::completeAuthentication(const idp::AuthenticationResponse& response)
{
    const auto message = credential(response.parameters(), "message");
    const auto signature = credential(response.parameters(), "signature");
    if (!message || !signature || signature->size() > 8192U) {
        return foundation::fail(authenticationFailure("The SIWE completion is incomplete."));
    }
    auto parsed = validateSiweMessage(*message, response.challengeId(), "siwe_",
        m_implementation->config.domain(), m_implementation->config.uri(),
        kWalletStatement, m_implementation->config.derivationKey(),
        m_implementation->config.challengeLifetime(), m_implementation->clock->now());
    if (!parsed) return foundation::fail(parsed.error());
    auto digest = ethereumMessageHash(*message);
    if (!digest) return foundation::fail(digest.error());

    bool verified = false;
    auto recovered = recoverAddress(digest.value(), *signature);
    if (recovered && security::constantTimeEquals(*recovered, parsed->address)) {
        verified = true;
    } else if (const auto endpoint = m_implementation->config.rpcEndpoint(parsed->chainId)) {
        auto matchingChain = rpcChainMatches(
            *endpoint, parsed->chainId, m_implementation->config.caFile(),
            m_implementation->config.authorizationHeader());
        if (!matchingChain) return foundation::fail(matchingChain.error());
        if (!matchingChain.value()) {
            return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                    "The configured smart-wallet RPC reports the wrong chain.");
        }
        auto valid = contractWalletValid(
            *endpoint, parsed->address, digest.value(), *signature,
            m_implementation->config.caFile(),
            m_implementation->config.authorizationHeader());
        if (!valid) return foundation::fail(valid.error());
        verified = valid.value();
    }
    if (!verified) {
        return foundation::fail(authenticationFailure(
            "The SIWE signature is invalid, or this smart-account chain has no configured RPC."));
    }

    idp::VerifiedClaims claims;
    claims.setExtension("wallet_address", parsed->address);
    claims.setExtension("chain_id", std::to_string(parsed->chainId));
    idp::ProviderEvidence evidence;
    evidence.add("protocol", "erc4361_siwe");
    evidence.add("chain_id", std::to_string(parsed->chainId));
    evidence.add("wallet_address", parsed->address);
    return idp::AuthenticationOutcome::create(
        id(), idp::ExternalSubject{parsed->address}, std::move(claims), idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, false},
        std::move(evidence), m_implementation->clock->now());
}

FarcasterProviderConfig::FarcasterProviderConfig(
    std::string domain, std::string uri, std::uint64_t optimismChainId,
    std::string optimismRpcEndpoint, std::string idRegistryAddress,
    foundation::SecretString derivationKey, foundation::Duration challengeLifetime,
    std::string caFile, foundation::SecretString authorizationHeader,
    std::string keyRegistryAddress)
    : m_domain(std::move(domain)), m_uri(std::move(uri)), m_chainId(optimismChainId),
      m_rpcEndpoint(std::move(optimismRpcEndpoint)), m_idRegistryAddress(std::move(idRegistryAddress)),
      m_keyRegistryAddress(std::move(keyRegistryAddress)),
      m_derivationKey(std::move(derivationKey)), m_challengeLifetime(challengeLifetime),
      m_caFile(std::move(caFile)), m_authorizationHeader(std::move(authorizationHeader)) {}

foundation::Result<FarcasterProviderConfig> FarcasterProviderConfig::create(
    std::string domain, std::string uri, std::uint64_t optimismChainId,
    std::string optimismRpcEndpoint, std::string idRegistryAddress,
    foundation::SecretString derivationKey, foundation::Duration challengeLifetime,
    std::string caFile, foundation::SecretString authorizationHeader,
    std::string keyRegistryAddress)
{
    auto registry = normalizeAddress(idRegistryAddress);
    auto keyRegistry = keyRegistryAddress.empty()
        ? std::optional<std::string>{std::string{}}
        : normalizeAddress(keyRegistryAddress);
    if (!validDomain(domain) || !parseHttpsUrl(uri) || !parseHttpsUrl(optimismRpcEndpoint)
        || !registry || !keyRegistry || optimismChainId != kOptimismMainnetChainId
        || derivationKey.expose().size() < 32U
        || challengeLifetime < std::chrono::seconds{30}
        || challengeLifetime > std::chrono::minutes{15}) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The Farcaster provider configuration is invalid.");
    }
    return FarcasterProviderConfig{std::move(domain), std::move(uri), optimismChainId,
        std::move(optimismRpcEndpoint), std::move(*registry), std::move(derivationKey),
        challengeLifetime, std::move(caFile), std::move(authorizationHeader),
        std::move(*keyRegistry)};
}

std::string_view FarcasterProviderConfig::domain() const noexcept { return m_domain; }
std::string_view FarcasterProviderConfig::uri() const noexcept { return m_uri; }
std::uint64_t FarcasterProviderConfig::chainId() const noexcept { return m_chainId; }
std::string_view FarcasterProviderConfig::rpcEndpoint() const noexcept { return m_rpcEndpoint; }
std::string_view FarcasterProviderConfig::idRegistryAddress() const noexcept { return m_idRegistryAddress; }
std::string_view FarcasterProviderConfig::keyRegistryAddress() const noexcept { return m_keyRegistryAddress; }
const foundation::SecretString& FarcasterProviderConfig::derivationKey() const noexcept { return m_derivationKey; }
foundation::Duration FarcasterProviderConfig::challengeLifetime() const noexcept { return m_challengeLifetime; }
std::string_view FarcasterProviderConfig::caFile() const noexcept { return m_caFile; }
const foundation::SecretString& FarcasterProviderConfig::authorizationHeader() const noexcept { return m_authorizationHeader; }

class FarcasterAuthenticationProvider::Implementation final {
public:
    Implementation(FarcasterProviderConfig value, const foundation::ClockSource& source,
                   std::unique_ptr<FarcasterChainVerifier> injected)
        : config(std::move(value)), clock(&source),
          verifier(injected ? std::move(injected)
                            : std::make_unique<RpcFarcasterChainVerifier>(config)) {}
    FarcasterProviderConfig config;
    const foundation::ClockSource* clock;
    std::unique_ptr<FarcasterChainVerifier> verifier;
};

FarcasterAuthenticationProvider::FarcasterAuthenticationProvider(
    FarcasterProviderConfig config, const foundation::ClockSource& clock,
    std::unique_ptr<FarcasterChainVerifier> verifier)
    : m_implementation(std::make_unique<Implementation>(
          std::move(config), clock, std::move(verifier))) {}
FarcasterAuthenticationProvider::~FarcasterAuthenticationProvider() = default;
idp::ProviderId FarcasterAuthenticationProvider::id() const { return idp::ProviderId{"farcaster"}; }
idp::InteractionModel FarcasterAuthenticationProvider::interactionModel() const noexcept { return idp::InteractionModel::ChallengeResponse; }
idp::AssuranceLevel FarcasterAuthenticationProvider::maximumClaimableAssurance() const noexcept { return idp::AssuranceLevel::Ial1; }

foundation::Result<idp::AuthenticationChallenge>
FarcasterAuthenticationProvider::beginAuthentication(const idp::AuthenticationRequest& request)
{
    if (request.provider() != id()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    const auto addressValue = publicParameter(request.parameters(), "address");
    const auto fidValue = publicParameter(request.parameters(), "fid");
    if (addressValue.has_value() != fidValue.has_value()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A direct SIWF request must provide both address and FID.");
    }
    auto chain = m_implementation->verifier->chainMatches();
    if (!chain || !chain.value()) return foundation::fail(chain ? foundation::Error{foundation::ErrorCode::FailedPrecondition}
                                                            : chain.error());
    std::optional<std::string> address;
    std::optional<std::uint64_t> fid;
    std::optional<FarcasterSignerKind> signerKind;
    if (addressValue && fidValue) {
        address = normalizeAddress(*addressValue);
        auto parsedFid = parseDecimal(*fidValue);
        if (!address || !parsedFid || parsedFid.value() == 0U) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The direct SIWF address or FID is invalid.");
        }
        fid = parsedFid.value();
        auto authorized = m_implementation->verifier->authorizeSigner(*fid, *address);
        if (!authorized || !authorized.value()) {
            return foundation::fail(authorized
                ? authenticationFailure("The address is not an active custody or auth address for that FID.")
                : authorized.error());
        }
        signerKind = *authorized.value();
    }
    const auto now = m_implementation->clock->now();
    auto challengeId = makeChallengeId("fcsiwf_", now);
    if (!challengeId) return foundation::fail(challengeId.error());
    auto nonce = challengeNonce(m_implementation->config.derivationKey(), challengeId.value());
    if (!nonce) return foundation::fail(nonce.error());
    idp::AuthenticationChallenge challenge{challengeId.value(), now + m_implementation->config.challengeLifetime()};
    challenge.setParameter("nonce", nonce.value());
    challenge.setParameter("domain", std::string{m_implementation->config.domain()});
    challenge.setParameter("uri", std::string{m_implementation->config.uri()});
    challenge.setParameter("statement", std::string{kFarcasterStatement});
    challenge.setParameter("resource_prefix", "farcaster://fid/");
    challenge.setParameter("chain_id", std::to_string(m_implementation->config.chainId()));
    if (address && fid && signerKind) {
        challenge.setParameter("message", buildFarcasterMessage(
            m_implementation->config.domain(), *address, m_implementation->config.uri(),
            nonce.value(), now, now + m_implementation->config.challengeLifetime(), *fid));
        challenge.setParameter("address", *address);
        challenge.setParameter("fid", std::to_string(*fid));
        challenge.setParameter("signer_kind",
            *signerKind == FarcasterSignerKind::Custody ? "custody" : "auth_address");
    }
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome>
FarcasterAuthenticationProvider::completeAuthentication(const idp::AuthenticationResponse& response)
{
    const auto message = credential(response.parameters(), "message");
    const auto signature = credential(response.parameters(), "signature");
    if (!message || !signature || signature->size() > 8192U) {
        return foundation::fail(authenticationFailure("The Farcaster SIWF completion is incomplete."));
    }
    auto parsed = validateFarcasterMessage(*message, response.challengeId(),
        m_implementation->config.domain(), m_implementation->config.uri(),
        m_implementation->config.derivationKey(), m_implementation->config.challengeLifetime(),
        m_implementation->clock->now());
    if (!parsed) return foundation::fail(parsed.error());
    auto signatureValid = m_implementation->verifier->verifySignature(
        parsed->address, *message, *signature);
    if (!signatureValid || !signatureValid.value()) {
        return foundation::fail(signatureValid ? authenticationFailure("The Farcaster SIWF signature is invalid.")
                                               : signatureValid.error());
    }
    auto authorized = m_implementation->verifier->authorizeSigner(parsed->fid, parsed->address);
    if (!authorized || !authorized.value()) {
        return foundation::fail(authorized
            ? authenticationFailure("The Farcaster signer was revoked or changed before verification completed.")
            : authorized.error());
    }
    const bool custody = *authorized.value() == FarcasterSignerKind::Custody;
    idp::VerifiedClaims claims;
    claims.setExtension("fid", std::to_string(parsed->fid));
    claims.setExtension("signer_address", parsed->address);
    claims.setExtension("signer_kind", custody ? "custody" : "auth_address");
    if (custody) claims.setExtension("custody_address", parsed->address);
    claims.setExtension("chain_id", std::to_string(m_implementation->config.chainId()));
    idp::ProviderEvidence evidence;
    evidence.add("protocol", "farcaster_fip11_siwf");
    evidence.add("fid", std::to_string(parsed->fid));
    evidence.add("signer_address", parsed->address);
    evidence.add("signer_kind", custody ? "custody" : "auth_address");
    evidence.add("id_registry", std::string{m_implementation->config.idRegistryAddress()});
    if (!m_implementation->config.keyRegistryAddress().empty()) {
        evidence.add("key_registry", std::string{m_implementation->config.keyRegistryAddress()});
    }
    return idp::AuthenticationOutcome::create(
        id(), idp::ExternalSubject{std::to_string(parsed->fid)}, std::move(claims),
        idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Possession, false},
        std::move(evidence), m_implementation->clock->now());
}

} // namespace openproof::provider::web3
