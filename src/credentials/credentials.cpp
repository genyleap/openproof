module;

#include <optional>
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>

module openproof.credentials;

namespace openproof::credentials {
namespace {

constexpr std::string_view kPasswordPrefix = "scrypt$v1$";
constexpr std::size_t kMinimumPepperBytes = 32U;
constexpr std::size_t kMinimumPasswordBytes = 8U;
constexpr std::size_t kMaximumPasswordBytes = 1024U;
constexpr std::uint64_t kMaximumScryptCost = 1U << 20U;
constexpr std::uint64_t kMaximumScryptBlockSize = 32U;
constexpr std::uint64_t kMaximumScryptParallelism = 16U;
constexpr std::uint64_t kMaximumScryptMemoryBytes = 256U * 1024U * 1024U;
constexpr std::string_view kBase32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

[[nodiscard]] foundation::Error authenticationFailure(std::string detail)
{
    return foundation::Error{
        foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(
            foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

[[nodiscard]] bool isPowerOfTwo(std::uint64_t value) noexcept
{
    return value > 1U && (value & (value - 1U)) == 0U;
}

[[nodiscard]] foundation::Result<std::uint64_t> parseUnsigned(std::string_view value)
{
    std::uint64_t parsed = 0U;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The password hash is malformed.");
    }
    return parsed;
}

[[nodiscard]] std::vector<std::string_view> split(std::string_view value, char delimiter)
{
    std::vector<std::string_view> fields;
    std::size_t begin = 0U;
    while (begin <= value.size()) {
        const std::size_t end = value.find(delimiter, begin);
        fields.push_back(value.substr(begin, end == std::string_view::npos
                                                ? value.size() - begin
                                                : end - begin));
        if (end == std::string_view::npos) {
            break;
        }
        begin = end + 1U;
    }
    return fields;
}

[[nodiscard]] foundation::Result<std::vector<std::byte>> derive(
    const foundation::SecretString& pepper, const foundation::SecretString& password,
    std::span<const std::byte> salt, const PasswordPolicy& policy)
{
    if (password.expose().size() < kMinimumPasswordBytes
        || password.expose().size() > kMaximumPasswordBytes) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The password length is outside the accepted range.");
    }

    foundation::Result<security::Sha256Digest> prehash =
        security::hmacSha256(pepper, password.expose());
    if (!prehash.has_value()) {
        return foundation::fail(prehash.error());
    }

    const security::Sha256Digest material = prehash.value();
    std::vector<std::byte> output(policy.derivedBytes());
    const int result = EVP_PBE_scrypt(
        reinterpret_cast<const char*>(material.data()), material.size(),
        reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
        policy.cost(), policy.blockSize(), policy.parallelism(),
        policy.maximumMemoryBytes(),
        reinterpret_cast<unsigned char*>(output.data()), output.size());
    if (result != 1) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "Password derivation failed.");
    }
    return output;
}

[[nodiscard]] std::string base32(std::string_view bytes)
{
    std::string output;
    output.reserve(((bytes.size() * 8U) + 4U) / 5U);
    std::uint32_t accumulator = 0U;
    unsigned int bits = 0U;
    for (const char symbol : bytes) {
        const auto byte = static_cast<unsigned char>(symbol);
        accumulator = (accumulator << 8U) | byte;
        bits += 8U;
        while (bits >= 5U) {
            bits -= 5U;
            output.push_back(kBase32Alphabet[(accumulator >> bits) & 0x1FU]);
        }
    }
    if (bits > 0U) {
        output.push_back(kBase32Alphabet[(accumulator << (5U - bits)) & 0x1FU]);
    }
    return output;
}

[[nodiscard]] foundation::Result<std::string>
hotp(const TotpSecret& secret, std::uint64_t counter, unsigned int digits)
{
    std::array<unsigned char, 8> message{};
    for (std::size_t index = 0U; index < message.size(); ++index) {
        message[message.size() - 1U - index] =
            static_cast<unsigned char>((counter >> (index * 8U)) & 0xFFU);
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> mac{};
    unsigned int length = 0U;
    const std::string_view key = secret.bytes().expose();
    if (key.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The TOTP secret is too large.");
    }
    const unsigned char* result = HMAC(
        EVP_sha1(), key.data(), static_cast<int>(key.size()), message.data(), message.size(),
        mac.data(), &length);
    if (result == nullptr || length < 20U) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "TOTP generation failed.");
    }
    const std::size_t offset = mac[length - 1U] & 0x0FU;
    if (offset + 4U > length) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "TOTP generation produced an invalid MAC.");
    }
    const std::uint32_t binary =
        (static_cast<std::uint32_t>(mac[offset] & 0x7FU) << 24U)
        | (static_cast<std::uint32_t>(mac[offset + 1U]) << 16U)
        | (static_cast<std::uint32_t>(mac[offset + 2U]) << 8U)
        | static_cast<std::uint32_t>(mac[offset + 3U]);
    std::uint32_t modulus = 1U;
    for (unsigned int index = 0U; index < digits; ++index) {
        modulus *= 10U;
    }
    return std::format("{:0{}}", binary % modulus, digits);
}

[[nodiscard]] foundation::Result<std::uint64_t>
timeStep(foundation::Instant now, foundation::Duration step)
{
    const auto epochMilliseconds = now.time_since_epoch().count();
    if (epochMilliseconds < 0 || step.count() <= 0) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "TOTP time is outside the supported range.");
    }
    return static_cast<std::uint64_t>(epochMilliseconds / step.count());
}

}

PasswordPolicy::PasswordPolicy(std::uint64_t cost, std::uint64_t blockSize,
                               std::uint64_t parallelism, std::size_t saltBytes,
                               std::size_t derivedBytes,
                               std::uint64_t maximumMemoryBytes) noexcept
    : m_cost(cost), m_blockSize(blockSize), m_parallelism(parallelism),
      m_saltBytes(saltBytes), m_derivedBytes(derivedBytes),
      m_maximumMemoryBytes(maximumMemoryBytes)
{
}

foundation::Result<PasswordPolicy> PasswordPolicy::create(
    std::uint64_t cost, std::uint64_t blockSize, std::uint64_t parallelism,
    std::size_t saltBytes, std::size_t derivedBytes,
    std::uint64_t maximumMemoryBytes)
{
    if (!isPowerOfTwo(cost) || cost > kMaximumScryptCost
        || blockSize == 0U || blockSize > kMaximumScryptBlockSize
        || parallelism == 0U || parallelism > kMaximumScryptParallelism
        || saltBytes < 16U || derivedBytes < 32U || derivedBytes > 64U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The password policy is outside secure bounds.");
    }
    if (blockSize > std::numeric_limits<std::uint64_t>::max() / cost / 128U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The password policy memory cost overflows.");
    }
    const std::uint64_t required = 128U * cost * blockSize;
    if (maximumMemoryBytes < required
        || maximumMemoryBytes > kMaximumScryptMemoryBytes) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The password memory ceiling is below its work factor.");
    }
    return PasswordPolicy{cost, blockSize, parallelism, saltBytes,
                          derivedBytes, maximumMemoryBytes};
}

PasswordPolicy PasswordPolicy::recommended() noexcept
{
    return PasswordPolicy{32768U, 8U, 1U, 16U, 32U, 64U * 1024U * 1024U};
}

std::uint64_t PasswordPolicy::cost() const noexcept { return m_cost; }
std::uint64_t PasswordPolicy::blockSize() const noexcept { return m_blockSize; }
std::uint64_t PasswordPolicy::parallelism() const noexcept { return m_parallelism; }
std::size_t PasswordPolicy::saltBytes() const noexcept { return m_saltBytes; }
std::size_t PasswordPolicy::derivedBytes() const noexcept { return m_derivedBytes; }
std::uint64_t PasswordPolicy::maximumMemoryBytes() const noexcept { return m_maximumMemoryBytes; }

PasswordHash::PasswordHash(std::string encoded) : m_encoded(std::move(encoded)) {}

foundation::Result<PasswordHash> PasswordHash::parse(std::string encoded)
{
    const auto fields = split(encoded, '$');
    if (fields.size() != 8U || fields[0] != "scrypt" || fields[1] != "v1"
        || fields[2].empty() || fields[3].empty() || fields[4].empty()
        || fields[5].empty() || fields[6].empty() || fields[7].empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The password hash is malformed.");
    }
    return PasswordHash{std::move(encoded)};
}

std::string_view PasswordHash::encoded() const noexcept { return m_encoded; }

PasswordHasher::PasswordHasher(foundation::SecretString pepper, PasswordPolicy policy)
    : m_pepper(std::move(pepper)), m_policy(policy)
{
}

foundation::Result<PasswordHasher>
PasswordHasher::create(foundation::SecretString pepper, PasswordPolicy policy)
{
    if (pepper.expose().size() < kMinimumPepperBytes) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A password pepper must contain at least 32 bytes.");
    }
    return PasswordHasher{std::move(pepper), policy};
}

foundation::Result<PasswordHash>
PasswordHasher::hash(const foundation::SecretString& password) const
{
    foundation::Result<std::vector<std::byte>> salt = security::randomBytes(m_policy.saltBytes());
    if (!salt.has_value()) {
        return foundation::fail(salt.error());
    }
    foundation::Result<std::vector<std::byte>> result =
        derive(m_pepper, password, salt.value(), m_policy);
    if (!result.has_value()) {
        return foundation::fail(result.error());
    }
    const std::string encoded = std::format(
        "{}{}${}${}${}${}${}", kPasswordPrefix, m_policy.cost(),
        m_policy.blockSize(), m_policy.parallelism(), m_policy.maximumMemoryBytes(),
        foundation::toBase64Url(salt.value()), foundation::toBase64Url(result.value()));
    return PasswordHash{encoded};
}

foundation::Result<bool> PasswordHasher::verify(
    const foundation::SecretString& password, const PasswordHash& expected) const
{
    const auto fields = split(expected.encoded(), '$');
    if (fields.size() != 8U || fields[0] != "scrypt" || fields[1] != "v1") {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The password hash is malformed.");
    }
    const auto cost = parseUnsigned(fields[2]);
    const auto blockSize = parseUnsigned(fields[3]);
    const auto parallelism = parseUnsigned(fields[4]);
    const auto maximumMemory = parseUnsigned(fields[5]);
    const auto salt = foundation::fromBase64Url(fields[6]);
    const auto wanted = foundation::fromBase64Url(fields[7]);
    if (!cost.has_value() || !blockSize.has_value() || !parallelism.has_value()
        || !maximumMemory.has_value() || !salt.has_value() || !wanted.has_value()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The password hash is malformed.");
    }
    const auto policy = PasswordPolicy::create(
        cost.value(), blockSize.value(), parallelism.value(), salt.value().size(),
        wanted.value().size(), maximumMemory.value());
    if (!policy.has_value()) {
        return foundation::fail(policy.error());
    }
    const auto actual = derive(m_pepper, password, salt.value(), policy.value());
    if (!actual.has_value()) {
        return foundation::fail(actual.error());
    }
    return security::constantTimeEquals(actual.value(), wanted.value());
}

TotpPolicy::TotpPolicy(foundation::Duration step, unsigned int digits,
                       unsigned int pastWindow, unsigned int futureWindow) noexcept
    : m_step(step), m_digits(digits), m_pastWindow(pastWindow), m_futureWindow(futureWindow)
{
}

foundation::Result<TotpPolicy> TotpPolicy::create(
    foundation::Duration step, unsigned int digits,
    unsigned int pastWindow, unsigned int futureWindow)
{
    if (step < std::chrono::seconds{15} || step > std::chrono::minutes{5}
        || (digits != 6U && digits != 8U) || pastWindow > 10U || futureWindow > 10U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The TOTP policy is outside secure bounds.");
    }
    return TotpPolicy{step, digits, pastWindow, futureWindow};
}

TotpPolicy TotpPolicy::recommended() noexcept
{
    return TotpPolicy{std::chrono::seconds{30}, 6U, 1U, 1U};
}

foundation::Duration TotpPolicy::step() const noexcept { return m_step; }
unsigned int TotpPolicy::digits() const noexcept { return m_digits; }
unsigned int TotpPolicy::pastWindow() const noexcept { return m_pastWindow; }
unsigned int TotpPolicy::futureWindow() const noexcept { return m_futureWindow; }

TotpSecret::TotpSecret(foundation::SecretString bytes) : m_bytes(std::move(bytes)) {}

foundation::Result<TotpSecret> TotpSecret::create(foundation::SecretString bytes)
{
    if (bytes.expose().size() < 20U || bytes.expose().size() > 64U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A TOTP secret must contain between 20 and 64 bytes.");
    }
    return TotpSecret{std::move(bytes)};
}

foundation::Result<TotpSecret> TotpSecret::generate(std::size_t byteCount)
{
    if (byteCount < 20U || byteCount > 64U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A TOTP secret must contain between 20 and 64 bytes.");
    }
    auto bytes = security::randomBytes(byteCount);
    if (!bytes.has_value()) {
        return foundation::fail(bytes.error());
    }
    std::string raw;
    raw.resize(bytes.value().size());
    std::ranges::transform(bytes.value(), raw.begin(),
                           [](std::byte value) {
                               return static_cast<char>(std::to_integer<unsigned char>(value));
                           });
    return TotpSecret{foundation::SecretString{std::move(raw)}};
}

const foundation::SecretString& TotpSecret::bytes() const noexcept { return m_bytes; }

foundation::SecretString TotpSecret::enrollmentBase32() const
{
    return foundation::SecretString{base32(m_bytes.expose())};
}

foundation::Result<std::string>
totpAt(const TotpSecret& secret, const TotpPolicy& policy, foundation::Instant now)
{
    auto step = timeStep(now, policy.step());
    if (!step.has_value()) {
        return foundation::fail(step.error());
    }
    return hotp(secret, step.value(), policy.digits());
}

foundation::Result<std::uint64_t> verifyTotp(
    const TotpSecret& secret, const TotpPolicy& policy,
    std::string_view presented, foundation::Instant now,
    std::optional<std::uint64_t> lastAcceptedStep)
{
    if (presented.size() != policy.digits()
        || !std::ranges::all_of(presented, [](char value) { return value >= '0' && value <= '9'; })) {
        return foundation::fail(authenticationFailure("TOTP response is malformed."));
    }
    auto current = timeStep(now, policy.step());
    if (!current.has_value()) {
        return foundation::fail(current.error());
    }
    const std::uint64_t first = current.value() >= policy.pastWindow()
                                    ? current.value() - policy.pastWindow() : 0U;
    const std::uint64_t last = current.value() + policy.futureWindow();
    for (std::uint64_t candidate = first; candidate <= last; ++candidate) {
        auto expected = hotp(secret, candidate, policy.digits());
        if (!expected.has_value()) {
            return foundation::fail(expected.error());
        }
        if (security::constantTimeEquals(expected.value(), presented)) {
            if (lastAcceptedStep.has_value() && candidate <= lastAcceptedStep.value()) {
                return foundation::fail(authenticationFailure("TOTP response was replayed."));
            }
            return candidate;
        }
    }
    return foundation::fail(authenticationFailure("TOTP response did not verify."));
}

RecoveryCodeBatch::RecoveryCodeBatch(std::vector<foundation::SecretString> codes)
    : m_codes(std::move(codes))
{
}

const std::vector<foundation::SecretString>& RecoveryCodeBatch::codes() const noexcept
{
    return m_codes;
}

foundation::Status InMemoryRecoveryCodeRepository::replace(
    const identity::core::IdentityId& identity,
    std::vector<RecoveryCodeDigest> digests)
{
    if (identity.empty() || digests.size() > 64U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The recovery-code replacement is invalid.");
    }
    std::ranges::sort(digests);
    if (std::ranges::adjacent_find(digests) != digests.end()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Recovery-code digests must be unique.");
    }
    const std::lock_guard<std::mutex> guard{m_mutex};
    if (digests.empty()) {
        m_codes.erase(identity);
    } else {
        m_codes.insert_or_assign(identity, std::move(digests));
    }
    return foundation::ok();
}

foundation::Status InMemoryRecoveryCodeRepository::consume(
    const identity::core::IdentityId& identity, const RecoveryCodeDigest& digest)
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto found = m_codes.find(identity);
    if (found == m_codes.end()) {
        return foundation::fail(authenticationFailure("No recovery-code set exists."));
    }
    const auto matching = std::ranges::find_if(found->second, [&digest](const auto& candidate) {
        return security::constantTimeEquals(candidate, digest);
    });
    if (matching == found->second.end()) {
        return foundation::fail(authenticationFailure("Recovery code did not verify."));
    }
    found->second.erase(matching);
    return foundation::ok();
}

foundation::Result<std::size_t> InMemoryRecoveryCodeRepository::remaining(
    const identity::core::IdentityId& identity) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    const auto found = m_codes.find(identity);
    return found == m_codes.end() ? 0U : found->second.size();
}

RecoveryCodeService::RecoveryCodeService(RecoveryCodeRepository& repository,
                                         foundation::SecretString pepper)
    : m_repository(&repository), m_pepper(std::move(pepper))
{
}

foundation::Result<RecoveryCodeService> RecoveryCodeService::create(
    RecoveryCodeRepository& repository, foundation::SecretString pepper)
{
    if (pepper.expose().size() < kMinimumPepperBytes) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "A recovery-code pepper must contain at least 32 bytes.");
    }
    return RecoveryCodeService{repository, std::move(pepper)};
}

foundation::Result<RecoveryCodeDigest> RecoveryCodeService::digest(
    const foundation::SecretString& code) const
{
    return security::hmacSha256(m_pepper, code.expose());
}

foundation::Result<RecoveryCodeBatch> RecoveryCodeService::issue(
    const identity::core::IdentityId& identity, std::size_t count)
{
    if (identity.empty() || count == 0U || count > 32U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Recovery-code issuance parameters are invalid.");
    }
    std::vector<foundation::SecretString> codes;
    std::vector<RecoveryCodeDigest> digests;
    codes.reserve(count);
    digests.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        auto generated = security::randomTokenBase64Url(20U);
        if (!generated.has_value()) {
            return foundation::fail(generated.error());
        }
        foundation::SecretString code{std::move(generated).value()};
        auto fingerprint = digest(code);
        if (!fingerprint.has_value()) {
            return foundation::fail(fingerprint.error());
        }
        digests.push_back(fingerprint.value());
        codes.push_back(std::move(code));
    }
    const foundation::Status stored = m_repository->replace(identity, std::move(digests));
    if (!stored.has_value()) {
        return foundation::fail(stored.error());
    }
    return RecoveryCodeBatch{std::move(codes)};
}

foundation::Status RecoveryCodeService::consume(
    const identity::core::IdentityId& identity,
    const foundation::SecretString& presented)
{
    auto fingerprint = digest(presented);
    if (!fingerprint.has_value()) {
        return foundation::fail(fingerprint.error());
    }
    return m_repository->consume(identity, fingerprint.value());
}

foundation::Status RecoveryCodeService::revoke(
    const identity::core::IdentityId& identity)
{
    if (identity.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "Recovery-code revocation requires an identity.");
    }
    return m_repository->replace(identity, {});
}

}
