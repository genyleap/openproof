#pragma once

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace openproof::provider::enterprise::async_detail {

// Passwords are heap-owned so transferring a coroutine request cannot leave
// a moved-from small-string-optimized plaintext copy in the caller's frame.
class SensitiveString final {
public:
    explicit SensitiveString(std::string_view value)
        : m_value(std::make_unique<std::string>(value)) {}
    SensitiveString(const SensitiveString&) = delete;
    SensitiveString& operator=(const SensitiveString&) = delete;
    SensitiveString(SensitiveString&&) noexcept = default;
    SensitiveString& operator=(SensitiveString&&) = delete;
    ~SensitiveString() noexcept;

    [[nodiscard]] std::string_view view() const noexcept {
        return m_value ? std::string_view{*m_value} : std::string_view{};
    }

private:
    std::unique_ptr<std::string> m_value;
};

struct LdapsRequest final {
    // A previously validated ldaps:// endpoint, not supplied by HTTP users.
    std::string uri;
    std::string baseDn;
    std::string usernameAttribute;
    std::string subjectAttribute;
    std::string displayNameAttribute;
    std::string emailAttribute;
    std::string serviceBindDn;
    SensitiveString servicePassword;
    std::string username;
    SensitiveString userPassword;
    std::string caFile;
    // Trusted internal budget; production uses 10s and tests may tighten it.
    std::chrono::milliseconds timeout{10000};

};

enum class LdapsFailure {
    None,
    InvalidConfiguration,
    Connection,
    Certificate,
    Timeout,
    BindRejected,
    Unresolved,
    Protocol
};

struct LdapsResult final {
    explicit LdapsResult(LdapsFailure code = LdapsFailure::Protocol) noexcept
        : failure(code) {}
    LdapsFailure failure;
    std::string subject;
    std::optional<std::string> displayName;
    std::optional<std::string> email;

    [[nodiscard]] bool success() const noexcept {
        return failure == LdapsFailure::None;
    }
};

// Strict LDAPv3 simple bind -> equality search -> user rebind over one
// certificate/hostname-verified LDAPS connection. All DNS/TCP/TLS/BER I/O is
// awaited on the calling Asio executor. No OpenLDAP sync APIs, blocking
// worker offload, referral chasing, StartTLS downgrade or reused connection.
// A single 10s steady-clock deadline bounds every network phase.
class AsyncLdapsClient final {
public:
    [[nodiscard]] static boost::asio::awaitable<LdapsResult>
    authenticate(LdapsRequest request);
};

} // namespace openproof::provider::enterprise::async_detail
