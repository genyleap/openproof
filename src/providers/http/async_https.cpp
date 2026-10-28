#include "async_https.hpp"

#include <boost/asio.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/ssl.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace openproof::provider::http::async_detail {
namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace wire = beast::http;
namespace ssl = asio::ssl;
using Tcp = asio::ip::tcp;
using Clock = std::chrono::steady_clock;

constexpr std::size_t kMaxRequestBody = 1024U * 1024U;
constexpr std::size_t kMaxRequestHeaders = 32U;
constexpr std::size_t kMaxRequestHeaderBytes = 16384U;

// A resolved destination must be globally routable, not merely syntactically
// valid or accompanied by a trusted TLS certificate. Fail the *whole* DNS
// answer set if even one result could route to loopback, a local network,
// special-use Internet infrastructure or an IPv4 tunnelling address.
// Endpoint hostname allowlisting remains a separate provider policy.
[[nodiscard]] bool publiclyRoutable(const asio::ip::address& address) noexcept
{
    if (address.is_v4()) {
        const std::uint32_t value = address.to_v4().to_uint();
        const auto inRange = [value](unsigned int bits, std::uint32_t base) {
            return (value >> (32U - bits)) == (base >> (32U - bits));
        };
        return !(inRange(8U, 0x00000000U)        // 0/8 unspecified
            || inRange(8U, 0x0A000000U)          // 10/8 private
            || inRange(10U, 0x64400000U)         // shared CGNAT
            || inRange(8U, 0x7F000000U)          // loopback
            || inRange(16U, 0xA9FE0000U)         // link-local/metadata
            || inRange(12U, 0xAC100000U)         // 172.16/12
            || inRange(16U, 0xC0A80000U)         // 192.168/16
            || inRange(24U, 0xC0000000U)         // 192.0.0/24 special use
            || inRange(24U, 0xC0000200U)         // 192.0.2/24 documentation
            || inRange(24U, 0xC0586300U)         // deprecated 6to4 relay
            || inRange(15U, 0xC6120000U)         // benchmarking
            || inRange(24U, 0xC6336400U)         // documentation
            || inRange(24U, 0xCB007100U)         // documentation
            || inRange(4U, 0xE0000000U)          // multicast
            || inRange(4U, 0xF0000000U));        // future/reserved
    }
    if (!address.is_v6()) return false;
    const auto bytes = address.to_v6().to_bytes();
    if ((bytes[0] & 0xE0U) != 0x20U) return false; // not global-unicast /3
    if (bytes[0] == 0x20U && bytes[1] == 0x02U) return false; // 6to4
    if (bytes[0] == 0x20U && bytes[1] == 0x01U) {
        if (bytes[2] == 0U || (bytes[2] == 0x0DU && bytes[3] == 0xB8U)) {
            return false; // Teredo and 2001:db8 documentation prefix
        }
    }
    return true;
}

[[nodiscard]] bool isDnsName(std::string_view host) noexcept
{
    if (host.empty() || host.size() > 253U || host.back() == '.') return false;
    std::size_t start = 0U;
    while (start < host.size()) {
        const auto dot = host.find('.', start);
        const std::size_t end = dot == std::string_view::npos ? host.size() : dot;
        const auto label = host.substr(start, end - start);
        if (label.empty() || label.size() > 63U
            || label.front() == '-' || label.back() == '-') return false;
        for (const char c : label) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '-')) return false;
        }
        if (end == host.size()) return true;
        start = end + 1U;
    }
    return false;
}

[[nodiscard]] bool validTarget(std::string_view target) noexcept
{
    if (target.empty() || target.front() != '/' || target.size() > 8192U
        || target.contains('#') || target.contains('\\')) return false;
    return std::all_of(target.begin(), target.end(), [](char c) {
        const auto b = static_cast<unsigned char>(c);
        return b >= 0x21U && b <= 0x7eU;
    });
}

[[nodiscard]] bool headerToken(std::string_view name) noexcept
{
    if (name.empty() || name.size() > 128U) return false;
    constexpr std::string_view extra{"!#$%&'*+-.^_`|~"};
    return std::all_of(name.begin(), name.end(), [extra](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9')
            || extra.find(c) != std::string_view::npos;
    });
}

[[nodiscard]] bool allowedHeader(std::string_view name) noexcept
{
    // Forbid client-controlled connection/framing authority, including
    // duplicate Host and contradictory Content-Length/Transfer-Encoding.
    static constexpr std::string_view forbidden[] = {
        "host", "connection", "content-length", "transfer-encoding",
        "proxy-authorization", "proxy-connection", "keep-alive",
        "te", "trailer", "upgrade", "expect"
    };
    for (const auto blocked : forbidden) {
        if (beast::iequals(name, blocked)) return false;
    }
    return true;
}

[[nodiscard]] bool validRequest(const HttpsRequest& request) noexcept
{
    if (!isDnsName(request.host) || request.port == 0U
        || !validTarget(request.target)
        || request.timeout <= std::chrono::milliseconds::zero()
        || request.timeout > std::chrono::minutes{2}
        || request.headers.size() > kMaxRequestHeaders
        || request.body.size() > kMaxRequestBody
        || (request.method == HttpsRequest::Method::Get
            && !request.body.empty())) return false;
    std::size_t total = 0U;
    for (std::size_t index = 0U; index < request.headers.size(); ++index) {
        const auto& [name, value] = request.headers[index];
        for (std::size_t previous = 0U; previous < index; ++previous) {
            if (beast::iequals(name, request.headers[previous].first)) {
                // No ambiguous Authorization, Content-Type, or custom
                // provider header values from duplicate mixed-case fields.
                return false;
            }
        }
        if (!headerToken(name) || !allowedHeader(name)
            || value.size() > kMaxRequestHeaderBytes - total
            || std::any_of(value.begin(), value.end(), [](char c) {
                const auto b = static_cast<unsigned char>(c);
                return b < 0x20U || b == 0x7fU;
            })) return false;
        total += name.size() + value.size();
        if (total > kMaxRequestHeaderBytes) return false;
    }
    return true;
}

[[nodiscard]] HttpsResult failure(HttpsFailure reason) noexcept
{
    return HttpsResult{reason, {}, false};
}

[[nodiscard]] HttpsResult connectionFailure(
    const boost::system::error_code& error, Clock::time_point deadline) noexcept
{
    if (Clock::now() >= deadline
        || error == asio::error::timed_out || error == beast::error::timeout) {
        return failure(HttpsFailure::Timeout);
    }
    return failure(HttpsFailure::Connection);
}
} // namespace

AsyncHttpsClient::AsyncHttpsClient(
    std::string caFile, std::size_t maxBodyBytes, std::size_t maxHeaderBytes)
    : m_context(ssl::context::tls_client),
      m_maxBodyBytes(maxBodyBytes), m_maxHeaderBytes(maxHeaderBytes)
{
    if (maxBodyBytes == 0U || maxBodyBytes > 8U * 1024U * 1024U
        || maxHeaderBytes < 1024U || maxHeaderBytes > 65536U) {
        throw std::invalid_argument{"Invalid async provider HTTPS limits"};
    }
    m_context.set_verify_mode(ssl::verify_peer);
    if (caFile.empty()) m_context.set_default_verify_paths();
    else m_context.load_verify_file(caFile);
}

asio::awaitable<HttpsResult> AsyncHttpsClient::exchange(HttpsRequest request)
{
    // Validate all potentially untrusted provider endpoints and headers
    // before issuing a DNS query or allocating an OpenSSL session.
    if (!validRequest(request)) co_return failure(HttpsFailure::InvalidRequest);

    try {
        auto executor = co_await asio::this_coro::executor;
        const auto deadline = Clock::now() + request.timeout;
        Tcp::resolver resolver{executor};
        boost::system::error_code error;

        // The DNS query has the SAME total deadline as connect/handshake/I/O.
        // cancel_after unregisters its timer with the awaitable completion;
        // there is no detached cancellation handler using an expired resolver.
        auto endpoints = co_await resolver.async_resolve(
            request.host, std::to_string(request.port),
            asio::cancel_after(request.timeout,
                asio::redirect_error(asio::use_awaitable, error)));
        if (error) co_return connectionFailure(error, deadline);
        if (Clock::now() >= deadline) co_return failure(HttpsFailure::Timeout);
        if (request.addressPolicy == HttpsRequest::AddressPolicy::PublicInternet) {
            // Reject mixed answers as well: falling back from a public to a
            // private address after a connection error is an SSRF primitive.
            bool observed = false;
            for (const auto& resolved : endpoints) {
                observed = true;
                if (!publiclyRoutable(resolved.endpoint().address())) {
                    co_return failure(HttpsFailure::UnsafeAddress);
                }
            }
            if (!observed) co_return failure(HttpsFailure::Connection);
        }

        beast::ssl_stream<beast::tcp_stream> stream{executor, m_context};
        if (SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                     TLSEXT_NAMETYPE_host_name,
                     const_cast<char*>(request.host.c_str())) != 1) {
            co_return failure(HttpsFailure::Certificate);
        }
        stream.set_verify_callback(ssl::host_name_verification(request.host));
        beast::get_lowest_layer(stream).expires_at(deadline);
        static_cast<void>(co_await beast::get_lowest_layer(stream).async_connect(
            endpoints, asio::redirect_error(asio::use_awaitable, error)));
        if (error) co_return connectionFailure(error, deadline);

        beast::get_lowest_layer(stream).expires_at(deadline);
        co_await stream.async_handshake(
            ssl::stream_base::client,
            asio::redirect_error(asio::use_awaitable, error));
        if (error) {
            if (Clock::now() >= deadline) co_return failure(HttpsFailure::Timeout);
            co_return failure(HttpsFailure::Certificate);
        }

        wire::request<wire::string_body> outgoing{
            request.method == HttpsRequest::Method::Get
                ? wire::verb::get : wire::verb::post,
            request.target, 11};
        outgoing.set(wire::field::host, request.host);
        outgoing.set(wire::field::user_agent, "OpenProof/1");
        outgoing.set(wire::field::cache_control, "no-store");
        for (const auto& [name, value] : request.headers) {
            outgoing.set(name, value);
        }
        outgoing.body() = std::move(request.body);
        outgoing.keep_alive(false);
        outgoing.prepare_payload();

        beast::get_lowest_layer(stream).expires_at(deadline);
        static_cast<void>(co_await wire::async_write(stream, outgoing,
            asio::redirect_error(asio::use_awaitable, error)));
        if (error) co_return connectionFailure(error, deadline);

        beast::flat_buffer buffer;
        wire::response_parser<wire::string_body> parser;
        parser.body_limit(m_maxBodyBytes);
        parser.header_limit(static_cast<std::uint32_t>(m_maxHeaderBytes));
        beast::get_lowest_layer(stream).expires_at(deadline);
        static_cast<void>(co_await wire::async_read(
            stream, buffer, parser,
            asio::redirect_error(asio::use_awaitable, error)));
        if (error == wire::error::body_limit || error == wire::error::header_limit) {
            co_return failure(HttpsFailure::ResponseLimit);
        }
        if (error) co_return connectionFailure(error, deadline);
        if (Clock::now() >= deadline) co_return failure(HttpsFailure::Timeout);

        auto received = parser.release();
        // Security policy is evaluated by the caller: redirects and 4xx/5xx
        // are returned without following a new DNS endpoint or exposing data.
        HttpsResponse response{received.result_int(), std::move(received.body())};
        boost::system::error_code ignored;
        beast::get_lowest_layer(stream).expires_at(deadline);
        co_await stream.async_shutdown(
            asio::redirect_error(asio::use_awaitable, ignored));
        // Once a complete bounded HTTP body is authenticated by TLS, a peer
        // omitting close_notify cannot invalidate the parsed response.
        co_return HttpsResult{HttpsFailure::None, std::move(response), true};
    } catch (const std::exception&) {
        // No URL, credentials, response text or OpenSSL details enter logs or
        // client responses. The executor cancellation also fails closed.
        co_return failure(HttpsFailure::Connection);
    }
}

} // namespace openproof::provider::http::async_detail
