#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace openproof::provider::http::async_detail {

struct HttpsRequest final {
    enum class Method { Get, Post };
    Method method{Method::Get};
    std::string host;
    std::uint16_t port{443U};
    std::string target{"/"};
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::chrono::milliseconds timeout{10000};
};

struct HttpsResponse final {
    unsigned int status{};
    std::string body;
};

// An explicitly typed and sanitized error; never exposes request credentials,
// OAuth codes, TLS verification internals, or upstream response content.
enum class HttpsFailure {
    None,
    InvalidRequest,
    Timeout,
    Connection,
    Certificate,
    ResponseLimit
};

struct HttpsResult final {
    HttpsFailure failure{HttpsFailure::None};
    HttpsResponse response;
    bool success{};
};

// Shared native Boost.Asio/Beast HTTPS client for first-party OAuth providers.
// Does not follow redirects or expose a synchronous fallback. The provider
// policy owns endpoint allowlisting, DNS rebinding and private-IP restrictions;
// this transport does not independently enforce a network-address allowlist.
// The client and SSL context must outlive every in-flight exchange.
class AsyncHttpsClient final {
public:
    explicit AsyncHttpsClient(
        std::string caFile = {}, std::size_t maxBodyBytes = 2U * 1024U * 1024U,
        std::size_t maxHeaderBytes = 32768U);
    AsyncHttpsClient(const AsyncHttpsClient&) = delete;
    AsyncHttpsClient& operator=(const AsyncHttpsClient&) = delete;
    ~AsyncHttpsClient() = default;

    [[nodiscard]] boost::asio::awaitable<HttpsResult>
    exchange(HttpsRequest request);

private:
    boost::asio::ssl::context m_context;
    std::size_t m_maxBodyBytes;
    std::size_t m_maxHeaderBytes;
};

} // namespace openproof::provider::http::async_detail
