module;

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

// Declare the explicit Asio TLS instantiation before Asio's networking
// templates can odr-use it. GCC 16 named modules otherwise emit duplicate
// strong symbols when combined with ordinary C++ translation units.
#include <boost/asio/detail/call_stack.hpp>
#include "asio_thread_context_extern.hpp"
#include "steady_deadline.hpp"
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <openssl/ssl.h>

module openproof.gateway.http;

import openproof.security;

namespace openproof::gateway::http {
namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace beastHttp = beast::http;
namespace ssl = asio::ssl;
using Tcp = asio::ip::tcp;

[[nodiscard]] foundation::Error networkError(std::string_view operation,
                                             const boost::system::error_code& error)
{
    const foundation::ErrorCode code =
        error == beast::error::timeout || error == asio::error::timed_out
            ? foundation::ErrorCode::Timeout : foundation::ErrorCode::Unavailable;
    return foundation::Error{
        code, std::string{foundation::defaultErrorMessage(code)},
        std::string{operation} + " failed: " + error.message()};
}

[[nodiscard]] beastHttp::verb toVerb(HttpMethod method) noexcept
{
    switch (method) {
    case HttpMethod::Get: return beastHttp::verb::get;
    case HttpMethod::Head: return beastHttp::verb::head;
    case HttpMethod::Post: return beastHttp::verb::post;
    case HttpMethod::Put: return beastHttp::verb::put;
    case HttpMethod::Patch: return beastHttp::verb::patch;
    case HttpMethod::Delete: return beastHttp::verb::delete_;
    case HttpMethod::Options: return beastHttp::verb::options;
    }
    return beastHttp::verb::get;
}

[[nodiscard]] HttpResponse fromBeast(beastHttp::response<beastHttp::string_body> response)
{
    HttpResponse output{static_cast<int>(response.result_int()), {},
                        std::move(response.body())};
    for (const auto& field : response.base()) {
        output.addHeader(std::string{field.name_string()}, std::string{field.value()});
    }
    return output;
}

[[nodiscard]] beastHttp::request<beastHttp::string_body>
toBeast(const Endpoint& endpoint, const HttpRequest& request)
{
    beastHttp::request<beastHttp::string_body> output{
        toVerb(request.method()), std::string{request.target()}, 11};
    for (const auto& [name, value] : request.headers()) output.set(name, value);
    output.set(beastHttp::field::host, std::string{endpoint.host()});
    output.body() = std::string{request.body()};
    output.keep_alive(false);
    output.prepare_payload();
    return output;
}

}

ProxyConfig::ProxyConfig(std::size_t responseHeaderLimitBytes,
                         std::size_t responseBodyLimitBytes, std::string caFile)
    : m_responseHeaderLimitBytes(responseHeaderLimitBytes),
      m_responseBodyLimitBytes(responseBodyLimitBytes), m_caFile(std::move(caFile))
{
}

foundation::Result<ProxyConfig> ProxyConfig::create(
    std::size_t responseHeaderLimitBytes, std::size_t responseBodyLimitBytes,
    std::string caFile)
{
    if (responseHeaderLimitBytes < 1024U || responseHeaderLimitBytes > 65536U
        || responseBodyLimitBytes == 0U
        || responseBodyLimitBytes > 64U * 1024U * 1024U) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The HTTP proxy configuration is invalid.");
    }
    return ProxyConfig{responseHeaderLimitBytes, responseBodyLimitBytes, std::move(caFile)};
}
std::size_t ProxyConfig::responseHeaderLimitBytes() const noexcept
{ return m_responseHeaderLimitBytes; }
std::size_t ProxyConfig::responseBodyLimitBytes() const noexcept
{ return m_responseBodyLimitBytes; }
std::string_view ProxyConfig::caFile() const noexcept { return m_caFile; }

namespace {
void scrubOwnedRequest(HttpRequest& request) noexcept
{
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();
    request.wipeBody();
    request.wipeTargetQuery();
}

struct OwnedRequestScrub final {
    HttpRequest& request;
    ~OwnedRequestScrub() { scrubOwnedRequest(request); }
};

struct WireRequestScrub final {
    beastHttp::request<beastHttp::string_body>& request;
    void clear() const noexcept
    {
        // Beast owns a separate string body. Its header allocator does not
        // provide a secure erase API; removing headers is best effort only.
        foundation::secureWipe(request.body().data(), request.body().size());
        request.body().clear();
        request.erase(beastHttp::field::authorization);
        request.erase(beastHttp::field::cookie);
    }
    ~WireRequestScrub() { clear(); }
};
} // namespace

class BeastProxyTransport::Implementation final {
public:
    explicit Implementation(ProxyConfig config)
        : m_config(std::move(config)), m_tlsContext(ssl::context::tls_client)
    {
    }

    foundation::Status initialize()
    {
        boost::system::error_code error;
        m_tlsContext.set_verify_mode(ssl::verify_peer, error);
        if (error) return foundation::fail(networkError("configure TLS verification", error));
        if (m_config.caFile().empty()) m_tlsContext.set_default_verify_paths(error);
        else m_tlsContext.load_verify_file(std::string{m_config.caFile()}, error);
        if (error) return foundation::fail(networkError("load TLS trust roots", error));
        return foundation::ok();
    }

    foundation::Result<HttpResponse> send(
        const Endpoint& endpoint, const HttpRequest& request,
        foundation::Duration timeout)
    {
        if (timeout <= foundation::Duration::zero()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The upstream timeout must be positive.");
        }
        // Retain the legacy synchronous facade for compatibility, but run
        // the very same native coroutine as the nonblocking gateway path.
        // The waiting thread is a legacy handler worker, never an Asio
        // socket-reactor task; no blocking DNS, TCP, TLS or HTTP I/O remains
        // in this transport. New callers must use sendAsync() directly.
        try {
            asio::io_context context;
            // Boost.Asio 1.88's co_spawn requires a default-constructible
            // coroutine result for its exception path. HttpResponse is not
            // default-constructible; an optional around the Result makes the
            // completion ABI safe without fabricating an HTTP response.
            auto completion = asio::co_spawn(
                context, sendResultAsync(endpoint, request, timeout),
                asio::use_future);
            context.run();
            return std::move(completion.get()).value();
        } catch (...) {
            // Keep network/credential details out of client-visible errors.
            return foundation::fail(foundation::ErrorCode::Unavailable,
                                    "The upstream request failed.");
        }
    }

    // Awaitable with a default-constructible completion envelope for Boost
    // co_spawn's exception handling. The public Result remains unchanged.
    asio::awaitable<std::optional<foundation::Result<HttpResponse>>> sendResultAsync(
        Endpoint endpoint, HttpRequest request, foundation::Duration timeout)
    {
        co_return std::optional<foundation::Result<HttpResponse>>{
            co_await sendAsync(std::move(endpoint), std::move(request), timeout)};
    }

    asio::awaitable<foundation::Result<HttpResponse>> sendAsync(
        Endpoint endpoint, HttpRequest request, foundation::Duration timeout)
    {
        const OwnedRequestScrub scrub{request};
        if (timeout <= foundation::Duration::zero()) {
            co_return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                        "The upstream timeout must be positive.");
        }
        // Include strand admission in the same absolute request budget.
        const auto deadline = detail::saturatingSteadyDeadline(timeout);
        auto executor = co_await asio::this_coro::executor;
        try {
            auto result = co_await asio::co_spawn(
                asio::make_strand(executor),
                sendSerialized(std::move(endpoint), std::move(request), deadline),
                asio::use_awaitable);
            if (result) co_return std::move(*result);
        } catch (...) {
            // Never propagate transport exception details to the caller.
        }
        co_return foundation::fail(
            std::chrono::steady_clock::now() >= deadline
                ? foundation::ErrorCode::Timeout : foundation::ErrorCode::Unavailable);
    }

private:
    // Optional completion envelope satisfies Boost.Asio 1.88 co_spawn
    // exception-path construction without inventing an HTTP response.
    asio::awaitable<std::optional<foundation::Result<HttpResponse>>> sendSerialized(
        Endpoint endpoint, HttpRequest request,
        std::chrono::steady_clock::time_point deadline)
    {
        co_return std::optional<foundation::Result<HttpResponse>>{
            co_await sendOnStrand(std::move(endpoint), std::move(request), deadline)};
    }

    asio::awaitable<foundation::Result<HttpResponse>> sendOnStrand(
        Endpoint endpoint, HttpRequest request,
        std::chrono::steady_clock::time_point deadline)
    {
        const OwnedRequestScrub scrub{request};
        auto executor = co_await asio::this_coro::executor;
        if (std::chrono::steady_clock::now() >= deadline) {
            co_return foundation::fail(foundation::ErrorCode::Timeout,
                                        "The upstream request timed out.");
        }
        auto resolver = std::make_shared<Tcp::resolver>(executor);
        asio::steady_timer resolverDeadline{executor};
        resolverDeadline.expires_at(deadline);
        resolverDeadline.async_wait(
            [weak = std::weak_ptr<Tcp::resolver>{resolver}](boost::system::error_code error) {
                if (!error) {
                    if (auto active = weak.lock()) active->cancel();
                }
            });
        boost::system::error_code error;
        auto endpoints = co_await resolver->async_resolve(
            std::string{endpoint.host()}, std::to_string(endpoint.port()),
            asio::redirect_error(asio::use_awaitable, error));
        resolverDeadline.cancel();
        // A successful DNS result does not imply that the overall request
        // deadline is still valid: cancellation can race a resolver result.
        // Never start TCP/TLS or contact a retry target after that deadline.
        if (std::chrono::steady_clock::now() >= deadline) {
            co_return foundation::fail(foundation::ErrorCode::Timeout,
                                        "The upstream request timed out.");
        }
        if (error) {
            co_return foundation::fail(networkError("resolve upstream", error));
        }

        if (!endpoint.tls()) {
            beast::tcp_stream stream{executor};
            stream.expires_at(deadline);
            static_cast<void>(co_await stream.async_connect(endpoints,
                asio::redirect_error(asio::use_awaitable, error)));
            if (std::chrono::steady_clock::now() >= deadline) {
                co_return foundation::fail(foundation::ErrorCode::Timeout,
                                            "The upstream request timed out.");
            }
            if (error) co_return foundation::fail(networkError("connect upstream", error));
            auto response = co_await exchangeAsync(stream, endpoint, request, deadline);
            boost::system::error_code ignored;
            stream.socket().shutdown(Tcp::socket::shutdown_both, ignored);
            co_return response;
        }

        beast::ssl_stream<beast::tcp_stream> stream{executor, m_tlsContext};
        const std::string host{endpoint.host()};
        if (SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                     TLSEXT_NAMETYPE_host_name,
                     const_cast<char*>(host.c_str())) != 1) {
            co_return foundation::fail(foundation::ErrorCode::Internal,
                                        "TLS SNI configuration failed.");
        }
        stream.set_verify_callback(ssl::host_name_verification{host});
        beast::get_lowest_layer(stream).expires_at(deadline);
        static_cast<void>(co_await beast::get_lowest_layer(stream).async_connect(
            endpoints, asio::redirect_error(asio::use_awaitable, error)));
        if (std::chrono::steady_clock::now() >= deadline) {
            co_return foundation::fail(foundation::ErrorCode::Timeout,
                                        "The upstream request timed out.");
        }
        if (error) co_return foundation::fail(networkError("connect TLS upstream", error));
        beast::get_lowest_layer(stream).expires_at(deadline);
        co_await stream.async_handshake(
            ssl::stream_base::client, asio::redirect_error(asio::use_awaitable, error));
        if (std::chrono::steady_clock::now() >= deadline) {
            co_return foundation::fail(foundation::ErrorCode::Timeout,
                                        "The upstream request timed out.");
        }
        if (error) co_return foundation::fail(networkError("verify TLS upstream", error));
        auto response = co_await exchangeAsync(stream, endpoint, request, deadline);
        // Beast completed and validated the entire HTTP message under an
        // authenticated TLS session. Awaiting peer close_notify after this
        // point lets a slow/half-closed upstream consume the gateway's retry
        // deadline even when the response body is already complete.
        // This transport is one-shot and explicitly uses Connection: close;
        // discard the socket without reading/trusting additional peer bytes.
        // Any truncated framing or oversized body was already rejected in
        // exchangeAsync before reaching this point.
        boost::system::error_code ignored;
        beast::get_lowest_layer(stream).socket().close(ignored);
        co_return response;
    }

private:
    template <typename Stream>
    asio::awaitable<foundation::Result<HttpResponse>> exchangeAsync(
        Stream& stream, const Endpoint& endpoint, HttpRequest& request,
        std::chrono::steady_clock::time_point deadline)
    {
        boost::system::error_code error;
        const bool headRequest = request.method() == HttpMethod::Head;
        auto outgoing = toBeast(endpoint, request);
        const WireRequestScrub scrub{outgoing};
        scrubOwnedRequest(request);
        // Framing and copying an outgoing body consume the same budget.
        if (std::chrono::steady_clock::now() >= deadline) {
            co_return foundation::fail(foundation::ErrorCode::Timeout,
                                        "The upstream request timed out.");
        }
        beast::get_lowest_layer(stream).expires_at(deadline);
        static_cast<void>(co_await beastHttp::async_write(
            stream, outgoing, asio::redirect_error(asio::use_awaitable, error)));
        // The async writer has completed, so its serialized body is no
        // longer needed even if the upstream delays its response.
        scrub.clear();
        // A successful completion may race timer expiry. Do not treat it
        // as permission to start a new read after the request deadline.
        if (std::chrono::steady_clock::now() >= deadline) {
            co_return foundation::fail(foundation::ErrorCode::Timeout,
                                        "The upstream request timed out.");
        }
        if (error) co_return foundation::fail(networkError("write upstream request", error));

        beastHttp::response_parser<beastHttp::string_body> parser;
        // HEAD has no response body even if Content-Length advertises the
        // corresponding GET representation. Set this before parsing any bytes.
        parser.skip(headRequest);
        parser.header_limit(static_cast<std::uint32_t>(
            m_config.responseHeaderLimitBytes()));
        parser.body_limit(m_config.responseBodyLimitBytes());
        beast::flat_buffer buffer;
        beast::get_lowest_layer(stream).expires_at(deadline);
        static_cast<void>(co_await beastHttp::async_read(
            stream, buffer, parser, asio::redirect_error(asio::use_awaitable, error)));
        // Even fully framed, nominally successful responses are rejected if
        // completion happens after the absolute upstream deadline.
        if (std::chrono::steady_clock::now() >= deadline) {
            co_return foundation::fail(foundation::ErrorCode::Timeout,
                                        "The upstream request timed out.");
        }
        if (error) co_return foundation::fail(networkError("read upstream response", error));
        co_return fromBeast(parser.release());
    }

    ProxyConfig m_config;
    ssl::context m_tlsContext;
};

BeastProxyTransport::BeastProxyTransport(
    std::unique_ptr<Implementation> implementation)
    : m_implementation(std::move(implementation))
{
}

foundation::Result<std::unique_ptr<BeastProxyTransport>>
BeastProxyTransport::create(ProxyConfig config)
{
    auto implementation = std::make_unique<Implementation>(std::move(config));
    const foundation::Status initialized = implementation->initialize();
    if (!initialized.has_value()) return foundation::fail(initialized.error());
    return std::unique_ptr<BeastProxyTransport>{
        new BeastProxyTransport{std::move(implementation)}};
}

BeastProxyTransport::~BeastProxyTransport() = default;

foundation::Result<HttpResponse> BeastProxyTransport::send(
    const Endpoint& endpoint, const HttpRequest& request,
    foundation::Duration timeout)
{
    return m_implementation->send(endpoint, request, timeout);
}

boost::asio::awaitable<foundation::Result<HttpResponse>>
BeastProxyTransport::sendAsync(
    Endpoint endpoint, HttpRequest request, foundation::Duration timeout)
{
    co_return co_await m_implementation->sendAsync(
        std::move(endpoint), std::move(request), timeout);
}


} // namespace openproof::gateway::http
