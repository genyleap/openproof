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
#include <vector>

// Declare the explicit Asio TLS instantiation before Asio's networking
// templates can odr-use it. GCC 16 named modules otherwise emit duplicate
// strong symbols when combined with ordinary C++ translation units.
#include <boost/asio/detail/call_stack.hpp>
namespace boost::asio::detail {
class thread_context;
class thread_info_base;
}
#include "asio_thread_context_extern.hpp"
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

[[nodiscard]] beastHttp::response<beastHttp::string_body>
wireResponse(HttpResponse response, unsigned int version, bool headRequest)
{
    const auto status = static_cast<beastHttp::status>(response.status());
    beastHttp::response<beastHttp::string_body> output{status, version};
    for (const auto& [name, value] : response.headers()) output.set(name, value);
    for (const auto& [name, value] : response.repeatedHeaders()) output.insert(name, value);
    if (!headRequest) output.body() = std::string{response.body()};
    output.keep_alive(false);
    output.prepare_payload();
    return output;
}

[[nodiscard]] beastHttp::response<beastHttp::string_body>
parserFailure(const boost::system::error_code& error, unsigned int version)
{
    beastHttp::status status = beastHttp::status::bad_request;
    if (error == beastHttp::error::body_limit) status = beastHttp::status::payload_too_large;
    else if (error == beastHttp::error::header_limit) {
        status = beastHttp::status::request_header_fields_too_large;
    }
    beastHttp::response<beastHttp::string_body> response{status, version};
    response.set(beastHttp::field::content_type, "application/json");
    response.set("cache-control", "no-store");
    response.set("x-content-type-options", "nosniff");
    response.body() = "{\"error\":{\"code\":\"INVALID_ARGUMENT\","
                      "\"message\":\"The HTTP request is invalid.\"}}";
    response.keep_alive(false);
    response.prepare_payload();
    return response;
}

}

ServerConfig::ServerConfig(std::string bindAddress, std::uint16_t port,
                           std::size_t headerLimitBytes, std::size_t bodyLimitBytes,
                           foundation::Duration readTimeout,
                           foundation::Duration writeTimeout,
                           std::size_t maximumConnections, std::size_t workerThreads,
                           bool trustProxyClientIp)
    : m_bindAddress(std::move(bindAddress)), m_port(port),
      m_headerLimitBytes(headerLimitBytes), m_bodyLimitBytes(bodyLimitBytes),
      m_readTimeout(readTimeout), m_writeTimeout(writeTimeout),
      m_maximumConnections(maximumConnections), m_workerThreads(workerThreads),
      m_trustProxyClientIp(trustProxyClientIp)
{
}

foundation::Result<ServerConfig> ServerConfig::create(
    std::string bindAddress, std::uint16_t port, std::size_t headerLimitBytes,
    std::size_t bodyLimitBytes, foundation::Duration readTimeout,
    foundation::Duration writeTimeout, std::size_t maximumConnections,
    std::size_t workerThreads, bool trustProxyClientIp)
{
    boost::system::error_code addressError;
    const asio::ip::address bindAddressValue = asio::ip::make_address(
        bindAddress, addressError);
    if (bindAddress.empty() || headerLimitBytes < 1024U || headerLimitBytes > 65536U
        || bodyLimitBytes == 0U || bodyLimitBytes > 64U * 1024U * 1024U
        || readTimeout <= foundation::Duration::zero()
        || writeTimeout <= foundation::Duration::zero()
        || maximumConnections == 0U || workerThreads == 0U || workerThreads > 256U
        || (trustProxyClientIp && (addressError || !bindAddressValue.is_loopback()))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The HTTP server configuration is invalid.");
    }
    return ServerConfig{std::move(bindAddress), port, headerLimitBytes, bodyLimitBytes,
                        readTimeout, writeTimeout, maximumConnections, workerThreads,
                        trustProxyClientIp};
}

std::string_view ServerConfig::bindAddress() const noexcept { return m_bindAddress; }
std::uint16_t ServerConfig::port() const noexcept { return m_port; }
std::size_t ServerConfig::headerLimitBytes() const noexcept { return m_headerLimitBytes; }
std::size_t ServerConfig::bodyLimitBytes() const noexcept { return m_bodyLimitBytes; }
foundation::Duration ServerConfig::readTimeout() const noexcept { return m_readTimeout; }
foundation::Duration ServerConfig::writeTimeout() const noexcept { return m_writeTimeout; }
std::size_t ServerConfig::maximumConnections() const noexcept { return m_maximumConnections; }
std::size_t ServerConfig::workerThreads() const noexcept { return m_workerThreads; }
bool ServerConfig::trustProxyClientIp() const noexcept { return m_trustProxyClientIp; }

class BeastHttpServer::Implementation final {
public:
    Implementation(HttpHandler& handler, ServerConfig config)
        : m_handler(&handler), m_config(std::move(config)), m_acceptor(m_context),
          m_handlerPool(std::clamp<std::size_t>(m_config.workerThreads() * 4U, 4U, 16U))
    {
    }

    class Connection final : public std::enable_shared_from_this<Connection> {
    public:
        Connection(Tcp::socket socket, Implementation& owner)
            : m_stream(std::move(socket)), m_owner(&owner)
        {
        }

        ~Connection()
        {
            m_owner->m_connections.fetch_sub(1U, std::memory_order_relaxed);
        }

        void start()
        {
            // Socket operations now have a native C++ coroutine lifetime.
            // The transport-neutral handler is still dispatched to the bounded
            // compatibility pool until repository/provider SPIs are async.
            asio::co_spawn(m_stream.get_executor(), readRequest(),
                [self = shared_from_this()](std::exception_ptr error) {
                    // co_spawn must consume exceptions rather than terminate a worker.
                    if (error) {
                        try { std::rethrow_exception(error); }
                        catch (...) {}
                    }
                });
        }

    private:
        asio::awaitable<void> readRequest()
        {
            m_parser.emplace();
            m_parser->header_limit(static_cast<std::uint32_t>(
                m_owner->m_config.headerLimitBytes()));
            m_parser->body_limit(m_owner->m_config.bodyLimitBytes());
            m_stream.expires_after(m_owner->m_config.readTimeout());
            boost::system::error_code error;
            static_cast<void>(co_await beastHttp::async_read(
                m_stream, m_buffer, *m_parser,
                asio::redirect_error(asio::use_awaitable, error)));
            onRead(error);
        }
        void onRead(const boost::system::error_code& error)
        {
            if (error) {
                if (error != beastHttp::error::end_of_stream
                    && error != asio::error::operation_aborted) {
                    write(parserFailure(error, 11U));
                }
                return;
            }
            auto incoming = m_parser->release();
            auto method = parseHttpMethod(incoming.method_string());
            std::vector<std::pair<std::string, std::string>> headers;
            std::optional<std::string> forwardedClientIp;
            for (const auto& field : incoming.base()) {
                if (beast::iequals(field.name_string(), "x-forwarded-for")) {
                    if (m_owner->m_config.trustProxyClientIp()
                        && !forwardedClientIp.has_value()) {
                        forwardedClientIp.emplace(field.value());
                    }
                    continue;
                }
                headers.emplace_back(std::string{field.name_string()},
                                     std::string{field.value()});
            }
            boost::system::error_code endpointError;
            const Tcp::endpoint remote = m_stream.socket().remote_endpoint(endpointError);
            auto correlation = security::randomTokenBase64Url(16U);
            if (!method.has_value() || endpointError || !correlation.has_value()) {
                write(parserFailure(make_error_code(boost::system::errc::invalid_argument),
                                    incoming.version()));
                return;
            }
            std::string remoteAddress = remote.address().to_string();
            if (m_owner->m_config.trustProxyClientIp()) {
                boost::system::error_code forwardedError;
                if (!forwardedClientIp.has_value()
                    || forwardedClientIp->empty()
                    || forwardedClientIp->contains(',')
                    || forwardedClientIp->contains(' ')
                    || forwardedClientIp->contains('\t')) {
                    write(parserFailure(
                        make_error_code(boost::system::errc::invalid_argument),
                        incoming.version()));
                    return;
                }
                const asio::ip::address forwarded = asio::ip::make_address(
                    *forwardedClientIp, forwardedError);
                if (forwardedError) {
                    write(parserFailure(
                        make_error_code(boost::system::errc::invalid_argument),
                        incoming.version()));
                    return;
                }
                remoteAddress = forwarded.to_string();
            }
            auto request = HttpRequest::create(
                method.value(), std::string{incoming.target()}, std::move(headers),
                std::move(incoming.body()), std::move(remoteAddress),
                foundation::CorrelationId{std::move(correlation).value()});
            if (!request.has_value()) {
                write(parserFailure(make_error_code(boost::system::errc::invalid_argument),
                                    incoming.version()));
                return;
            }
            // Guard the executor queue: a slow provider/database must not turn
            // the maximum HTTP connection count into an unbounded work backlog.
            const std::size_t pendingLimit = std::clamp<std::size_t>(
                m_owner->m_config.workerThreads() * 32U, 64U, 256U);
            const std::size_t outstanding = m_owner->m_pendingHandlers.fetch_add(
                1U, std::memory_order_acq_rel);
            if (outstanding >= pendingLimit) {
                m_owner->m_pendingHandlers.fetch_sub(1U, std::memory_order_acq_rel);
                beastHttp::response<beastHttp::string_body> overload{
                    beastHttp::status::service_unavailable, incoming.version()};
                overload.set(beastHttp::field::content_type, "application/json");
                overload.set(beastHttp::field::cache_control, "no-store");
                overload.set(beastHttp::field::retry_after, "1");
                overload.set("x-content-type-options", "nosniff");
                if (incoming.method() != beastHttp::verb::head) {
                    overload.body() = "{\"error\":{\"code\":\"UNAVAILABLE\","
                                      "\"message\":\"The server is busy.\"}}";
                }
                overload.keep_alive(false);
                overload.prepare_payload();
                write(std::move(overload));
                return;
            }
            // Keep blocking repository/provider/crypto work off the socket event loop.
            // This is a bounded compatibility executor, not a claim that those
            // operations have become coroutine-based or non-blocking.
            const unsigned int version = incoming.version();
            const bool headRequest = incoming.method() == beastHttp::verb::head;
            asio::post(m_owner->m_handlerPool,
                [self = shared_from_this(), operation = std::move(request).value(),
                 version, headRequest]() mutable {
                    beastHttp::response<beastHttp::string_body> wire;
                    try {
                        auto response = self->m_owner->m_handler->handle(
                            std::move(operation));
                        wire = wireResponse(std::move(response), version, headRequest);
                    } catch (...) {
                        // A faulty provider must not terminate an I/O worker.
                        beastHttp::response<beastHttp::string_body> failure{
                            beastHttp::status::internal_server_error, version};
                        failure.set(beastHttp::field::content_type, "application/json");
                        failure.set(beastHttp::field::cache_control, "no-store");
                        failure.set("x-content-type-options", "nosniff");
                        if (!headRequest) {
                            failure.body() = "{\"error\":{\"code\":\"INTERNAL\","
                                             "\"message\":\"The request failed.\"}}";
                        }
                        failure.keep_alive(false);
                        failure.prepare_payload();
                        wire = std::move(failure);
                    }
                    self->m_owner->m_pendingHandlers.fetch_sub(
                        1U, std::memory_order_acq_rel);
                    asio::post(self->m_owner->m_context,
                        [self, result = std::move(wire)]() mutable {
                            if (self->m_owner->m_running.load(std::memory_order_acquire)) {
                                self->write(std::move(result));
                            }
                        });
                });
        }

        void write(beastHttp::response<beastHttp::string_body> response)
        {
            m_response.emplace(std::move(response));
            asio::co_spawn(m_stream.get_executor(), writeResponse(),
                [self = shared_from_this()](std::exception_ptr error) {
                    if (error) {
                        try { std::rethrow_exception(error); }
                        catch (...) {}
                    }
                });
        }

        asio::awaitable<void> writeResponse()
        {
            m_stream.expires_after(m_owner->m_config.writeTimeout());
            boost::system::error_code error;
            static_cast<void>(co_await beastHttp::async_write(
                m_stream, *m_response,
                asio::redirect_error(asio::use_awaitable, error)));
            boost::system::error_code ignored;
            m_stream.socket().shutdown(Tcp::socket::shutdown_send, ignored);
        }

        beast::tcp_stream m_stream;
        Implementation* m_owner;
        beast::flat_buffer m_buffer;
        std::optional<beastHttp::request_parser<beastHttp::string_body>> m_parser;
        std::optional<beastHttp::response<beastHttp::string_body>> m_response;
    };

    foundation::Status start()
    {
        bool neverStarted = false;
        if (!m_started.compare_exchange_strong(neverStarted, true)) {
            return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                    "An HTTP server instance cannot be restarted.");
        }
        bool expected = false;
        if (!m_running.compare_exchange_strong(expected, true)) {
            return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                    "The HTTP server is already running.");
        }
        boost::system::error_code error;
        const asio::ip::address address = asio::ip::make_address(m_config.bindAddress(), error);
        if (error) return startFailure("parse bind address", error);
        const Tcp::endpoint endpoint{address, m_config.port()};
        m_acceptor.open(endpoint.protocol(), error);
        if (error) return startFailure("open listener", error);
        m_acceptor.set_option(asio::socket_base::reuse_address(true), error);
        if (error) return startFailure("configure listener", error);
        m_acceptor.bind(endpoint, error);
        if (error) return startFailure("bind listener", error);
        m_acceptor.listen(asio::socket_base::max_listen_connections, error);
        if (error) return startFailure("listen", error);
        m_boundPort.store(m_acceptor.local_endpoint(error).port(), std::memory_order_relaxed);
        if (error) return startFailure("read bound port", error);
        accept();
        m_workers.reserve(m_config.workerThreads());
        for (std::size_t index = 0U; index < m_config.workerThreads(); ++index) {
            m_workers.emplace_back([this] { m_context.run(); });
        }
        return foundation::ok();
    }

    void stop() noexcept
    {
        if (!m_running.exchange(false)) return;
        boost::system::error_code ignored;
        m_acceptor.close(ignored);
        m_context.stop();
        m_workers.clear();
        // Discard queued work instead of keeping shutdown behind a long queue.
        // Running handlers can finish before the handler object is destroyed.
        m_handlerPool.stop();
        m_handlerPool.join();
        m_boundPort.store(0U, std::memory_order_relaxed);
    }

    [[nodiscard]] bool running() const noexcept { return m_running.load(); }
    [[nodiscard]] std::uint16_t boundPort() const noexcept { return m_boundPort.load(); }

private:
    foundation::Status startFailure(std::string_view operation,
                                    const boost::system::error_code& error)
    {
        m_running.store(false);
        boost::system::error_code ignored;
        m_acceptor.close(ignored);
        return foundation::fail(networkError(operation, error));
    }

    void accept()
    {
        asio::co_spawn(m_context, acceptLoop(),
            [](std::exception_ptr error) {
                if (error) {
                    try { std::rethrow_exception(error); }
                    catch (...) {}
                }
            });
    }

    asio::awaitable<void> acceptLoop()
    {
            while (m_running.load(std::memory_order_acquire)) {
                boost::system::error_code error;
                Tcp::socket socket = co_await m_acceptor.async_accept(
                    asio::redirect_error(asio::use_awaitable, error));
                if (error == asio::error::operation_aborted) co_return;
                if (error) continue;
                const std::size_t count =
                    m_connections.fetch_add(1U, std::memory_order_relaxed) + 1U;
                if (count > m_config.maximumConnections()) {
                    m_connections.fetch_sub(1U, std::memory_order_relaxed);
                    boost::system::error_code ignored;
                    socket.shutdown(Tcp::socket::shutdown_both, ignored);
                    socket.close(ignored);
                } else {
                    std::make_shared<Connection>(std::move(socket), *this)->start();
                }
            }
    }

    HttpHandler* m_handler;
    ServerConfig m_config;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_started{false};
    std::atomic<std::uint16_t> m_boundPort{0U};
    std::atomic<std::size_t> m_connections{0U};
    std::atomic<std::size_t> m_pendingHandlers{0U};
    asio::io_context m_context;
    Tcp::acceptor m_acceptor;
    asio::thread_pool m_handlerPool;
    std::vector<std::jthread> m_workers;
};

BeastHttpServer::BeastHttpServer(HttpHandler& handler, ServerConfig config)
    : m_implementation(std::make_unique<Implementation>(handler, std::move(config)))
{
}
BeastHttpServer::~BeastHttpServer() { stop(); }
foundation::Status BeastHttpServer::start() { return m_implementation->start(); }
void BeastHttpServer::stop() noexcept { m_implementation->stop(); }
bool BeastHttpServer::running() const noexcept { return m_implementation->running(); }
std::uint16_t BeastHttpServer::boundPort() const noexcept { return m_implementation->boundPort(); }

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
        return endpoint.tls() ? sendTls(endpoint, request, timeout)
                              : sendPlain(endpoint, request, timeout);
    }

    asio::awaitable<foundation::Result<HttpResponse>> sendAsync(
        Endpoint endpoint, HttpRequest request, foundation::Duration timeout)
    {
        if (timeout <= foundation::Duration::zero()) {
            co_return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                        "The upstream timeout must be positive.");
        }
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        auto executor = co_await asio::this_coro::executor;
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
        if (error) {
            if (std::chrono::steady_clock::now() >= deadline) {
                co_return foundation::fail(foundation::ErrorCode::Timeout,
                                            "The upstream request timed out.");
            }
            co_return foundation::fail(networkError("resolve upstream", error));
        }

        if (!endpoint.tls()) {
            beast::tcp_stream stream{executor};
            stream.expires_at(deadline);
            static_cast<void>(co_await stream.async_connect(endpoints,
                asio::redirect_error(asio::use_awaitable, error)));
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
        if (error) co_return foundation::fail(networkError("connect TLS upstream", error));
        beast::get_lowest_layer(stream).expires_at(deadline);
        co_await stream.async_handshake(
            ssl::stream_base::client, asio::redirect_error(asio::use_awaitable, error));
        if (error) co_return foundation::fail(networkError("verify TLS upstream", error));
        auto response = co_await exchangeAsync(stream, endpoint, request, deadline);
        beast::get_lowest_layer(stream).expires_at(deadline);
        co_await stream.async_shutdown(asio::redirect_error(asio::use_awaitable, error));
        if (error == asio::error::eof || error == ssl::error::stream_truncated) error.clear();
        if (error && response.has_value()) {
            co_return foundation::fail(networkError("shutdown TLS upstream", error));
        }
        co_return response;
    }

private:
    foundation::Result<Tcp::resolver::results_type> resolve(
        asio::io_context& context, const Endpoint& endpoint)
    {
        boost::system::error_code error;
        Tcp::resolver resolver{context};
        auto results = resolver.resolve(std::string{endpoint.host()},
                                        std::to_string(endpoint.port()), error);
        if (error) return foundation::fail(networkError("resolve upstream", error));
        return results;
    }

    template <typename Stream>
    asio::awaitable<foundation::Result<HttpResponse>> exchangeAsync(
        Stream& stream, const Endpoint& endpoint, const HttpRequest& request,
        std::chrono::steady_clock::time_point deadline)
    {
        boost::system::error_code error;
        auto outgoing = toBeast(endpoint, request);
        beast::get_lowest_layer(stream).expires_at(deadline);
        static_cast<void>(co_await beastHttp::async_write(
            stream, outgoing, asio::redirect_error(asio::use_awaitable, error)));
        if (error) co_return foundation::fail(networkError("write upstream request", error));

        beastHttp::response_parser<beastHttp::string_body> parser;
        parser.header_limit(static_cast<std::uint32_t>(
            m_config.responseHeaderLimitBytes()));
        parser.body_limit(m_config.responseBodyLimitBytes());
        beast::flat_buffer buffer;
        beast::get_lowest_layer(stream).expires_at(deadline);
        static_cast<void>(co_await beastHttp::async_read(
            stream, buffer, parser, asio::redirect_error(asio::use_awaitable, error)));
        if (error) co_return foundation::fail(networkError("read upstream response", error));
        co_return fromBeast(parser.release());
    }

    template <typename Stream>
    foundation::Result<HttpResponse> exchange(
        Stream& stream, const Endpoint& endpoint, const HttpRequest& request,
        foundation::Duration timeout)
    {
        boost::system::error_code error;
        auto outgoing = toBeast(endpoint, request);
        beast::get_lowest_layer(stream).expires_after(timeout);
        beastHttp::write(stream, outgoing, error);
        if (error) return foundation::fail(networkError("write upstream request", error));
        beastHttp::response_parser<beastHttp::string_body> parser;
        parser.header_limit(static_cast<std::uint32_t>(
            m_config.responseHeaderLimitBytes()));
        parser.body_limit(m_config.responseBodyLimitBytes());
        beast::flat_buffer buffer;
        beast::get_lowest_layer(stream).expires_after(timeout);
        beastHttp::read(stream, buffer, parser, error);
        if (error) return foundation::fail(networkError("read upstream response", error));
        return fromBeast(parser.release());
    }

    foundation::Result<HttpResponse> sendPlain(
        const Endpoint& endpoint, const HttpRequest& request,
        foundation::Duration timeout)
    {
        asio::io_context context;
        auto endpoints = resolve(context, endpoint);
        if (!endpoints.has_value()) return foundation::fail(endpoints.error());
        beast::tcp_stream stream{context};
        stream.expires_after(timeout);
        boost::system::error_code error;
        stream.connect(endpoints.value(), error);
        if (error) return foundation::fail(networkError("connect upstream", error));
        auto response = exchange(stream, endpoint, request, timeout);
        stream.socket().shutdown(Tcp::socket::shutdown_both, error);
        return response;
    }

    foundation::Result<HttpResponse> sendTls(
        const Endpoint& endpoint, const HttpRequest& request,
        foundation::Duration timeout)
    {
        asio::io_context context;
        auto endpoints = resolve(context, endpoint);
        if (!endpoints.has_value()) return foundation::fail(endpoints.error());
        beast::ssl_stream<beast::tcp_stream> stream{context, m_tlsContext};
        const std::string host{endpoint.host()};
        if (SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                     TLSEXT_NAMETYPE_host_name,
                     const_cast<char*>(host.c_str())) != 1) {
            return foundation::fail(foundation::ErrorCode::Internal,
                                    "TLS SNI configuration failed.");
        }
        stream.set_verify_callback(ssl::host_name_verification{host});
        beast::get_lowest_layer(stream).expires_after(timeout);
        boost::system::error_code error;
        beast::get_lowest_layer(stream).connect(endpoints.value(), error);
        if (error) return foundation::fail(networkError("connect TLS upstream", error));
        beast::get_lowest_layer(stream).expires_after(timeout);
        stream.handshake(ssl::stream_base::client, error);
        if (error) return foundation::fail(networkError("verify TLS upstream", error));
        auto response = exchange(stream, endpoint, request, timeout);
        beast::get_lowest_layer(stream).expires_after(timeout);
        stream.shutdown(error);
        if (error == asio::error::eof || error == ssl::error::stream_truncated) error.clear();
        if (error && response.has_value()) {
            return foundation::fail(networkError("shutdown TLS upstream", error));
        }
        return response;
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

}
