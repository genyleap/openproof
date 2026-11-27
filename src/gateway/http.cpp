module;

#include "asio_service_ids_extern.hpp"
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
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/beast.hpp>

module openproof.gateway.http;

import openproof.security;

namespace openproof::gateway::http {
namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace beastHttp = beast::http;
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

[[nodiscard]] beastHttp::response<beastHttp::string_body>
wireResponse(HttpResponse response, unsigned int version, bool headRequest)
{
    const auto status = static_cast<beastHttp::status>(response.status());
    beastHttp::response<beastHttp::string_body> output{status, version};
    for (const auto& [name, value] : response.headers()) output.set(name, value);
    for (const auto& [name, value] : response.repeatedHeaders()) output.insert(name, value);
    output.keep_alive(false);
    if (headRequest) {
        // HEAD carries representation metadata, not an actual message body.
        // prepare_payload() on an empty string_body would overwrite a valid
        // upstream Content-Length with zero. Never advertise transfer framing
        // on this header-only response; preserve the known representation size.
        output.erase(beastHttp::field::transfer_encoding);
        if ((response.status() >= 100 && response.status() < 200)
            || response.status() == 204) {
            output.erase(beastHttp::field::content_length);
        } else if (!response.body().empty()) {
            output.content_length(response.body().size());
        }
        return output;
    }
    output.body() = std::move(response).takeBody();
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
                           bool trustProxyClientIp, std::size_t handlerThreads,
                           bool reactorPublicReads)
    : m_bindAddress(std::move(bindAddress)), m_port(port),
      m_headerLimitBytes(headerLimitBytes), m_bodyLimitBytes(bodyLimitBytes),
      m_readTimeout(readTimeout), m_writeTimeout(writeTimeout),
      m_maximumConnections(maximumConnections), m_workerThreads(workerThreads),
      m_handlerThreads(handlerThreads == 0U
          ? std::clamp<std::size_t>(workerThreads * 4U, 4U, 16U) : handlerThreads),
      m_trustProxyClientIp(trustProxyClientIp),
      m_reactorPublicReads(reactorPublicReads)
{
}

foundation::Result<ServerConfig> ServerConfig::create(
    std::string bindAddress, std::uint16_t port, std::size_t headerLimitBytes,
    std::size_t bodyLimitBytes, foundation::Duration readTimeout,
    foundation::Duration writeTimeout, std::size_t maximumConnections,
    std::size_t workerThreads, bool trustProxyClientIp,
    std::size_t handlerThreads, bool reactorPublicReads)
{
    boost::system::error_code addressError;
    const asio::ip::address bindAddressValue = asio::ip::make_address(
        bindAddress, addressError);
    if (bindAddress.empty() || headerLimitBytes < 1024U || headerLimitBytes > 65536U
        || bodyLimitBytes == 0U || bodyLimitBytes > 64U * 1024U * 1024U
        || readTimeout <= foundation::Duration::zero()
        || writeTimeout <= foundation::Duration::zero()
        || maximumConnections == 0U || workerThreads == 0U || workerThreads > 256U
        || handlerThreads > 16U
        || (trustProxyClientIp && (addressError || !bindAddressValue.is_loopback()))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The HTTP server configuration is invalid.");
    }
    return ServerConfig{std::move(bindAddress), port, headerLimitBytes, bodyLimitBytes,
                        readTimeout, writeTimeout, maximumConnections, workerThreads,
                        trustProxyClientIp, handlerThreads, reactorPublicReads};
}

std::string_view ServerConfig::bindAddress() const noexcept { return m_bindAddress; }
std::uint16_t ServerConfig::port() const noexcept { return m_port; }
std::size_t ServerConfig::headerLimitBytes() const noexcept { return m_headerLimitBytes; }
std::size_t ServerConfig::bodyLimitBytes() const noexcept { return m_bodyLimitBytes; }
foundation::Duration ServerConfig::readTimeout() const noexcept { return m_readTimeout; }
foundation::Duration ServerConfig::writeTimeout() const noexcept { return m_writeTimeout; }
std::size_t ServerConfig::maximumConnections() const noexcept { return m_maximumConnections; }
std::size_t ServerConfig::workerThreads() const noexcept { return m_workerThreads; }
std::size_t ServerConfig::handlerThreads() const noexcept { return m_handlerThreads; }
bool ServerConfig::trustProxyClientIp() const noexcept { return m_trustProxyClientIp; }
bool ServerConfig::reactorPublicReads() const noexcept { return m_reactorPublicReads; }

class BeastHttpServer::Implementation final {
public:
    Implementation(HttpHandler& handler, ServerConfig config)
        : m_handler(&handler), m_config(std::move(config)), m_acceptor(m_context),
          m_handlerPool(m_config.handlerThreads())
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
                    // An unexpected exception during request parsing or
                    // dispatch must not silently tear down a client socket.
                    // The exception can contain secrets; never render or log
                    // its message. A response may already be in flight.
                    if (error) self->sendReadFailureIfUnanswered();
                });
        }

    private:
        void sendReadFailureIfUnanswered() noexcept
        {
            if (m_response.has_value()
                || !m_owner->m_running.load(std::memory_order_acquire)) return;
            try {
                beastHttp::response<beastHttp::string_body> failure{
                    beastHttp::status::internal_server_error, 11U};
                failure.set(beastHttp::field::content_type, "application/json");
                failure.set(beastHttp::field::cache_control, "no-store");
                failure.set("x-content-type-options", "nosniff");
                failure.body() = "{\"error\":{\"code\":\"INTERNAL\","
                                 "\"message\":\"The request failed.\"}}";
                failure.keep_alive(false);
                failure.prepare_payload();
                write(std::move(failure));
            } catch (...) {
                // If memory or socket setup is unavailable, there is no
                // recoverable response. Preserve fail-closed behavior.
            }
        }

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
            if (error) {
                if (error != beastHttp::error::end_of_stream
                    && error != asio::error::operation_aborted) {
                    write(parserFailure(error, 11U));
                }
                co_return;
            }
            std::optional<HttpRequest> operation;
            unsigned int version = 11U;
            bool headRequest = false;
            {
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
                    co_return;
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
                        co_return;
                    }
                    const asio::ip::address forwarded = asio::ip::make_address(
                        *forwardedClientIp, forwardedError);
                    if (forwardedError) {
                        write(parserFailure(
                            make_error_code(boost::system::errc::invalid_argument),
                            incoming.version()));
                        co_return;
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
                    co_return;
                }
                version = incoming.version();
                headRequest = incoming.method() == beastHttp::verb::head;
                operation.emplace(std::move(request).value());
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
                    beastHttp::status::service_unavailable, version};
                overload.set(beastHttp::field::content_type, "application/json");
                overload.set(beastHttp::field::cache_control, "no-store");
                overload.set(beastHttp::field::retry_after, "1");
                overload.set("x-content-type-options", "nosniff");
                if (!headRequest) {
                    overload.body() = "{\"error\":{\"code\":\"UNAVAILABLE\","
                                      "\"message\":\"The server is busy.\"}}";
                }
                overload.keep_alive(false);
                overload.prepare_payload();
                write(std::move(overload));
                co_return;
            }
            // Keep the bounded worker pool, but await its result on the
            // connection strand. A successful request now has one listener
            // coroutine for both read and write, not a second posted write
            // coroutine. The outer co_spawn completion pins the connection.
            {
                // Own exactly one admission slot until the handler finishes,
                // including exceptions during initiation or shutdown.
                struct PendingHandlerGuard final {
                    std::atomic<std::size_t>& pending;
                    ~PendingHandlerGuard() {
                        pending.fetch_sub(1U, std::memory_order_acq_rel);
                    }
                } guard{m_owner->m_pendingHandlers};
                beastHttp::response<beastHttp::string_body> wire;
                auto* asyncHandler = m_owner->m_config.reactorPublicReads()
                    ? dynamic_cast<CoroutineHttpHandler*>(m_owner->m_handler) : nullptr;
                // Never move large request-body scrubbing or arbitrary native
                // providers onto the connection strand. An explicit capability
                // is required in addition to native dispatch readiness.
                if (asyncHandler && operation->body().empty()
                    && asyncHandler->reactorSafeFor(*operation)) {
                    wire = co_await dispatchHandler(
                        std::move(*operation), version, headRequest, true);
                } else {
                    wire = co_await asio::co_spawn(m_owner->m_handlerPool,
                        dispatchHandler(std::move(*operation), version, headRequest),
                        asio::use_awaitable);
                }
                operation.reset();
                if (!m_owner->m_running.load(std::memory_order_acquire)) co_return;
                m_response.emplace(std::move(wire));
            }
            // Completion is associated with this coroutine's executor, the
            // connection strand. No handler worker touches the Beast stream.
            co_await writeResponse(headRequest);
        }

        asio::awaitable<beastHttp::response<beastHttp::string_body>> dispatchHandler(
            HttpRequest operation, unsigned int version, bool headRequest,
            bool reactorOnly = false)
        {
            beastHttp::response<beastHttp::string_body> wire;
            try {
                auto* asyncHandler =
                    dynamic_cast<CoroutineHttpHandler*>(m_owner->m_handler);
                // Keep legacy routing unchanged for a coroutine-capable
                // adapter whose native storage dependencies are not enabled.
                const bool native = asyncHandler
                    && asyncHandler->nativeEnabledFor(operation);
                if (reactorOnly && (!native || !asyncHandler->reactorSafeFor(operation))) {
                    // A revoked capability must never select synchronous
                    // fallback on the reactor, even during a routing change.
                    operation.wipeBody();
                    operation.wipeAuthorizationHeader();
                    operation.wipeCookieHeader();
                    operation.wipeTargetQuery();
                    co_return wireResponse(HttpResponse{503,
                        Headers{{"cache-control", "no-store"},
                                {"x-content-type-options", "nosniff"}}, {}},
                        version, headRequest);
                }
                auto response = native
                    ? co_await asyncHandler->handleAsync(std::move(operation))
                    : m_owner->m_handler->handle(std::move(operation));
                wire = wireResponse(std::move(response), version, headRequest);
            } catch (...) {
                // Preserve a sanitized server error even when an async
                // provider throws after resuming from an I/O suspension.
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
            co_return wire;
        }

        void write(beastHttp::response<beastHttp::string_body> response, bool headRequest = false)
        {
            m_response.emplace(std::move(response));
            asio::co_spawn(m_stream.get_executor(), writeResponse(headRequest),
                [self = shared_from_this()](std::exception_ptr error) {
                    if (error) {
                        try { std::rethrow_exception(error); }
                        catch (...) {}
                    }
                });
        }

        asio::awaitable<void> writeResponse(bool headRequest)
        {
            m_stream.expires_after(m_owner->m_config.writeTimeout());
            boost::system::error_code error;
            if (headRequest) {
                beastHttp::response_serializer<beastHttp::string_body> serializer{*m_response};
                static_cast<void>(co_await beastHttp::async_write_header(
                    m_stream, serializer,
                    asio::redirect_error(asio::use_awaitable, error)));
            } else {
                static_cast<void>(co_await beastHttp::async_write(
                    m_stream, *m_response,
                    asio::redirect_error(asio::use_awaitable, error)));
            }
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
                // Every accepted connection owns a distinct strand. The
                // listener runs multiple reactor threads in production;
                // reads, response writes and socket deadlines must never
                // execute simultaneously on different worker threads.
                Tcp::socket socket = co_await m_acceptor.async_accept(
                    asio::make_strand(m_context),
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


} // namespace openproof::gateway::http
