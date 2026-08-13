module;

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

export module openproof.gateway.http;

import openproof.foundation;
import openproof.gateway;

export namespace openproof::gateway::http {

class ServerConfig final {
public:
    [[nodiscard]] static foundation::Result<ServerConfig>
    create(std::string bindAddress, std::uint16_t port,
           std::size_t headerLimitBytes, std::size_t bodyLimitBytes,
           foundation::Duration readTimeout, foundation::Duration writeTimeout,
           std::size_t maximumConnections, std::size_t workerThreads,
           bool trustProxyClientIp = false);

    [[nodiscard]] std::string_view bindAddress() const noexcept;
    [[nodiscard]] std::uint16_t port() const noexcept;
    [[nodiscard]] std::size_t headerLimitBytes() const noexcept;
    [[nodiscard]] std::size_t bodyLimitBytes() const noexcept;
    [[nodiscard]] foundation::Duration readTimeout() const noexcept;
    [[nodiscard]] foundation::Duration writeTimeout() const noexcept;
    [[nodiscard]] std::size_t maximumConnections() const noexcept;
    [[nodiscard]] std::size_t workerThreads() const noexcept;
    [[nodiscard]] bool trustProxyClientIp() const noexcept;

private:
    ServerConfig(std::string bindAddress, std::uint16_t port,
                 std::size_t headerLimitBytes, std::size_t bodyLimitBytes,
                 foundation::Duration readTimeout, foundation::Duration writeTimeout,
                 std::size_t maximumConnections, std::size_t workerThreads,
                 bool trustProxyClientIp);
    std::string m_bindAddress;
    std::uint16_t m_port{};
    std::size_t m_headerLimitBytes{};
    std::size_t m_bodyLimitBytes{};
    foundation::Duration m_readTimeout{};
    foundation::Duration m_writeTimeout{};
    std::size_t m_maximumConnections{};
    std::size_t m_workerThreads{};
    bool m_trustProxyClientIp{};
};

class BeastHttpServer final {
public:
    BeastHttpServer(HttpHandler& handler, ServerConfig config);
    BeastHttpServer(const BeastHttpServer&) = delete;
    BeastHttpServer& operator=(const BeastHttpServer&) = delete;
    BeastHttpServer(BeastHttpServer&&) = delete;
    BeastHttpServer& operator=(BeastHttpServer&&) = delete;
    ~BeastHttpServer();

    /**
     * Opens the listener and starts workers. Port 0 asks the OS for an ephemeral
     * port. A server instance is intentionally single-start; construct a new
     * instance after stop so stale asynchronous handlers cannot be revived.
     */
    [[nodiscard]] foundation::Status start();
    void stop() noexcept;
    [[nodiscard]] bool running() const noexcept;
    [[nodiscard]] std::uint16_t boundPort() const noexcept;

private:
    class Implementation;
    std::unique_ptr<Implementation> m_implementation;
};

class ProxyConfig final {
public:
    [[nodiscard]] static foundation::Result<ProxyConfig>
    create(std::size_t responseHeaderLimitBytes,
           std::size_t responseBodyLimitBytes, std::string caFile = {});
    [[nodiscard]] std::size_t responseHeaderLimitBytes() const noexcept;
    [[nodiscard]] std::size_t responseBodyLimitBytes() const noexcept;
    [[nodiscard]] std::string_view caFile() const noexcept;
private:
    ProxyConfig(std::size_t responseHeaderLimitBytes,
                std::size_t responseBodyLimitBytes, std::string caFile);
    std::size_t m_responseHeaderLimitBytes{};
    std::size_t m_responseBodyLimitBytes{};
    std::string m_caFile;
};

class BeastProxyTransport final : public ProxyTransport {
public:
    [[nodiscard]] static foundation::Result<std::unique_ptr<BeastProxyTransport>>
    create(ProxyConfig config);
    BeastProxyTransport(const BeastProxyTransport&) = delete;
    BeastProxyTransport& operator=(const BeastProxyTransport&) = delete;
    ~BeastProxyTransport() override;

    [[nodiscard]] foundation::Result<HttpResponse>
    send(const Endpoint& endpoint, const HttpRequest& request,
         foundation::Duration timeout) override;

private:
    class Implementation;
    explicit BeastProxyTransport(std::unique_ptr<Implementation> implementation);
    std::unique_ptr<Implementation> m_implementation;
};

}
