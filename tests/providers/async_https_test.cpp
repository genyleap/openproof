#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "async_https.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <unistd.h>

namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace wire = beast::http;
namespace pghttp = openproof::provider::http::async_detail;
using Tcp = asio::ip::tcp;
using namespace std::chrono_literals;

template <typename T, void(*Cleanup)(T*)>
struct Owned final {
    explicit Owned(T* ptr) : value(ptr) {}
    ~Owned() { if (value) Cleanup(value); }
    Owned(const Owned&) = delete;
    Owned& operator=(const Owned&) = delete;
    T* get() const noexcept { return value; }
    T* value;
};

void freeBio(BIO* ptr) { BIO_free(ptr); }

struct LocalTlsServer final {
    asio::io_context io;
    asio::ssl::context tls{asio::ssl::context::tls_server};
    Tcp::acceptor acceptor{io, Tcp::endpoint{asio::ip::address_v4::loopback(), 0}};
    std::thread thread;
    std::string caFile;
    bool observedRequest{};
    std::string observedAuthorization;
    unsigned int replyStatus{200U};
    std::string replyBody{"{\"provider\":\"isolated\"}"};
    std::chrono::milliseconds replyDelay{0};

    LocalTlsServer()
    {
        // In-memory test-only identity generated for each test. No reusable
        // private key is checked into the protocol repository.
        Owned<EVP_PKEY, EVP_PKEY_free> key{
            EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")};
        Owned<X509, X509_free> certificate{X509_new()};
        if (!key.get() || !certificate.get()
            || X509_set_version(certificate.get(), 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 7) != 1
            || !X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -30)
            || !X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600)
            || X509_set_pubkey(certificate.get(), key.get()) != 1) {
            throw std::runtime_error{"TLS test certificate creation failed"};
        }
        X509_NAME* subject = X509_get_subject_name(certificate.get());
        if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>("localhost"),
                -1, -1, 0) != 1
            || X509_set_issuer_name(certificate.get(), subject) != 1) {
            throw std::runtime_error{"TLS test certificate subject failed"};
        }
        X509V3_CTX context;
        X509V3_set_ctx(&context, certificate.get(), certificate.get(),
                       nullptr, nullptr, 0);
        Owned<X509_EXTENSION, X509_EXTENSION_free> san{
            X509V3_EXT_conf_nid(nullptr, &context, NID_subject_alt_name,
                                const_cast<char*>("DNS:localhost"))};
        if (!san.get() || X509_add_ext(certificate.get(), san.get(), -1) != 1
            || X509_sign(certificate.get(), key.get(), nullptr) <= 0
            || SSL_CTX_use_certificate(tls.native_handle(), certificate.get()) != 1
            || SSL_CTX_use_PrivateKey(tls.native_handle(), key.get()) != 1) {
            throw std::runtime_error{"TLS test identity configuration failed"};
        }

        Owned<BIO, freeBio> encoded{BIO_new(BIO_s_mem())};
        if (!encoded.get()
            || PEM_write_bio_X509(encoded.get(), certificate.get()) != 1) {
            throw std::runtime_error{"TLS test public certificate encoding failed"};
        }
        BUF_MEM* data = nullptr;
        BIO_get_mem_ptr(encoded.get(), &data);
        if (!data || !data->data || !data->length) {
            throw std::runtime_error{"TLS test public certificate is empty"};
        }
        char templatePath[] = "/tmp/openproof-https-ca-XXXXXX";
        const int fd = mkstemp(templatePath);
        if (fd < 0) throw std::runtime_error{"TLS test certificate file failed"};
        close(fd);
        caFile.assign(templatePath);
        std::ofstream file{caFile, std::ios::binary};
        file.write(data->data, static_cast<std::streamsize>(data->length));
        file.close();
        if (!file.good()) {
            throw std::runtime_error{"TLS test certificate save failed"};
        }
    }

    ~LocalTlsServer()
    {
        boost::system::error_code ignored;
        acceptor.close(ignored);
        if (thread.joinable()) thread.join();
        if (!caFile.empty()) std::filesystem::remove(caFile);
    }

    std::uint16_t port() const
    {
        return acceptor.local_endpoint().port();
    }

    void start()
    {
        thread = std::thread{[this] {
            try {
                Tcp::socket socket{io};
                acceptor.accept(socket);
                asio::ssl::stream<Tcp::socket> stream{std::move(socket), tls};
                boost::system::error_code error;
                stream.handshake(asio::ssl::stream_base::server, error);
                if (error) return;
                beast::flat_buffer buffer;
                wire::request<wire::string_body> request;
                wire::read(stream, buffer, request, error);
                if (error) return;
                observedRequest = true;
                const auto authorization =
                    request[wire::field::authorization];
                observedAuthorization.assign(
                    authorization.data(), authorization.size());
                if (replyDelay > 0ms) std::this_thread::sleep_for(replyDelay);
                wire::response<wire::string_body> response{
                    static_cast<wire::status>(replyStatus), request.version()};
                response.set(wire::field::content_type, "application/json");
                if (replyStatus == 302U) {
                    response.set(wire::field::location, "https://other.invalid/path");
                }
                response.body() = replyBody;
                response.keep_alive(false);
                response.prepare_payload();
                wire::write(stream, response, error);
                stream.shutdown(error);
            } catch (const std::exception&) {
                // The client assertion captures the sanitized network failure.
            }
        }};
    }
};

[[nodiscard]] pghttp::HttpsResult execute(
    pghttp::AsyncHttpsClient& client, pghttp::HttpsRequest request)
{
    asio::io_context io;
    auto task = asio::co_spawn(
        io, client.exchange(std::move(request)), asio::use_future);
    io.run();
    return task.get();
}

pghttp::HttpsRequest loopback(std::uint16_t port)
{
    pghttp::HttpsRequest request;
    request.host = "localhost";
    request.port = port;
    request.target = "/oauth/test";
    request.timeout = 2000ms;
    return request;
}
} // namespace

TEST(AsyncProviderHttpsTest, HostAndHeaderInjectionAreRejectedBeforeNetwork)
{
    pghttp::AsyncHttpsClient client;
    auto req = loopback(443);
    req.host = "localhost\\evil";
    EXPECT_EQ(execute(client, req).failure,
              pghttp::HttpsFailure::InvalidRequest);
    req.host = "localhost";
    req.headers.emplace_back("Authorization", "Bearer secret\r\nInjected: true");
    EXPECT_EQ(execute(client, req).failure,
              pghttp::HttpsFailure::InvalidRequest);
    req.headers.clear();
    req.headers.emplace_back("Host", "attacker.example");
    EXPECT_EQ(execute(client, req).failure,
              pghttp::HttpsFailure::InvalidRequest);
    req.headers.clear();
    req.headers.emplace_back("Transfer-Encoding", "chunked");
    EXPECT_EQ(execute(client, req).failure,
              pghttp::HttpsFailure::InvalidRequest);
    req.headers.clear();
    req.headers.emplace_back("authorization", "Bearer first");
    req.headers.emplace_back("Authorization", "Bearer second");
    EXPECT_EQ(execute(client, req).failure,
              pghttp::HttpsFailure::InvalidRequest);
    req.headers.clear();
    req.target = "https://other.example/";
    EXPECT_EQ(execute(client, req).failure,
              pghttp::HttpsFailure::InvalidRequest);
}

TEST(AsyncProviderHttpsTest, InvalidLimitsFailClosed)
{
    EXPECT_THROW((pghttp::AsyncHttpsClient{"", 0, 32768}), std::invalid_argument);
    EXPECT_THROW((pghttp::AsyncHttpsClient{"", 1024, 512}), std::invalid_argument);
    pghttp::AsyncHttpsClient client;
    auto req = loopback(443);
    req.method = pghttp::HttpsRequest::Method::Get;
    req.body = "forbidden GET payload";
    EXPECT_EQ(execute(client, req).failure,
              pghttp::HttpsFailure::InvalidRequest);
    req.body.clear();
    req.timeout = 0ms;
    EXPECT_EQ(execute(client, req).failure,
              pghttp::HttpsFailure::InvalidRequest);
}

TEST(AsyncProviderHttpsTest, NativeLoopbackTlsWithPinnedTestCa)
{
    LocalTlsServer server;
    server.start();
    pghttp::AsyncHttpsClient client{server.caFile};
    auto request = loopback(server.port());
    request.method = pghttp::HttpsRequest::Method::Post;
    request.headers.emplace_back("authorization", "Bearer test-only");
    request.headers.emplace_back("content-type", "application/json");
    request.body = "{\"code\":\"local-test\"}";
    auto result = execute(client, std::move(request));
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.failure, pghttp::HttpsFailure::None);
    EXPECT_EQ(result.response.status, 200U);
    EXPECT_EQ(result.response.body, "{\"provider\":\"isolated\"}");
    if (server.thread.joinable()) server.thread.join();
    EXPECT_TRUE(server.observedRequest);
    EXPECT_EQ(server.observedAuthorization, "Bearer test-only");
}

TEST(AsyncProviderHttpsTest, UntrustedLoopbackCertificateCannotBeAccepted)
{
    LocalTlsServer server;
    server.start();
    pghttp::AsyncHttpsClient client;
    const auto result = execute(client, loopback(server.port()));
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, pghttp::HttpsFailure::Certificate);
}

TEST(AsyncProviderHttpsTest, OversizedResponseIsRejectedWithoutReturningBody)
{
    LocalTlsServer server;
    server.replyBody.assign(2048U, 'X');
    server.start();
    pghttp::AsyncHttpsClient client{server.caFile, 512U, 32768U};
    const auto result = execute(client, loopback(server.port()));
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, pghttp::HttpsFailure::ResponseLimit);
    EXPECT_TRUE(result.response.body.empty());
}

TEST(AsyncProviderHttpsTest, RedirectIsReturnedButNeverFollowed)
{
    LocalTlsServer server;
    server.replyStatus = 302U;
    server.start();
    pghttp::AsyncHttpsClient client{server.caFile};
    const auto result = execute(client, loopback(server.port()));
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.failure, pghttp::HttpsFailure::None);
    EXPECT_EQ(result.response.status, 302U);
    if (server.thread.joinable()) server.thread.join();
    EXPECT_TRUE(server.observedRequest);
}

TEST(AsyncProviderHttpsTest, SlowTlsPeerUsesEndToEndDeadline)
{
    LocalTlsServer server;
    server.replyDelay = 250ms;
    server.start();
    pghttp::AsyncHttpsClient client{server.caFile};
    auto request = loopback(server.port());
    request.timeout = 40ms;
    const auto started = std::chrono::steady_clock::now();
    const auto result = execute(client, std::move(request));
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failure, pghttp::HttpsFailure::Timeout);
    // The client must not wait on an upstream that has not responded yet.
    EXPECT_LT(elapsed, 200ms);
}
