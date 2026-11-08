#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "async_ldaps.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <unistd.h>

namespace {
namespace asio = boost::asio;
namespace ldap = openproof::provider::enterprise::async_detail;
using Tcp = asio::ip::tcp;
using Byte = unsigned char;
using Bytes = std::vector<Byte>;
using namespace std::chrono_literals;

template <typename T, void (*Deleter)(T*)>
struct Owned final {
    explicit Owned(T* value) : ptr(value) {}
    ~Owned() { if (ptr) Deleter(ptr); }
    Owned(const Owned&) = delete;
    Owned& operator=(const Owned&) = delete;
    T* get() const noexcept { return ptr; }
    T* ptr;
};
void freeBio(BIO* ptr) { BIO_free(ptr); }

void append(Bytes& to, Byte tag, const Bytes& body)
{
    to.push_back(tag);
    if (body.size() < 128U) {
        to.push_back(static_cast<Byte>(body.size()));
    } else if (body.size() < 256U) {
        to.push_back(0x81U);
        to.push_back(static_cast<Byte>(body.size()));
    } else {
        to.push_back(0x82U);
        to.push_back(static_cast<Byte>(body.size() >> 8U));
        to.push_back(static_cast<Byte>(body.size()));
    }
    to.insert(to.end(), body.begin(), body.end());
}

void append(Bytes& to, Byte tag, std::string_view value)
{
    Bytes data(value.begin(), value.end());
    append(to, tag, data);
}

void smallNumber(Bytes& to, Byte tag, Byte value)
{
    append(to, tag, Bytes{value});
}

[[nodiscard]] Bytes frame(Byte id, Byte tag, const Bytes& payload)
{
    Bytes elements;
    smallNumber(elements, 0x02U, id);
    append(elements, tag, payload);
    Bytes message;
    append(message, 0x30U, elements);
    return message;
}

[[nodiscard]] Bytes result(Byte id, Byte operationTag, Byte resultCode)
{
    Bytes payload;
    smallNumber(payload, 0x0AU, resultCode);
    append(payload, 0x04U, "");
    append(payload, 0x04U, "");
    return frame(id, operationTag, payload);
}

[[nodiscard]] Bytes attribute(std::string_view name, std::string_view value)
{
    Bytes values;
    append(values, 0x04U, value);
    Bytes body;
    append(body, 0x04U, name);
    append(body, 0x31U, values);
    Bytes item;
    append(item, 0x30U, body);
    return item;
}

[[nodiscard]] Bytes entry(bool hasSubject)
{
    Bytes attrs;
    if (hasSubject) {
        const auto uid = attribute("uid", "directory-user-27");
        attrs.insert(attrs.end(), uid.begin(), uid.end());
    }
    const auto display = attribute("displayName", "A Test Account");
    attrs.insert(attrs.end(), display.begin(), display.end());
    const auto mail = attribute("mail", "test@example.invalid");
    attrs.insert(attrs.end(), mail.begin(), mail.end());

    Bytes body;
    append(body, 0x04U, "uid=testuser,ou=people,dc=example,dc=test");
    append(body, 0x30U, attrs);
    return frame(2U, 0x64U, body);
}

template <typename Stream>
[[nodiscard]] Bytes readFrame(Stream& stream)
{
    std::array<Byte, 2U> first{};
    asio::read(stream, asio::buffer(first));
    if (first[0] != 0x30U) throw std::runtime_error{"bad mock LDAP request"};
    std::size_t size = first[1];
    Bytes output{first.begin(), first.end()};
    if ((size & 0x80U) != 0U) {
        const std::size_t count = size & 0x7fU;
        if (count == 0U || count > 3U) throw std::runtime_error{"bad BER"};
        Bytes countBytes(count);
        asio::read(stream, asio::buffer(countBytes));
        output.insert(output.end(), countBytes.begin(), countBytes.end());
        size = 0U;
        for (Byte value : countBytes) size = (size << 8U) | value;
    }
    if (size > 65536U) throw std::runtime_error{"oversized mock LDAP request"};
    const auto prefix = output.size();
    output.resize(prefix + size);
    asio::read(stream, asio::buffer(output.data() + prefix, size));
    return output;
}

[[nodiscard]] bool contains(const Bytes& input, std::string_view text)
{
    const Bytes target(text.begin(), text.end());
    return std::search(input.begin(), input.end(),
        target.begin(), target.end()) != input.end();
}

struct LocalLdaps final {
    enum class Mode { Good, UserRejected, Ambiguous, MissingSubject,
                      InvalidResult, StallAfterBind, BadBerLength };
    asio::io_context io;
    asio::ssl::context tls{asio::ssl::context::tls_server};
    Tcp::acceptor acceptor{io, Tcp::endpoint{
        asio::ip::address_v4::loopback(), 0}};
    std::thread thread;
    std::string caFile;
    Mode mode{Mode::Good};
    bool observedServiceBind{};
    bool observedSearch{};
    bool observedUserBind{};

    explicit LocalLdaps(Mode behavior = Mode::Good) : mode(behavior)
    {
        Owned<EVP_PKEY, EVP_PKEY_free> key{
            EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")};
        Owned<X509, X509_free> cert{X509_new()};
        if (!key.get() || !cert.get()
            || X509_set_version(cert.get(), 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 9) != 1
            || !X509_gmtime_adj(X509_getm_notBefore(cert.get()), -30)
            || !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600)
            || X509_set_pubkey(cert.get(), key.get()) != 1) {
            throw std::runtime_error{"LDAP fixture certificate generation failed"};
        }
        X509_NAME* subject = X509_get_subject_name(cert.get());
        if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>("localhost"),
                -1, -1, 0) != 1
            || X509_set_issuer_name(cert.get(), subject) != 1) {
            throw std::runtime_error{"LDAP fixture subject failed"};
        }
        X509V3_CTX context;
        X509V3_set_ctx(&context, cert.get(), cert.get(), nullptr, nullptr, 0);
        Owned<X509_EXTENSION, X509_EXTENSION_free> san{
            X509V3_EXT_conf_nid(nullptr, &context, NID_subject_alt_name,
                                const_cast<char*>("DNS:localhost"))};
        if (!san.get() || X509_add_ext(cert.get(), san.get(), -1) != 1
            || X509_sign(cert.get(), key.get(), nullptr) <= 0
            || SSL_CTX_use_certificate(tls.native_handle(), cert.get()) != 1
            || SSL_CTX_use_PrivateKey(tls.native_handle(), key.get()) != 1) {
            throw std::runtime_error{"LDAP fixture TLS policy failed"};
        }

        Owned<BIO, freeBio> encoded{BIO_new(BIO_s_mem())};
        if (!encoded.get() || PEM_write_bio_X509(encoded.get(), cert.get()) != 1) {
            throw std::runtime_error{"LDAP fixture certificate encoding failed"};
        }
        BUF_MEM* body = nullptr;
        BIO_get_mem_ptr(encoded.get(), &body);
        if (!body || !body->data || body->length == 0U) {
            throw std::runtime_error{"LDAP fixture certificate empty"};
        }
        char name[] = "/tmp/openproof-ldaps-ca-XXXXXX";
        const int fd = mkstemp(name);
        if (fd < 0) throw std::runtime_error{"LDAP test CA file failed"};
        close(fd);
        caFile.assign(name);
        std::ofstream ca{caFile, std::ios::binary};
        ca.write(body->data, static_cast<std::streamsize>(body->length));
        ca.close();
        if (!ca.good()) throw std::runtime_error{"LDAP test CA write failed"};
    }

    ~LocalLdaps()
    {
        boost::system::error_code ignored;
        acceptor.close(ignored);
        if (thread.joinable()) thread.join();
        if (!caFile.empty()) std::filesystem::remove(caFile);
    }

    [[nodiscard]] std::uint16_t port() const
    {
        return acceptor.local_endpoint().port();
    }

    void start()
    {
        thread = std::thread{[this] {
            try {
                Tcp::socket socket{io};
                acceptor.accept(socket);
                asio::ssl::stream<Tcp::socket> stream{
                    std::move(socket), tls};
                stream.handshake(asio::ssl::stream_base::server);
                const auto service = readFrame(stream);
                observedServiceBind = contains(service, "service-secret")
                    && contains(service, "cn=service");
                if (mode == Mode::StallAfterBind) {
                    std::this_thread::sleep_for(250ms);
                    return;
                }
                if (mode == Mode::InvalidResult) {
                    const auto malformed = result(77U, 0x61U, 0U);
                    asio::write(stream, asio::buffer(malformed));
                    return;
                }
                if (mode == Mode::BadBerLength) {
                    const std::array<Byte, 2U> malicious{0x30U, 0x84U};
                    asio::write(stream, asio::buffer(malicious));
                    return;
                }
                const auto bound = result(1U, 0x61U, 0U);
                asio::write(stream, asio::buffer(bound));
                const auto search = readFrame(stream);
                observedSearch = contains(search, "testuser")
                    && contains(search, "uid")
                    && contains(search, "ou=people,dc=example,dc=test");
                const auto entryMessage = entry(mode != Mode::MissingSubject);
                asio::write(stream, asio::buffer(entryMessage));
                if (mode == Mode::Ambiguous) {
                    asio::write(stream, asio::buffer(entryMessage));
                    return;
                }
                const auto done = result(2U, 0x65U, 0U);
                asio::write(stream, asio::buffer(done));
                if (mode == Mode::MissingSubject) return;
                const auto user = readFrame(stream);
                observedUserBind = contains(user, "user-secret")
                    && contains(user, "uid=testuser,ou=people,dc=example,dc=test");
                const auto reply = result(3U, 0x61U,
                    mode == Mode::UserRejected ? 49U : 0U);
                asio::write(stream, asio::buffer(reply));
            } catch (const std::exception&) {
                // Closing a one-shot client early is expected in negative tests.
            }
        }};
    }
};

[[nodiscard]] ldap::LdapsRequest request(
    const LocalLdaps& server, bool pinned = true)
{
    return ldap::LdapsRequest{
        "ldaps://localhost:" + std::to_string(server.port()),
        "ou=people,dc=example,dc=test",
        "uid",
        "uid",
        "displayName",
        "mail",
        "cn=service",
        ldap::SensitiveString{"service-secret"},
        "testuser",
        ldap::SensitiveString{"user-secret"},
        pinned ? server.caFile : std::string{}
    };
}

[[nodiscard]] ldap::LdapsResult execute(ldap::LdapsRequest request)
{
    asio::io_context io;
    auto completion = asio::co_spawn(io,
        ldap::AsyncLdapsClient::authenticate(std::move(request)),
        asio::use_future);
    io.run();
    return completion.get();
}
} // namespace

TEST(AsyncLdapsTest, VerifiedTlsBindSearchAndUserRebindAreNative)
{
    LocalLdaps server;
    server.start();
    const auto result = execute(request(server));
    ASSERT_TRUE(result.success());
    EXPECT_EQ(result.failure, ldap::LdapsFailure::None);
    EXPECT_EQ(result.subject, "directory-user-27");
    EXPECT_EQ(result.displayName, "A Test Account");
    EXPECT_EQ(result.email, "test@example.invalid");
    if (server.thread.joinable()) server.thread.join();
    EXPECT_TRUE(server.observedServiceBind);
    EXPECT_TRUE(server.observedSearch);
    EXPECT_TRUE(server.observedUserBind);
}

TEST(AsyncLdapsTest, InvalidUserBindCannotAuthenticate)
{
    LocalLdaps server{LocalLdaps::Mode::UserRejected};
    server.start();
    const auto result = execute(request(server));
    EXPECT_FALSE(result.success());
    EXPECT_EQ(result.failure, ldap::LdapsFailure::BindRejected);
}

TEST(AsyncLdapsTest, AmbiguousSearchNeverBindsUser)
{
    LocalLdaps server{LocalLdaps::Mode::Ambiguous};
    server.start();
    const auto result = execute(request(server));
    EXPECT_FALSE(result.success());
    EXPECT_EQ(result.failure, ldap::LdapsFailure::Unresolved);
    if (server.thread.joinable()) server.thread.join();
    EXPECT_FALSE(server.observedUserBind);
}

TEST(AsyncLdapsTest, MissingStableSubjectNeverBindsUser)
{
    LocalLdaps server{LocalLdaps::Mode::MissingSubject};
    server.start();
    const auto result = execute(request(server));
    EXPECT_FALSE(result.success());
    EXPECT_EQ(result.failure, ldap::LdapsFailure::Unresolved);
    if (server.thread.joinable()) server.thread.join();
    EXPECT_FALSE(server.observedUserBind);
}

TEST(AsyncLdapsTest, UntrustedCertificateIsNotAccepted)
{
    LocalLdaps server;
    server.start();
    const auto result = execute(request(server, false));
    EXPECT_FALSE(result.success());
    EXPECT_EQ(result.failure, ldap::LdapsFailure::Certificate);
}

TEST(AsyncLdapsTest, InvalidMessageIdIsRejected)
{
    LocalLdaps server{LocalLdaps::Mode::InvalidResult};
    server.start();
    const auto result = execute(request(server));
    EXPECT_FALSE(result.success());
    EXPECT_EQ(result.failure, ldap::LdapsFailure::Protocol);
}

TEST(AsyncLdapsTest, OversizedLengthPrefixIsRejected)
{
    LocalLdaps server{LocalLdaps::Mode::BadBerLength};
    server.start();
    const auto result = execute(request(server));
    EXPECT_FALSE(result.success());
    EXPECT_EQ(result.failure, ldap::LdapsFailure::Protocol);
}

TEST(AsyncLdapsTest, NativeTimeoutCannotBlockOnSlowDirectory)
{
    LocalLdaps server{LocalLdaps::Mode::StallAfterBind};
    server.start();
    auto proof = request(server);
    proof.timeout = 50ms;
    const auto started = std::chrono::steady_clock::now();
    const auto result = execute(std::move(proof));
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_FALSE(result.success());
    EXPECT_EQ(result.failure, ldap::LdapsFailure::Timeout);
    EXPECT_LT(elapsed, 200ms);
}

TEST(AsyncLdapsTest, UntrustedUriAndDeadlineFailWithoutNetworking)
{
    LocalLdaps server;
    auto invalid = request(server);
    invalid.uri = "ldap://localhost:636";
    EXPECT_EQ(execute(std::move(invalid)).failure,
              ldap::LdapsFailure::InvalidConfiguration);
    auto timeout = request(server);
    timeout.timeout = 0ms;
    EXPECT_EQ(execute(std::move(timeout)).failure,
              ldap::LdapsFailure::InvalidConfiguration);
}
