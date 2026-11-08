#include "async_ldaps.hpp"

#include <boost/asio.hpp>
#include <boost/asio/cancel_after.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/ssl.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace openproof::provider::enterprise::async_detail {
namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace ssl = asio::ssl;
using Tcp = asio::ip::tcp;
using Byte = unsigned char;
using Bytes = std::vector<Byte>;
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

constexpr std::size_t kMaximumLdapFrame = 65536U;
constexpr std::size_t kMaximumAttributes = 16U;
constexpr std::size_t kMaximumAttributeValue = 4096U;
constexpr std::chrono::seconds kTotalDeadline{10};

struct InvalidFrame final {};
struct NetworkError final {};
struct DeadlineExceeded final {};

[[nodiscard]] bool printable(std::string_view text, std::size_t limit) noexcept
{
    return !text.empty() && text.size() <= limit
        && std::all_of(text.begin(), text.end(), [](char c) {
            const auto value = static_cast<unsigned char>(c);
            return value >= 0x20U && value < 0x7fU;
        });
}

[[nodiscard]] std::optional<std::pair<std::string, std::uint16_t>>
parseLdapsUri(std::string_view uri)
{
    constexpr std::string_view scheme{"ldaps://"};
    if (!uri.starts_with(scheme)) return std::nullopt;
    uri.remove_prefix(scheme.size());
    if (uri.empty() || uri.size() > 260U
        || uri.find_first_of("/?#@\\[]") != std::string_view::npos) {
        return std::nullopt;
    }
    std::string_view host = uri;
    std::uint16_t port = 636U;
    if (const auto colon = uri.find(':'); colon != std::string_view::npos) {
        if (uri.find(':', colon + 1U) != std::string_view::npos) return std::nullopt;
        host = uri.substr(0, colon);
        const auto suffix = uri.substr(colon + 1U);
        unsigned int parsed{};
        const auto [end, status] = std::from_chars(
            suffix.data(), suffix.data() + suffix.size(), parsed);
        if (suffix.empty() || status != std::errc{}
            || end != suffix.data() + suffix.size() || parsed == 0U
            || parsed > 65535U) return std::nullopt;
        port = static_cast<std::uint16_t>(parsed);
    }
    if (!printable(host, 253U) || host.starts_with('.')
        || host.ends_with('.') || host.contains("..")) return std::nullopt;
    std::size_t first = 0U;
    for (;;) {
        const auto end = host.find('.', first);
        const auto label = host.substr(first,
            end == std::string_view::npos ? host.size() - first : end - first);
        if (label.empty() || label.size() > 63U
            || label.front() == '-' || label.back() == '-'
            || !std::all_of(label.begin(), label.end(), [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-';
            })) return std::nullopt;
        if (end == std::string_view::npos) break;
        first = end + 1U;
    }
    return std::pair{std::string{host}, port};
}

void length(Bytes& target, std::size_t value)
{
    if (value > kMaximumLdapFrame) throw InvalidFrame{};
    if (value < 128U) {
        target.push_back(static_cast<Byte>(value));
    } else if (value < 256U) {
        target.push_back(0x81U);
        target.push_back(static_cast<Byte>(value));
    } else if (value < 65536U) {
        target.push_back(0x82U);
        target.push_back(static_cast<Byte>(value >> 8U));
        target.push_back(static_cast<Byte>(value));
    } else {
        target.push_back(0x83U);
        target.insert(target.end(), {0x01U, 0x00U, 0x00U});
    }
}

void append(Bytes& target, Byte tag, std::span<const Byte> value)
{
    target.push_back(tag);
    length(target, value.size());
    target.insert(target.end(), value.begin(), value.end());
}

void append(Bytes& target, Byte tag, std::string_view value)
{
    target.push_back(tag);
    length(target, value.size());
    for (const char c : value) target.push_back(static_cast<Byte>(c));
}

void appendInteger(Bytes& target, Byte tag, unsigned int value)
{
    Bytes encoded;
    do {
        encoded.insert(encoded.begin(), static_cast<Byte>(value));
        value >>= 8U;
    } while (value != 0U);
    if ((encoded.front() & 0x80U) != 0U) encoded.insert(encoded.begin(), 0x00U);
    append(target, tag, encoded);
}

[[nodiscard]] Bytes message(unsigned int id, Byte protocol, const Bytes& operation)
{
    Bytes contents;
    appendInteger(contents, 0x02U, id);
    append(contents, protocol, operation);
    Bytes result;
    append(result, 0x30U, contents);
    if (result.size() > kMaximumLdapFrame) throw InvalidFrame{};
    return result;
}

[[nodiscard]] Bytes bindRequest(unsigned int id, std::string_view dn,
                                std::string_view secret)
{
    Bytes operation;
    appendInteger(operation, 0x02U, 3U); // LDAPv3
    append(operation, 0x04U, dn);
    append(operation, 0x80U, secret);    // simple auth [0], not plaintext TCP
    return message(id, 0x60U, operation);
}

[[nodiscard]] Bytes searchRequest(
    std::string_view baseDn, std::string_view usernameAttribute,
    std::string_view username, std::span<const std::string> attributes)
{
    Bytes operation;
    append(operation, 0x04U, baseDn);
    appendInteger(operation, 0x0AU, 2U); // whole subtree
    appendInteger(operation, 0x0AU, 0U); // never dereference aliases
    appendInteger(operation, 0x02U, 2U); // refuse ambiguous identity matches
    appendInteger(operation, 0x02U, 5U); // server-side search time limit
    const Byte allAttributeValues{0U};
    append(operation, 0x01U,
           std::span<const Byte>{&allAttributeValues, 1U}); // typesOnly=false

    // BER equalityMatch encodes the username as an OCTET STRING, not as a
    // concatenated LDAP filter. RFC 4515 filter injection is impossible here.
    Bytes equality;
    append(equality, 0x04U, usernameAttribute);
    append(equality, 0x04U, username);
    append(operation, 0xA3U, equality);
    Bytes names;
    for (const auto& attribute : attributes) append(names, 0x04U, attribute);
    append(operation, 0x30U, names);
    return message(2U, 0x63U, operation);
}

struct Tlv final {
    Byte tag{};
    std::span<const Byte> bytes;
};

class BerReader final {
public:
    explicit BerReader(std::span<const Byte> input) : m_input(input) {}

    [[nodiscard]] bool empty() const noexcept { return m_input.empty(); }

    [[nodiscard]] Tlv take()
    {
        if (m_input.size() < 2U) throw InvalidFrame{};
        const Byte tag = m_input[0];
        std::size_t count = m_input[1];
        std::size_t header = 2U;
        if ((count & 0x80U) != 0U) {
            const auto number = count & 0x7fU;
            if (number == 0U || number > 3U
                || m_input.size() < 2U + number) throw InvalidFrame{};
            count = 0U;
            for (std::size_t i = 0; i < number; ++i) {
                count = (count << 8U) | m_input[2U + i];
            }
            if (count < 128U || count > kMaximumLdapFrame) throw InvalidFrame{};
            header += number;
        }
        if (count > kMaximumLdapFrame || count > m_input.size() - header) {
            throw InvalidFrame{};
        }
        auto bytes = m_input.subspan(header, count);
        m_input = m_input.subspan(header + count);
        return Tlv{tag, bytes};
    }

    [[nodiscard]] std::span<const Byte> expect(Byte tag)
    {
        const Tlv result = take();
        if (result.tag != tag) throw InvalidFrame{};
        return result.bytes;
    }

    [[nodiscard]] unsigned int number(Byte tag)
    {
        const auto value = expect(tag);
        if (value.empty() || value.size() > 4U
            || (value.front() & 0x80U) != 0U) throw InvalidFrame{};
        unsigned int result{};
        for (Byte byte : value) result = (result << 8U) | byte;
        return result;
    }

    [[nodiscard]] std::string text(Byte tag, std::size_t maximum)
    {
        auto value = expect(tag);
        if (value.size() > maximum) throw InvalidFrame{};
        return std::string{value.begin(), value.end()};
    }

private:
    std::span<const Byte> m_input;
};

[[nodiscard]] std::string lowered(std::string_view source)
{
    std::string result{source};
    for (auto& c : result) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return result;
}

struct Pdu final {
    Byte tag{};
    Bytes contents;
};

[[nodiscard]] Pdu decodeMessage(const Bytes& frame, unsigned int id)
{
    BerReader root{frame};
    BerReader messageContents{root.expect(0x30U)};
    if (!root.empty() || messageContents.number(0x02U) != id) {
        throw InvalidFrame{};
    }
    auto operation = messageContents.take();
    // LDAP controls and unsolicited results are not needed for this strict
    // simple-bind subset; reject them rather than silently following a
    // referral or accepting an unexpected server extension.
    if (!messageContents.empty()) throw InvalidFrame{};
    return Pdu{operation.tag, Bytes{operation.bytes.begin(), operation.bytes.end()}};
}

[[nodiscard]] unsigned int ldapResult(std::span<const Byte> body)
{
    BerReader result{body};
    const auto code = result.number(0x0AU); // ENUMERATED resultCode
    static_cast<void>(result.text(0x04U, 2048U)); // matchedDN
    static_cast<void>(result.text(0x04U, 4096U)); // diagnosticMessage
    if (!result.empty()) throw InvalidFrame{};
    return code;
}

struct Entry final {
    std::string dn;
    std::map<std::string, std::string, std::less<>> values;
};

[[nodiscard]] Entry decodeEntry(std::span<const Byte> body)
{
    BerReader result{body};
    Entry entry;
    entry.dn = result.text(0x04U, 2048U);
    if (!printable(entry.dn, 2048U)) throw InvalidFrame{};
    BerReader attributes{result.expect(0x30U)};
    if (!result.empty()) throw InvalidFrame{};
    std::size_t count = 0U;
    while (!attributes.empty()) {
        if (++count > kMaximumAttributes) throw InvalidFrame{};
        BerReader attribute{attributes.expect(0x30U)};
        const std::string name = lowered(attribute.text(0x04U, 128U));
        BerReader values{attribute.expect(0x31U)};
        if (!attribute.empty()) throw InvalidFrame{};
        if (values.empty()) continue;
        const std::string value = values.text(0x04U, kMaximumAttributeValue);
        if (!values.empty() || name.empty()
            || !entry.values.emplace(name, value).second) throw InvalidFrame{};
    }
    return entry;
}

template <typename Stream>
[[nodiscard]] asio::awaitable<void> writeMessage(
    Stream& stream, Bytes outgoing, Deadline deadline, bool sensitive)
{
    if (Clock::now() >= deadline) throw DeadlineExceeded{};
    // The TLS write owns its buffer for the entire suspension. Clear the
    // encoded bind password even if a peer disconnects midway through write.
    struct Eraser final {
        Bytes& bytes;
        bool enabled;
        ~Eraser() noexcept {
            if (enabled) {
                volatile Byte* p = bytes.data();
                for (std::size_t i = 0; i < bytes.size(); ++i) p[i] = 0U;
            }
        }
    } erase{outgoing, sensitive};
    beast::get_lowest_layer(stream).expires_at(deadline);
    boost::system::error_code error;
    co_await asio::async_write(stream, asio::buffer(outgoing),
        asio::redirect_error(asio::use_awaitable, error));
    if (error) throw NetworkError{};
}

template <typename Stream>
[[nodiscard]] asio::awaitable<Bytes> readMessage(Stream& stream, Deadline deadline)
{
    if (Clock::now() >= deadline) throw DeadlineExceeded{};
    Bytes header(2U);
    boost::system::error_code error;
    beast::get_lowest_layer(stream).expires_at(deadline);
    co_await asio::async_read(stream, asio::buffer(header),
        asio::redirect_error(asio::use_awaitable, error));
    if (error) throw NetworkError{};
    if (header[0] != 0x30U) throw InvalidFrame{};
    std::size_t lengthValue = header[1];
    if ((lengthValue & 0x80U) != 0U) {
        const std::size_t count = lengthValue & 0x7FU;
        if (count == 0U || count > 3U) throw InvalidFrame{};
        const auto begin = header.size();
        header.resize(begin + count);
        beast::get_lowest_layer(stream).expires_at(deadline);
        co_await asio::async_read(stream,
            asio::buffer(header.data() + begin, count),
            asio::redirect_error(asio::use_awaitable, error));
        if (error) throw NetworkError{};
        lengthValue = 0U;
        for (std::size_t i = 0; i < count; ++i) {
            lengthValue = (lengthValue << 8U) | header[begin + i];
        }
        if (lengthValue < 128U) throw InvalidFrame{};
    }
    if (lengthValue == 0U || lengthValue > kMaximumLdapFrame
        || lengthValue > kMaximumLdapFrame - header.size()) throw InvalidFrame{};
    const auto begin = header.size();
    header.resize(begin + lengthValue);
    beast::get_lowest_layer(stream).expires_at(deadline);
    co_await asio::async_read(stream,
        asio::buffer(header.data() + begin, lengthValue),
        asio::redirect_error(asio::use_awaitable, error));
    if (error) throw NetworkError{};
    co_return header;
}

template <typename Stream>
[[nodiscard]] asio::awaitable<bool> doBind(
    Stream& stream, unsigned int id, std::string_view dn,
    std::string_view password, Deadline deadline)
{
    co_await writeMessage(stream, bindRequest(id, dn, password), deadline, true);
    auto response = decodeMessage(co_await readMessage(stream, deadline), id);
    if (response.tag != 0x61U) throw InvalidFrame{};
    co_return ldapResult(response.contents) == 0U;
}

template <typename Stream>
[[nodiscard]] asio::awaitable<std::optional<Entry>> searchUnique(
    Stream& stream, const LdapsRequest& request, Deadline deadline)
{
    std::vector<std::string> wanted{request.subjectAttribute};
    if (!request.displayNameAttribute.empty()
        && request.displayNameAttribute != request.subjectAttribute) {
        wanted.push_back(request.displayNameAttribute);
    }
    if (!request.emailAttribute.empty()
        && request.emailAttribute != request.subjectAttribute
        && request.emailAttribute != request.displayNameAttribute) {
        wanted.push_back(request.emailAttribute);
    }
    co_await writeMessage(stream, searchRequest(
        request.baseDn, request.usernameAttribute, request.username, wanted),
        deadline, false);
    std::optional<Entry> found;
    for (;;) {
        const Pdu response =
            decodeMessage(co_await readMessage(stream, deadline), 2U);
        if (response.tag == 0x64U) {
            if (found) co_return std::nullopt; // ambiguous user
            found.emplace(decodeEntry(response.contents));
        } else if (response.tag == 0x65U) {
            if (ldapResult(response.contents) != 0U) {
                co_return std::nullopt; // timeout, sizelimit, referral, etc.
            }
            co_return found;
        } else {
            throw InvalidFrame{}; // no referrals, aliases or extensions
        }
    }
}
} // namespace

SensitiveString::~SensitiveString() noexcept
{
    if (m_value) {
        volatile char* data = m_value->data();
        for (std::size_t i = 0U; i < m_value->size(); ++i) data[i] = '\0';
    }
}

asio::awaitable<LdapsResult> AsyncLdapsClient::authenticate(LdapsRequest request)
{
    const Deadline deadline = Clock::now() + request.timeout;
    const auto endpoint = parseLdapsUri(request.uri);
    if (!endpoint || !printable(request.baseDn, 2048U)
        || !printable(request.username, 320U)
        || request.userPassword.view().empty()
        || request.userPassword.view().size() > 1024U
        || request.timeout <= std::chrono::milliseconds::zero()
        || request.timeout > kTotalDeadline
        || (request.serviceBindDn.empty() != request.servicePassword.view().empty())
        || request.usernameAttribute.empty() || request.subjectAttribute.empty()) {
        co_return LdapsResult{LdapsFailure::InvalidConfiguration};
    }

    try {
        // Constructing the SSL context performs no socket operations; all
        // server I/O is dispatched asynchronously with the same deadline.
        ssl::context tls{ssl::context::tls_client};
        tls.set_verify_mode(ssl::verify_peer);
        if (request.caFile.empty()) tls.set_default_verify_paths();
        else tls.load_verify_file(request.caFile);

        auto executor = co_await asio::this_coro::executor;
        Tcp::resolver resolver{executor};
        boost::system::error_code error;
        auto endpoints = co_await resolver.async_resolve(
            endpoint->first, std::to_string(endpoint->second),
            asio::cancel_after(deadline - Clock::now(),
                asio::redirect_error(asio::use_awaitable, error)));
        if (error || endpoints.empty()) {
            co_return LdapsResult{Clock::now() >= deadline
                ? LdapsFailure::Timeout : LdapsFailure::Connection};
        }

        beast::ssl_stream<beast::tcp_stream> stream{executor, tls};
        if (SSL_ctrl(stream.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                TLSEXT_NAMETYPE_host_name,
                const_cast<char*>(endpoint->first.c_str())) != 1) {
            co_return LdapsResult{LdapsFailure::Certificate};
        }
        stream.set_verify_callback(ssl::host_name_verification(endpoint->first));
        beast::get_lowest_layer(stream).expires_at(deadline);
        static_cast<void>(co_await beast::get_lowest_layer(stream).async_connect(
            endpoints, asio::redirect_error(asio::use_awaitable, error)));
        if (error) co_return LdapsResult{Clock::now() >= deadline
            ? LdapsFailure::Timeout : LdapsFailure::Connection};

        beast::get_lowest_layer(stream).expires_at(deadline);
        co_await stream.async_handshake(ssl::stream_base::client,
            asio::redirect_error(asio::use_awaitable, error));
        if (error) co_return LdapsResult{Clock::now() >= deadline
            ? LdapsFailure::Timeout : LdapsFailure::Certificate};

        if (!(co_await doBind(stream, 1U, request.serviceBindDn,
                             request.servicePassword.view(), deadline))) {
            co_return LdapsResult{LdapsFailure::BindRejected};
        }
        auto entry = co_await searchUnique(stream, request, deadline);
        if (!entry) co_return LdapsResult{LdapsFailure::Unresolved};
        const auto subject = entry->values.find(lowered(request.subjectAttribute));
        if (subject == entry->values.end() || !printable(subject->second, 1024U)) {
            co_return LdapsResult{LdapsFailure::Unresolved};
        }
        // Rebind on the same TLS-authenticated connection. There are no
        // subsequent directory reads under the user's authorization level.
        if (!(co_await doBind(stream, 3U, entry->dn,
                             request.userPassword.view(), deadline))) {
            co_return LdapsResult{LdapsFailure::BindRejected};
        }

        LdapsResult success;
        success.failure = LdapsFailure::None;
        success.subject = subject->second;
        if (!request.displayNameAttribute.empty()) {
            const auto present = entry->values.find(lowered(request.displayNameAttribute));
            if (present != entry->values.end()) success.displayName = present->second;
        }
        if (!request.emailAttribute.empty()) {
            const auto present = entry->values.find(lowered(request.emailAttribute));
            if (present != entry->values.end()) success.email = present->second;
        }
        boost::system::error_code ignored;
        beast::get_lowest_layer(stream).socket().close(ignored);
        co_return success;
    } catch (const DeadlineExceeded&) {
        co_return LdapsResult{LdapsFailure::Timeout};
    } catch (const InvalidFrame&) {
        co_return LdapsResult{LdapsFailure::Protocol};
    } catch (const NetworkError&) {
        co_return LdapsResult{Clock::now() >= deadline
            ? LdapsFailure::Timeout : LdapsFailure::Connection};
    } catch (const std::exception&) {
        co_return LdapsResult{Clock::now() >= deadline
            ? LdapsFailure::Timeout : LdapsFailure::Connection};
    }
}

} // namespace openproof::provider::enterprise::async_detail
