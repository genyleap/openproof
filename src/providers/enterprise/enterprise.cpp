module;

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if OPENPROOF_PLATFORM_APPLE
#include <LDAP/ldap.h>
#else
#include <ldap.h>
#endif
#include <libxml/c14n.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <zlib.h>

#include "presentation.hpp"

module openproof.provider.enterprise;

import openproof.security;

namespace openproof::provider::enterprise {
namespace {

namespace idp = identity::provider;
using namespace std::chrono_literals;

constexpr std::string_view kSamlProtocol{"urn:oasis:names:tc:SAML:2.0:protocol"};
constexpr std::string_view kSamlAssertion{"urn:oasis:names:tc:SAML:2.0:assertion"};
constexpr std::string_view kXmlDsig{"http://www.w3.org/2000/09/xmldsig#"};
constexpr std::string_view kExclusiveC14n{"http://www.w3.org/2001/10/xml-exc-c14n#"};
constexpr std::string_view kRsaSha256{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"};
constexpr std::string_view kSha256{"http://www.w3.org/2001/04/xmlenc#sha256"};
constexpr std::string_view kEnvelopedSignature{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"};
constexpr std::string_view kSamlSuccess{"urn:oasis:names:tc:SAML:2.0:status:Success"};

[[nodiscard]] foundation::Error authenticationFailure(std::string detail)
{
    return foundation::Error{foundation::ErrorCode::AuthenticationFailed,
        std::string{foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
        std::move(detail)};
}

[[nodiscard]] bool safeToken(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::all_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte >= 0x21U && byte <= 0x7EU;
           });
}

[[nodiscard]] bool safeAttribute(std::string_view value) noexcept
{
    if (value.empty() || value.size() > 128U) return false;
    return std::ranges::all_of(value, [](char symbol) {
        const auto byte = static_cast<unsigned char>(symbol);
        return std::isalnum(byte) != 0 || symbol == '-' || symbol == '_' || symbol == '.';
    });
}

[[nodiscard]] bool safeLdapText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] bool validLdapHost(std::string_view value) noexcept
{
    if (!safeLdapText(value, 253U) || value.starts_with('.') || value.ends_with('.')
        || value.contains("..")) {
        return false;
    }
    std::size_t begin = 0U;
    while (begin < value.size()) {
        const auto end = value.find('.', begin);
        const auto label = value.substr(
            begin, end == std::string_view::npos ? value.size() - begin : end - begin);
        if (label.empty() || label.size() > 63U || label.starts_with('-') || label.ends_with('-')
            || !std::ranges::all_of(label, [](char symbol) {
                   return (symbol >= 'A' && symbol <= 'Z')
                       || (symbol >= 'a' && symbol <= 'z')
                       || (symbol >= '0' && symbol <= '9') || symbol == '-';
               })) {
            return false;
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return true;
}

[[nodiscard]] bool validLdapsUri(std::string_view value) noexcept
{
    constexpr std::string_view scheme{"ldaps://"};
    if (!value.starts_with(scheme) || value.size() > 2048U
        || std::ranges::any_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte <= 0x20U || byte == 0x7FU;
           })) {
        return false;
    }
    value.remove_prefix(scheme.size());
    if (value.empty() || value.contains('/') || value.contains('?') || value.contains('#')
        || value.contains('@') || value.contains('\\') || value.contains('[')
        || value.contains(']')) {
        return false;
    }

    std::string_view host = value;
    if (const auto colon = value.rfind(':'); colon != std::string_view::npos) {
        if (value.find(':') != colon) return false;
        host = value.substr(0U, colon);
        const auto portText = value.substr(colon + 1U);
        unsigned int port{};
        const auto parsed = std::from_chars(
            portText.data(), portText.data() + portText.size(), port);
        if (portText.empty() || parsed.ec != std::errc{}
            || parsed.ptr != portText.data() + portText.size()
            || port == 0U || port > 65535U) {
            return false;
        }
    }
    return validLdapHost(host);
}

[[nodiscard]] bool validLdapDn(std::string_view value) noexcept
{
    if (!safeLdapText(value, 2048U)) return false;
    std::string storage{value};
    LDAPDN parsed = nullptr;
    const int result = ldap_str2dn(storage.c_str(), &parsed, LDAP_DN_FORMAT_LDAPV3);
    if (parsed != nullptr) ldap_dnfree(parsed);
    return result == LDAP_SUCCESS;
}

[[nodiscard]] bool validHttpsEndpoint(std::string_view value) noexcept
{
    constexpr std::string_view scheme{"https://"};
    if (!value.starts_with(scheme) || !safeToken(value, 2048U)
        || value.contains('#') || value.contains('\\')) {
        return false;
    }

    value.remove_prefix(scheme.size());
    const auto slash = value.find('/');
    const auto query = value.find('?');
    const auto authorityEnd = std::min(
        slash == std::string_view::npos ? value.size() : slash,
        query == std::string_view::npos ? value.size() : query);
    const auto authority = value.substr(0U, authorityEnd);
    if (authority.empty() || authority.contains('@')
        || authority.contains('[') || authority.contains(']')) {
        return false;
    }

    std::string_view host = authority;
    if (const auto colon = authority.rfind(':'); colon != std::string_view::npos) {
        host = authority.substr(0U, colon);
        const auto portText = authority.substr(colon + 1U);
        unsigned int port{};
        const auto parsed = std::from_chars(
            portText.data(), portText.data() + portText.size(), port);
        if (portText.empty() || parsed.ec != std::errc{}
            || parsed.ptr != portText.data() + portText.size()
            || port == 0U || port > 65535U) {
            return false;
        }
    }

    if (!safeToken(host, 253U) || host.contains(':')) return false;
    if (authorityEnd == value.size()) return true;
    return value[authorityEnd] == '/' || value[authorityEnd] == '?';
}

[[nodiscard]] std::string escapeLdapFilter(std::string_view value)
{
    constexpr char hex[] = "0123456789abcdef";
    std::string output;
    output.reserve(value.size() * 3U);
    for (const char symbol : value) {
        const auto byte = static_cast<unsigned char>(symbol);
        const bool escape = byte == '*' || byte == '(' || byte == ')' || byte == '\\'
            || byte == 0U || byte < 0x20U || byte == 0x7FU;
        if (!escape) {
            output.push_back(static_cast<char>(byte));
            continue;
        }
        output.push_back('\\');
        output.push_back(hex[(byte >> 4U) & 0x0FU]);
        output.push_back(hex[byte & 0x0FU]);
    }
    return output;
}

#if OPENPROOF_PLATFORM_APPLE && defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

struct LdapDeleter final {
    void operator()(LDAP* handle) const noexcept
    {
        if (handle != nullptr) {
            (void)ldap_unbind_ext_s(handle, nullptr, nullptr);
        }
    }
};
using LdapPtr = std::unique_ptr<LDAP, LdapDeleter>;

struct LdapMessageDeleter final {
    void operator()(LDAPMessage* value) const noexcept
    {
        if (value != nullptr) {
            (void)ldap_msgfree(value);
        }
    }
};
using LdapMessagePtr = std::unique_ptr<LDAPMessage, LdapMessageDeleter>;

struct BerValuesDeleter final {
    void operator()(berval** values) const noexcept
    {
        if (values != nullptr) {
            ldap_value_free_len(values);
        }
    }
};
using BerValuesPtr = std::unique_ptr<berval*, BerValuesDeleter>;

struct LdapMemDeleter final {
    void operator()(char* value) const noexcept
    {
        if (value != nullptr) {
            ldap_memfree(value);
        }
    }
};
using LdapStringPtr = std::unique_ptr<char, LdapMemDeleter>;

struct LdapResolvedEntry final {
    LdapMessagePtr result;
    LDAPMessage* entry{};
    LdapStringPtr distinguishedName;
};

[[nodiscard]] foundation::Result<LdapPtr> openLdap(const LdapProviderConfig& config)
{
    LDAP* raw = nullptr;
    const std::string uri{config.uri()};
    if (ldap_initialize(&raw, uri.c_str()) != LDAP_SUCCESS || raw == nullptr) {
        return foundation::fail(foundation::ErrorCode::Unavailable,
                                "Unable to initialize the LDAP connection.");
    }

    LdapPtr handle{raw};
    int version = LDAP_VERSION3;
    int requireCertificate = LDAP_OPT_X_TLS_DEMAND;
    timeval networkTimeout{5, 0};
    timeval operationTimeout{5, 0};
    if (ldap_set_option(handle.get(), LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_OPT_SUCCESS
        || ldap_set_option(handle.get(), LDAP_OPT_NETWORK_TIMEOUT, &networkTimeout) != LDAP_OPT_SUCCESS
        || ldap_set_option(handle.get(), LDAP_OPT_TIMEOUT, &operationTimeout) != LDAP_OPT_SUCCESS
        || ldap_set_option(handle.get(), LDAP_OPT_X_TLS_REQUIRE_CERT, &requireCertificate) != LDAP_OPT_SUCCESS) {
        return foundation::fail(foundation::ErrorCode::Internal,
                                "Unable to configure the LDAP TLS policy.");
    }

    if (!config.caFile().empty()) {
        const std::string caFile{config.caFile()};
        if (ldap_set_option(handle.get(), LDAP_OPT_X_TLS_CACERTFILE, caFile.c_str()) != LDAP_OPT_SUCCESS) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "Unable to configure the LDAP CA file.");
        }
    }

    return handle;
}

[[nodiscard]] foundation::Status simpleBind(LDAP* handle, std::string_view dn,
                                             std::string_view password)
{
    std::string dnStorage{dn};
    std::string passwordStorage{password};
    berval credential{passwordStorage.size(), passwordStorage.data()};
    const char* bindDn = dnStorage.empty() ? nullptr : dnStorage.c_str();
    const int result = ldap_sasl_bind_s(handle, bindDn, LDAP_SASL_SIMPLE,
                                        &credential, nullptr, nullptr, nullptr);
    if (result != LDAP_SUCCESS) {
        return foundation::fail(authenticationFailure("The LDAP bind was rejected."));
    }
    return foundation::ok();
}

[[nodiscard]] std::optional<std::string> ldapValue(LDAP* handle, LDAPMessage* entry,
                                                    std::string_view attribute)
{
    const std::string attributeName{attribute};
    BerValuesPtr values{ldap_get_values_len(handle, entry, attributeName.c_str())};
    if (!values || values.get()[0] == nullptr || values.get()[1] != nullptr) {
        return std::nullopt;
    }

    const auto* value = values.get()[0];
    if (value->bv_len == 0U || value->bv_len > 4096U) {
        return std::nullopt;
    }
    return std::string{value->bv_val, value->bv_len};
}

[[nodiscard]] foundation::Result<LdapResolvedEntry> findUniqueLdapEntry(
    LDAP* handle, std::string_view baseDn, std::string_view filter,
    std::span<char*> attributes)
{
    const std::string baseDnStorage{baseDn};
    const std::string filterStorage{filter};
    LDAPMessage* rawResult = nullptr;
    timeval timeout{5, 0};
    const int searchResult = ldap_search_ext_s(
        handle, baseDnStorage.c_str(), LDAP_SCOPE_SUBTREE, filterStorage.c_str(),
        attributes.data(), 0, nullptr, nullptr, &timeout, 2, &rawResult);

    LdapMessagePtr result{rawResult};
    if (searchResult != LDAP_SUCCESS || !result
        || ldap_count_entries(handle, result.get()) != 1) {
        return foundation::fail(authenticationFailure(
            "The LDAP identity could not be uniquely resolved."));
    }

    LDAPMessage* entry = ldap_first_entry(handle, result.get());
    LdapStringPtr distinguishedName{
        entry == nullptr ? nullptr : ldap_get_dn(handle, entry)};
    if (entry == nullptr || !distinguishedName) {
        return foundation::fail(authenticationFailure(
            "The LDAP identity does not have a distinguished name."));
    }

    return LdapResolvedEntry{
        std::move(result), entry, std::move(distinguishedName)};
}

#if OPENPROOF_PLATFORM_APPLE && defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

[[nodiscard]] std::string percentEncode(std::string_view value)
{
    constexpr char hex[] = "0123456789ABCDEF";
    std::string output;
    for (const char symbol : value) {
        const auto byte = static_cast<unsigned char>(symbol);
        const bool unreserved = std::isalnum(byte) != 0 || byte == '-' || byte == '.' || byte == '_' || byte == '~';
        if (unreserved) output.push_back(static_cast<char>(byte));
        else {
            output.push_back('%');
            output.push_back(hex[(byte >> 4U) & 0x0FU]);
            output.push_back(hex[byte & 0x0FU]);
        }
    }
    return output;
}

[[nodiscard]] std::string xmlEscape(std::string_view value)
{
    std::string output;
    output.reserve(value.size());
    for (char symbol : value) {
        switch (symbol) {
        case '&': output += "&amp;"; break;
        case '<': output += "&lt;"; break;
        case '>': output += "&gt;"; break;
        case '"': output += "&quot;"; break;
        case '\'': output += "&apos;"; break;
        default: output.push_back(symbol); break;
        }
    }
    return output;
}

[[nodiscard]] foundation::Result<std::string> standardBase64(std::span<const std::byte> input)
{
    if (input.size() > 1024U * 1024U) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    std::string output(4U * ((input.size() + 2U) / 3U), '\0');
    const int length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output.data()),
        reinterpret_cast<const unsigned char*>(input.data()), static_cast<int>(input.size()));
    if (length < 0) return foundation::fail(foundation::ErrorCode::Internal);
    output.resize(static_cast<std::size_t>(length));
    return output;
}

[[nodiscard]] foundation::Result<std::vector<std::byte>> decodeStandardBase64(std::string_view text,
                                                                              std::size_t maximum)
{
    std::string compact;
    compact.reserve(text.size());
    for (char symbol : text) {
        if (symbol == ' ' || symbol == '\t' || symbol == '\r' || symbol == '\n') continue;
        if ((symbol >= 'A' && symbol <= 'Z') || (symbol >= 'a' && symbol <= 'z')
            || (symbol >= '0' && symbol <= '9') || symbol == '+' || symbol == '/' || symbol == '=') {
            compact.push_back(symbol);
        } else return foundation::fail(authenticationFailure("The SAML response has invalid base64 encoding."));
    }
    if (compact.empty() || compact.size() % 4U != 0U || compact.size() > maximum * 2U) {
        return foundation::fail(authenticationFailure("The SAML response has invalid base64 length."));
    }
    std::vector<std::byte> output((compact.size() / 4U) * 3U);
    const int decoded = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(output.data()),
        reinterpret_cast<const unsigned char*>(compact.data()), static_cast<int>(compact.size()));
    if (decoded < 0) return foundation::fail(authenticationFailure("The SAML response has invalid base64 encoding."));
    std::size_t length = static_cast<std::size_t>(decoded);
    if (compact.ends_with("==")) length -= 2U;
    else if (compact.ends_with("=")) length -= 1U;
    if (length > maximum) return foundation::fail(authenticationFailure("The SAML response is too large."));
    output.resize(length);
    return output;
}

[[nodiscard]] foundation::Result<std::string> deflateAndBase64(std::string_view input)
{
    z_stream stream{};
    if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return foundation::fail(foundation::ErrorCode::Internal);
    }
    std::vector<std::byte> output(compressBound(input.size()));
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    stream.next_out = reinterpret_cast<Bytef*>(output.data());
    stream.avail_out = static_cast<uInt>(output.size());
    const int result = deflate(&stream, Z_FINISH);
    const std::size_t written = stream.total_out;
    deflateEnd(&stream);
    if (result != Z_STREAM_END) return foundation::fail(foundation::ErrorCode::Internal);
    output.resize(written);
    return standardBase64(output);
}

[[nodiscard]] std::string hmacToken(const foundation::SecretString& key, std::string_view label,
                                    std::string_view challenge, std::string_view extra = {})
{
    std::string material{label};
    material.push_back('\0');
    material.append(challenge);
    material.push_back('\0');
    material.append(extra);
    auto digest = security::hmacSha256(key, material);
    if (!digest) return {};
    return foundation::toBase64Url(digest.value());
}

[[nodiscard]] xmlNodePtr uniqueChild(xmlNodePtr parent, std::string_view local,
                                     std::string_view namespaceUri)
{
    xmlNodePtr found = nullptr;
    for (xmlNodePtr node = parent == nullptr ? nullptr : parent->children; node != nullptr; node = node->next) {
        if (node->type != XML_ELEMENT_NODE || node->ns == nullptr || node->ns->href == nullptr) continue;
        if (std::string_view{reinterpret_cast<const char*>(node->name)} != local
            || std::string_view{reinterpret_cast<const char*>(node->ns->href)} != namespaceUri) continue;
        if (found != nullptr) return nullptr;
        found = node;
    }
    return found;
}

[[nodiscard]] std::vector<xmlNodePtr> children(xmlNodePtr parent, std::string_view local,
                                               std::string_view namespaceUri)
{
    std::vector<xmlNodePtr> output;
    for (xmlNodePtr node = parent == nullptr ? nullptr : parent->children; node != nullptr; node = node->next) {
        if (node->type == XML_ELEMENT_NODE && node->ns != nullptr && node->ns->href != nullptr
            && std::string_view{reinterpret_cast<const char*>(node->name)} == local
            && std::string_view{reinterpret_cast<const char*>(node->ns->href)} == namespaceUri) {
            output.push_back(node);
        }
    }
    return output;
}

[[nodiscard]] std::optional<std::string> attribute(xmlNodePtr node, std::string_view name)
{
    xmlChar* raw = xmlGetProp(node, reinterpret_cast<const xmlChar*>(std::string{name}.c_str()));
    if (raw == nullptr) return std::nullopt;
    std::string value{reinterpret_cast<const char*>(raw)};
    xmlFree(raw);
    return value;
}

[[nodiscard]] std::string content(xmlNodePtr node)
{
    if (node == nullptr) return {};
    xmlChar* raw = xmlNodeGetContent(node);
    if (raw == nullptr) return {};
    std::string value{reinterpret_cast<const char*>(raw)};
    xmlFree(raw);
    return value;
}

struct XmlDocDeleter final { void operator()(xmlDoc* value) const noexcept { if (value) xmlFreeDoc(value); } };
using XmlDocPtr = std::unique_ptr<xmlDoc, XmlDocDeleter>;
struct XmlBufferDeleter final { void operator()(xmlChar* value) const noexcept { if (value) xmlFree(value); } };
using XmlBufferPtr = std::unique_ptr<xmlChar, XmlBufferDeleter>;
struct X509Deleter final { void operator()(X509* value) const noexcept { X509_free(value); } };
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
struct PkeyDeleter final { void operator()(EVP_PKEY* value) const noexcept { EVP_PKEY_free(value); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
struct BioDeleter final { void operator()(BIO* value) const noexcept { BIO_free(value); } };
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
struct MdCtxDeleter final { void operator()(EVP_MD_CTX* value) const noexcept { EVP_MD_CTX_free(value); } };
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

[[nodiscard]] foundation::Result<std::string> canonicalizeCopy(xmlNodePtr node,
                                                               bool removeDirectSignature)
{
    XmlDocPtr document{xmlNewDoc(reinterpret_cast<const xmlChar*>("1.0"))};
    if (!document) return foundation::fail(foundation::ErrorCode::Internal);
    xmlNodePtr copy = xmlDocCopyNode(node, document.get(), 1);
    if (copy == nullptr) return foundation::fail(foundation::ErrorCode::Internal);
    xmlDocSetRootElement(document.get(), copy);
    xmlReconciliateNs(document.get(), copy);
    if (removeDirectSignature) {
        for (xmlNodePtr child = copy->children; child != nullptr;) {
            xmlNodePtr next = child->next;
            if (child->type == XML_ELEMENT_NODE && child->ns != nullptr && child->ns->href != nullptr
                && std::string_view{reinterpret_cast<const char*>(child->name)} == "Signature"
                && std::string_view{reinterpret_cast<const char*>(child->ns->href)} == kXmlDsig) {
                xmlUnlinkNode(child);
                xmlFreeNode(child);
            }
            child = next;
        }
    }
    xmlChar* raw = nullptr;
    const int size = xmlC14NDocDumpMemory(document.get(), nullptr, XML_C14N_EXCLUSIVE_1_0,
                                          nullptr, 0, &raw);
    XmlBufferPtr buffer{raw};
    if (size < 0 || raw == nullptr) return foundation::fail(foundation::ErrorCode::Internal);
    return std::string{reinterpret_cast<const char*>(raw), static_cast<std::size_t>(size)};
}

[[nodiscard]] foundation::Status rejectDuplicateIds(xmlNodePtr root)
{
    std::set<std::string, std::less<>> ids;
    std::vector<xmlNodePtr> stack{root};
    while (!stack.empty()) {
        xmlNodePtr node = stack.back();
        stack.pop_back();
        if (node->type == XML_ELEMENT_NODE) {
            if (auto id = attribute(node, "ID"); id && !id->empty()) {
                if (!ids.insert(*id).second) {
                    return foundation::fail(authenticationFailure("The SAML document contains duplicate ID attributes."));
                }
            }
        }
        for (xmlNodePtr child = node->children; child != nullptr; child = child->next) stack.push_back(child);
    }
    return foundation::ok();
}

[[nodiscard]] foundation::Result<X509Ptr> pinnedCertificate(std::string_view pem,
                                                            foundation::Instant now)
{
    BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
    X509Ptr certificate{bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr};
    if (!certificate) return foundation::fail(foundation::ErrorCode::InvalidArgument, "The SAML IdP certificate is invalid.");
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::time_t timestamp = static_cast<std::time_t>(seconds);
    if (X509_cmp_time(X509_get0_notBefore(certificate.get()), &timestamp) > 0
        || X509_cmp_time(X509_get0_notAfter(certificate.get()), &timestamp) < 0) {
        return foundation::fail(authenticationFailure("The pinned SAML IdP certificate is outside its validity period."));
    }
    return certificate;
}

[[nodiscard]] foundation::Status verifyXmlSignature(xmlNodePtr signedNode,
                                                     std::string_view certificatePem,
                                                     foundation::Instant now)
{
    xmlNodePtr signature = uniqueChild(signedNode, "Signature", kXmlDsig);
    if (signature == nullptr) return foundation::fail(authenticationFailure("A required SAML XML signature is missing or ambiguous."));
    xmlNodePtr signedInfo = uniqueChild(signature, "SignedInfo", kXmlDsig);
    xmlNodePtr signatureValue = uniqueChild(signature, "SignatureValue", kXmlDsig);
    if (signedInfo == nullptr || signatureValue == nullptr) return foundation::fail(authenticationFailure("The SAML XML signature is malformed."));
    xmlNodePtr canonicalization = uniqueChild(signedInfo, "CanonicalizationMethod", kXmlDsig);
    xmlNodePtr signatureMethod = uniqueChild(signedInfo, "SignatureMethod", kXmlDsig);
    auto references = children(signedInfo, "Reference", kXmlDsig);
    if (canonicalization == nullptr || signatureMethod == nullptr || references.size() != 1U
        || attribute(canonicalization, "Algorithm") != kExclusiveC14n
        || attribute(signatureMethod, "Algorithm") != kRsaSha256) {
        return foundation::fail(authenticationFailure("The SAML XML signature uses an unsupported algorithm profile."));
    }
    const auto signedId = attribute(signedNode, "ID");
    const auto referenceUri = attribute(references.front(), "URI");
    if (!signedId || signedId->empty() || !referenceUri || *referenceUri != "#" + *signedId) {
        return foundation::fail(authenticationFailure("The SAML signature is not bound to the expected XML element."));
    }
    xmlNodePtr transforms = uniqueChild(references.front(), "Transforms", kXmlDsig);
    xmlNodePtr digestMethod = uniqueChild(references.front(), "DigestMethod", kXmlDsig);
    xmlNodePtr digestValue = uniqueChild(references.front(), "DigestValue", kXmlDsig);
    if (transforms == nullptr || digestMethod == nullptr || digestValue == nullptr
        || attribute(digestMethod, "Algorithm") != kSha256) {
        return foundation::fail(authenticationFailure("The SAML digest profile is unsupported."));
    }
    auto transformNodes = children(transforms, "Transform", kXmlDsig);
    if (transformNodes.size() != 2U
        || attribute(transformNodes[0], "Algorithm") != kEnvelopedSignature
        || attribute(transformNodes[1], "Algorithm") != kExclusiveC14n) {
        return foundation::fail(authenticationFailure("The SAML reference transforms are unsupported."));
    }
    auto canonicalReference = canonicalizeCopy(signedNode, true);
    if (!canonicalReference) return foundation::fail(canonicalReference.error());
    auto digest = security::sha256(canonicalReference.value());
    if (!digest) return foundation::fail(digest.error());
    auto expectedDigest = standardBase64(digest.value());
    if (!expectedDigest || !security::constantTimeEquals(expectedDigest.value(), content(digestValue))) {
        return foundation::fail(authenticationFailure("The SAML assertion digest is invalid."));
    }
    auto canonicalSignedInfo = canonicalizeCopy(signedInfo, false);
    auto signatureBytes = decodeStandardBase64(content(signatureValue), 8192U);
    auto certificate = pinnedCertificate(certificatePem, now);
    if (!canonicalSignedInfo || !signatureBytes || !certificate) {
        return foundation::fail(authenticationFailure("The SAML signature could not be validated."));
    }
    PkeyPtr key{X509_get_pubkey(certificate->get())};
    if (!key || EVP_PKEY_base_id(key.get()) != EVP_PKEY_RSA || EVP_PKEY_get_bits(key.get()) < 2048) {
        return foundation::fail(authenticationFailure("The pinned SAML signing key is not an acceptable RSA key."));
    }
    MdCtxPtr context{EVP_MD_CTX_new()};
    const bool verified = context
        && EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, key.get()) == 1
        && EVP_DigestVerifyUpdate(context.get(), canonicalSignedInfo->data(), canonicalSignedInfo->size()) == 1
        && EVP_DigestVerifyFinal(context.get(), reinterpret_cast<const unsigned char*>(signatureBytes->data()),
                                 signatureBytes->size()) == 1;
    if (!verified) return foundation::fail(authenticationFailure("The SAML XML signature is invalid."));
    return foundation::ok();
}

[[nodiscard]] foundation::Result<foundation::Instant> parseSamlTime(std::string_view value)
{
    if (value.size() < 20U || value[4] != '-' || value[7] != '-' || value[10] != 'T'
        || value[13] != ':' || value[16] != ':' || !value.ends_with('Z')) {
        return foundation::fail(authenticationFailure("A SAML timestamp is invalid."));
    }
    auto number = [&](std::size_t offset, std::size_t length) -> std::optional<int> {
        int result{};
        const char* begin = value.data() + offset;
        const char* end = begin + length;
        auto parsed = std::from_chars(begin, end, result);
        if (parsed.ec != std::errc{} || parsed.ptr != end) return std::nullopt;
        return result;
    };
    auto year = number(0U, 4U); auto month = number(5U, 2U); auto day = number(8U, 2U);
    auto hour = number(11U, 2U); auto minute = number(14U, 2U); auto second = number(17U, 2U);
    if (!year || !month || !day || !hour || !minute || !second || *hour > 23 || *minute > 59 || *second > 60) {
        return foundation::fail(authenticationFailure("A SAML timestamp is invalid."));
    }
    std::chrono::year_month_day date{std::chrono::year{*year}, std::chrono::month{static_cast<unsigned>(*month)},
                                     std::chrono::day{static_cast<unsigned>(*day)}};
    if (!date.ok()) return foundation::fail(authenticationFailure("A SAML timestamp is invalid."));
    foundation::Duration fraction{};
    std::size_t position = 19U;
    if (position < value.size() - 1U && value[position] == '.') {
        ++position;
        std::int64_t milliseconds = 0;
        std::size_t digits = 0U;
        while (position < value.size() - 1U && value[position] >= '0' && value[position] <= '9') {
            if (digits < 3U) milliseconds = milliseconds * 10 + (value[position] - '0');
            ++digits; ++position;
        }
        if (digits == 0U || position != value.size() - 1U) return foundation::fail(authenticationFailure("A SAML timestamp is invalid."));
        if (digits == 1U) milliseconds *= 100;
        else if (digits == 2U) milliseconds *= 10;
        fraction = std::chrono::milliseconds{milliseconds};
    } else if (position != value.size() - 1U) {
        return foundation::fail(authenticationFailure("A SAML timestamp is invalid."));
    }
    auto instant = std::chrono::time_point_cast<foundation::Duration>(std::chrono::sys_days{date})
        + std::chrono::hours{*hour} + std::chrono::minutes{*minute} + std::chrono::seconds{*second} + fraction;
    return instant;
}

[[nodiscard]] foundation::Status withinWindow(xmlNodePtr node, foundation::Instant now,
                                              foundation::Duration skew)
{
    if (auto notBefore = attribute(node, "NotBefore")) {
        auto parsed = parseSamlTime(*notBefore);
        if (!parsed || now + skew < parsed.value()) return foundation::fail(authenticationFailure("The SAML assertion is not yet valid."));
    }
    if (auto notOnOrAfter = attribute(node, "NotOnOrAfter")) {
        auto parsed = parseSamlTime(*notOnOrAfter);
        if (!parsed || now - skew >= parsed.value()) return foundation::fail(authenticationFailure("The SAML assertion has expired."));
    }
    return foundation::ok();
}

[[nodiscard]] std::optional<std::string> samlAttribute(xmlNodePtr assertion, std::string_view name)
{
    xmlNodePtr statement = uniqueChild(assertion, "AttributeStatement", kSamlAssertion);
    if (statement == nullptr) return std::nullopt;
    std::optional<std::string> found;
    for (xmlNodePtr item : children(statement, "Attribute", kSamlAssertion)) {
        auto itemName = attribute(item, "Name");
        if (!itemName || *itemName != name) continue;
        auto values = children(item, "AttributeValue", kSamlAssertion);
        if (values.size() != 1U || found) return std::nullopt;
        std::string value = content(values.front());
        if (value.empty() || value.size() > 4096U) return std::nullopt;
        found = std::move(value);
    }
    return found;
}

} // namespace

LdapProviderConfig::LdapProviderConfig(
    std::string uri, std::string baseDn, std::string usernameAttribute,
    std::string subjectAttribute, std::string displayNameAttribute,
    std::string emailAttribute, std::string serviceBindDn,
    foundation::SecretString serviceBindPassword, foundation::SecretString derivationKey,
    std::string caFile, foundation::Duration challengeLifetime)
    : m_uri(std::move(uri)), m_baseDn(std::move(baseDn)),
      m_usernameAttribute(std::move(usernameAttribute)), m_subjectAttribute(std::move(subjectAttribute)),
      m_displayNameAttribute(std::move(displayNameAttribute)), m_emailAttribute(std::move(emailAttribute)),
      m_serviceBindDn(std::move(serviceBindDn)), m_serviceBindPassword(std::move(serviceBindPassword)),
      m_derivationKey(std::move(derivationKey)), m_caFile(std::move(caFile)), m_challengeLifetime(challengeLifetime) {}

foundation::Result<LdapProviderConfig> LdapProviderConfig::create(
    std::string uri, std::string baseDn, std::string usernameAttribute,
    std::string subjectAttribute, std::string displayNameAttribute,
    std::string emailAttribute, std::string serviceBindDn,
    foundation::SecretString serviceBindPassword, foundation::SecretString derivationKey,
    std::string caFile, foundation::Duration challengeLifetime)
{
    if (!validLdapsUri(uri) || !validLdapDn(baseDn)
        || !safeAttribute(usernameAttribute) || !safeAttribute(subjectAttribute)
        || (!displayNameAttribute.empty() && !safeAttribute(displayNameAttribute))
        || (!emailAttribute.empty() && !safeAttribute(emailAttribute))
        || (serviceBindDn.empty() != serviceBindPassword.empty())
        || (!serviceBindDn.empty() && !safeLdapText(serviceBindDn, 2048U))
        || derivationKey.size() < 32U
        || challengeLifetime < 30s || challengeLifetime > 10min) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The enterprise LDAP configuration is invalid.");
    }
    return LdapProviderConfig{std::move(uri), std::move(baseDn), std::move(usernameAttribute),
        std::move(subjectAttribute), std::move(displayNameAttribute), std::move(emailAttribute),
        std::move(serviceBindDn), std::move(serviceBindPassword), std::move(derivationKey),
        std::move(caFile), challengeLifetime};
}


std::string_view LdapProviderConfig::uri() const noexcept { return m_uri; }
std::string_view LdapProviderConfig::baseDn() const noexcept { return m_baseDn; }
std::string_view LdapProviderConfig::usernameAttribute() const noexcept { return m_usernameAttribute; }
std::string_view LdapProviderConfig::subjectAttribute() const noexcept { return m_subjectAttribute; }
std::string_view LdapProviderConfig::displayNameAttribute() const noexcept { return m_displayNameAttribute; }
std::string_view LdapProviderConfig::emailAttribute() const noexcept { return m_emailAttribute; }
std::string_view LdapProviderConfig::serviceBindDn() const noexcept { return m_serviceBindDn; }
const foundation::SecretString& LdapProviderConfig::serviceBindPassword() const noexcept { return m_serviceBindPassword; }
const foundation::SecretString& LdapProviderConfig::derivationKey() const noexcept { return m_derivationKey; }
std::string_view LdapProviderConfig::caFile() const noexcept { return m_caFile; }
foundation::Duration LdapProviderConfig::challengeLifetime() const noexcept { return m_challengeLifetime; }

class LdapAuthenticationProvider::Implementation final {
public:
    Implementation(LdapProviderConfig providerConfig,
                   const foundation::ClockSource& clockSource)
        : config(std::move(providerConfig)), clock(&clockSource) {}
    LdapProviderConfig config;
    const foundation::ClockSource* clock;
};

LdapAuthenticationProvider::LdapAuthenticationProvider(LdapProviderConfig config,
                                                       const foundation::ClockSource& clock)
    : m_implementation(std::make_unique<Implementation>(std::move(config), clock)) {}
LdapAuthenticationProvider::~LdapAuthenticationProvider() = default;
idp::ProviderId LdapAuthenticationProvider::id() const { return idp::ProviderId{"ldap"}; }
idp::InteractionModel LdapAuthenticationProvider::interactionModel() const noexcept { return idp::InteractionModel::ChallengeResponse; }
idp::AssuranceLevel LdapAuthenticationProvider::maximumClaimableAssurance() const noexcept { return idp::AssuranceLevel::Ial1; }

foundation::Result<idp::AuthenticationChallenge> LdapAuthenticationProvider::beginAuthentication(
    const idp::AuthenticationRequest& request)
{
    if (request.provider() != id()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The LDAP authentication request targets another provider.");
    }
    const auto username = request.parameters().find("username");
    if (username == request.parameters().end() || !safeToken(username->second, 320U)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument, "LDAP authentication requires a username.");
    }
    auto challengeId = security::randomTokenBase64Url(32U);
    if (!challengeId) return foundation::fail(challengeId.error());
    idp::AuthenticationChallenge challenge{idp::ChallengeId{challengeId.value()},
        m_implementation->clock->now() + m_implementation->config.m_challengeLifetime};
    const auto binding = hmacToken(m_implementation->config.m_derivationKey,
        "ldap-username", challengeId.value(), username->second);
    if (binding.empty()) return foundation::fail(foundation::ErrorCode::Internal);
    challenge.setParameter("username", username->second);
    challenge.setParameter("username_binding", binding);
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome> LdapAuthenticationProvider::completeAuthentication(
    const idp::AuthenticationResponse& response)
{
    const auto usernameIt = response.parameters().find("username");
    const auto passwordIt = response.parameters().find("password");
    const auto bindingIt = response.parameters().find("username_binding");
    if (usernameIt == response.parameters().end() || passwordIt == response.parameters().end()
        || bindingIt == response.parameters().end() || usernameIt->second.empty()
        || passwordIt->second.empty() || bindingIt->second.empty()) {
        return foundation::fail(authenticationFailure("LDAP credentials are incomplete."));
    }
    const auto& config = m_implementation->config;
    const auto expectedBinding = hmacToken(config.m_derivationKey, "ldap-username",
        response.challengeId().value(), usernameIt->second.expose());
    if (expectedBinding.empty() || !security::constantTimeEquals(expectedBinding, bindingIt->second.expose())) {
        return foundation::fail(authenticationFailure("The LDAP username is not bound to this challenge."));
    }
    auto directory = openLdap(config);
    if (!directory) return foundation::fail(directory.error());
    auto serviceBind = simpleBind(directory->get(), config.m_serviceBindDn, config.m_serviceBindPassword.expose());
    if (!serviceBind) return foundation::fail(serviceBind.error());
    const std::string filter = "(" + config.m_usernameAttribute + "="
        + escapeLdapFilter(usernameIt->second.expose()) + ")";
    std::vector<std::string> attributeStorage{config.m_subjectAttribute};
    if (!config.m_displayNameAttribute.empty()) attributeStorage.push_back(config.m_displayNameAttribute);
    if (!config.m_emailAttribute.empty()) attributeStorage.push_back(config.m_emailAttribute);
    std::vector<char*> attributes;
    attributes.reserve(attributeStorage.size() + 1U);
    for (auto& value : attributeStorage) attributes.push_back(value.data());
    attributes.push_back(nullptr);
    auto resolved = findUniqueLdapEntry(directory->get(), config.m_baseDn, filter, attributes);
    if (!resolved) {
        return foundation::fail(resolved.error());
    }
    LDAPMessage* entry = resolved->entry;
    auto subject = ldapValue(directory->get(), entry, config.m_subjectAttribute);
    if (!subject || !safeToken(*subject, 1024U)) {
        return foundation::fail(authenticationFailure(
            "The LDAP entry is missing a stable subject identifier."));
    }
    auto userConnection = openLdap(config);
    if (!userConnection) return foundation::fail(userConnection.error());
    auto userBind = simpleBind(userConnection->get(), resolved->distinguishedName.get(),
                               passwordIt->second.expose());
    if (!userBind) return foundation::fail(userBind.error());

    idp::VerifiedClaims claims;
    if (!config.m_displayNameAttribute.empty()) {
        if (auto value = ldapValue(directory->get(), entry, config.m_displayNameAttribute); value && detail::safePresentationText(*value)) {
            claims.set(idp::ClaimName::DisplayName, *value);
        }
    }
    if (!config.m_emailAttribute.empty()) {
        if (auto value = ldapValue(directory->get(), entry, config.m_emailAttribute); value && safeToken(*value, 320U)) {
            claims.set(idp::ClaimName::Email, *value);
        }
    }
    idp::ProviderEvidence evidence;
    evidence.add("protocol", "ldap");
    evidence.add("transport", "ldaps");
    evidence.add("subject_attribute", config.m_subjectAttribute);
    return idp::AuthenticationOutcome::create(id(), idp::ExternalSubject{*subject}, std::move(claims),
        idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Knowledge, false},
        std::move(evidence), m_implementation->clock->now());
}

SamlProviderConfig::SamlProviderConfig(
    std::string spEntityId, std::string assertionConsumerServiceUri,
    std::string idpEntityId, std::string idpSsoUrl, std::string idpCertificatePem,
    foundation::SecretString derivationKey, foundation::Duration challengeLifetime,
    foundation::Duration clockSkew)
    : m_spEntityId(std::move(spEntityId)), m_acsUri(std::move(assertionConsumerServiceUri)),
      m_idpEntityId(std::move(idpEntityId)), m_idpSsoUrl(std::move(idpSsoUrl)),
      m_idpCertificatePem(std::move(idpCertificatePem)), m_derivationKey(std::move(derivationKey)),
      m_challengeLifetime(challengeLifetime), m_clockSkew(clockSkew) {}

foundation::Result<SamlProviderConfig> SamlProviderConfig::create(
    std::string spEntityId, std::string assertionConsumerServiceUri,
    std::string idpEntityId, std::string idpSsoUrl, std::string idpCertificatePem,
    foundation::SecretString derivationKey, foundation::Duration challengeLifetime,
    foundation::Duration clockSkew)
{
    if (!safeToken(spEntityId, 2048U)
        || !validHttpsEndpoint(assertionConsumerServiceUri)
        || !validHttpsEndpoint(idpSsoUrl) || !safeToken(idpEntityId, 2048U)
        || idpCertificatePem.size() < 64U || derivationKey.size() < 32U
        || challengeLifetime < 30s || challengeLifetime > 10min || clockSkew < 0ms || clockSkew > 5min) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument, "The SAML service-provider configuration is invalid.");
    }
    auto certificate = pinnedCertificate(idpCertificatePem, foundation::SystemClockSource{}.now());
    if (!certificate) return foundation::fail(certificate.error());
    return SamlProviderConfig{std::move(spEntityId), std::move(assertionConsumerServiceUri),
        std::move(idpEntityId), std::move(idpSsoUrl), std::move(idpCertificatePem),
        std::move(derivationKey), challengeLifetime, clockSkew};
}

class SamlAuthenticationProvider::Implementation final {
public:
    Implementation(SamlProviderConfig providerConfig,
                   const foundation::ClockSource& clockSource)
        : config(std::move(providerConfig)), clock(&clockSource) {}
    SamlProviderConfig config;
    const foundation::ClockSource* clock;
};

SamlAuthenticationProvider::SamlAuthenticationProvider(SamlProviderConfig config,
                                                       const foundation::ClockSource& clock)
    : m_implementation(std::make_unique<Implementation>(std::move(config), clock)) {}
SamlAuthenticationProvider::~SamlAuthenticationProvider() = default;
idp::ProviderId SamlAuthenticationProvider::id() const { return idp::ProviderId{"saml"}; }
idp::InteractionModel SamlAuthenticationProvider::interactionModel() const noexcept { return idp::InteractionModel::Redirect; }
idp::AssuranceLevel SamlAuthenticationProvider::maximumClaimableAssurance() const noexcept { return idp::AssuranceLevel::Ial1; }

foundation::Result<idp::AuthenticationChallenge> SamlAuthenticationProvider::beginAuthentication(
    const idp::AuthenticationRequest& request)
{
    if (request.provider() != id()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The SAML authentication request targets another provider.");
    }
    auto random = security::randomTokenBase64Url(32U);
    if (!random) return foundation::fail(random.error());
    const auto now = m_implementation->clock->now();
    const std::string challengeText = random.value();
    const std::string requestId = "_" + challengeText;
    const auto& config = m_implementation->config;
    const std::string xml = "<samlp:AuthnRequest xmlns:samlp=\"" + std::string{kSamlProtocol}
        + "\" xmlns:saml=\"" + std::string{kSamlAssertion} + "\" ID=\"" + xmlEscape(requestId)
        + "\" Version=\"2.0\" IssueInstant=\"" + foundation::toIso8601(now)
        + "\" Destination=\"" + xmlEscape(config.m_idpSsoUrl)
        + "\" AssertionConsumerServiceURL=\"" + xmlEscape(config.m_acsUri)
        + "\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">"
          "<saml:Issuer>" + xmlEscape(config.m_spEntityId) + "</saml:Issuer>"
          "<samlp:NameIDPolicy AllowCreate=\"true\"/>"
          "</samlp:AuthnRequest>";
    auto encoded = deflateAndBase64(xml);
    if (!encoded) return foundation::fail(encoded.error());
    const std::string relayState = hmacToken(config.m_derivationKey, "saml-relay", challengeText);
    if (relayState.empty()) return foundation::fail(foundation::ErrorCode::Internal);
    std::string separator = config.m_idpSsoUrl.contains('?') ? "&" : "?";
    const std::string authorizationUrl = config.m_idpSsoUrl + separator + "SAMLRequest="
        + percentEncode(encoded.value()) + "&RelayState=" + percentEncode(relayState);
    idp::AuthenticationChallenge challenge{idp::ChallengeId{challengeText}, now + config.m_challengeLifetime};
    challenge.setParameter("authorization_url", authorizationUrl);
    return challenge;
}

foundation::Result<idp::AuthenticationOutcome> SamlAuthenticationProvider::completeAuthentication(
    const idp::AuthenticationResponse& response)
{
    const auto assertionIt = response.parameters().find("SAMLResponse");
    const auto relayIt = response.parameters().find("RelayState");
    if (assertionIt == response.parameters().end() || relayIt == response.parameters().end()
        || assertionIt->second.empty() || relayIt->second.empty()) {
        return foundation::fail(authenticationFailure("The SAML callback is incomplete."));
    }
    const auto& config = m_implementation->config;
    const std::string expectedRelay = hmacToken(config.m_derivationKey, "saml-relay", response.challengeId().value());
    if (expectedRelay.empty() || !security::constantTimeEquals(expectedRelay, relayIt->second.expose())) {
        return foundation::fail(authenticationFailure("The SAML RelayState is invalid."));
    }
    auto decoded = decodeStandardBase64(assertionIt->second.expose(), 1024U * 1024U);
    if (!decoded) return foundation::fail(decoded.error());
    const int parseOptions = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NOBLANKS;
    XmlDocPtr document{xmlReadMemory(reinterpret_cast<const char*>(decoded->data()),
        static_cast<int>(decoded->size()), "saml-response.xml", nullptr, parseOptions)};
    if (!document || document->intSubset != nullptr || document->extSubset != nullptr) {
        return foundation::fail(authenticationFailure("The SAML XML document is invalid."));
    }
    xmlNodePtr root = xmlDocGetRootElement(document.get());
    if (root == nullptr || root->ns == nullptr || root->ns->href == nullptr
        || std::string_view{reinterpret_cast<const char*>(root->name)} != "Response"
        || std::string_view{reinterpret_cast<const char*>(root->ns->href)} != kSamlProtocol) {
        return foundation::fail(authenticationFailure("The SAML root element is invalid."));
    }
    auto uniqueIds = rejectDuplicateIds(root);
    if (!uniqueIds) return foundation::fail(uniqueIds.error());
    const auto expectedRequestId = "_" + std::string{response.challengeId().value()};
    if (attribute(root, "Destination") != config.m_acsUri || attribute(root, "InResponseTo") != expectedRequestId) {
        return foundation::fail(authenticationFailure("The SAML response is not bound to this service-provider request."));
    }
    xmlNodePtr issuer = uniqueChild(root, "Issuer", kSamlAssertion);
    if (issuer == nullptr || content(issuer) != config.m_idpEntityId) {
        return foundation::fail(authenticationFailure("The SAML issuer is invalid."));
    }
    xmlNodePtr status = uniqueChild(root, "Status", kSamlProtocol);
    xmlNodePtr statusCode = status == nullptr ? nullptr : uniqueChild(status, "StatusCode", kSamlProtocol);
    if (statusCode == nullptr || attribute(statusCode, "Value") != kSamlSuccess) {
        return foundation::fail(authenticationFailure("The SAML identity provider rejected authentication."));
    }
    auto assertions = children(root, "Assertion", kSamlAssertion);
    if (assertions.size() != 1U) return foundation::fail(authenticationFailure("The SAML response must contain exactly one assertion."));
    xmlNodePtr assertion = assertions.front();
    const auto now = m_implementation->clock->now();
    const bool responseSigned = uniqueChild(root, "Signature", kXmlDsig) != nullptr;
    const bool assertionSigned = uniqueChild(assertion, "Signature", kXmlDsig) != nullptr;
    if (!responseSigned && !assertionSigned) return foundation::fail(authenticationFailure("The SAML response is unsigned."));
    if (responseSigned) {
        auto verified = verifyXmlSignature(root, config.m_idpCertificatePem, now);
        if (!verified) return foundation::fail(verified.error());
    }
    if (assertionSigned) {
        auto verified = verifyXmlSignature(assertion, config.m_idpCertificatePem, now);
        if (!verified) return foundation::fail(verified.error());
    }
    xmlNodePtr conditions = uniqueChild(assertion, "Conditions", kSamlAssertion);
    if (conditions == nullptr) return foundation::fail(authenticationFailure("The SAML assertion has no Conditions."));
    auto window = withinWindow(conditions, now, config.m_clockSkew);
    if (!window) return foundation::fail(window.error());
    bool audienceAccepted = false;
    for (xmlNodePtr restriction : children(conditions, "AudienceRestriction", kSamlAssertion)) {
        for (xmlNodePtr audience : children(restriction, "Audience", kSamlAssertion)) {
            if (content(audience) == config.m_spEntityId) audienceAccepted = true;
        }
    }
    if (!audienceAccepted) return foundation::fail(authenticationFailure("The SAML assertion audience is invalid."));
    xmlNodePtr subject = uniqueChild(assertion, "Subject", kSamlAssertion);
    xmlNodePtr nameId = subject == nullptr ? nullptr : uniqueChild(subject, "NameID", kSamlAssertion);
    auto confirmations = subject == nullptr ? std::vector<xmlNodePtr>{} : children(subject, "SubjectConfirmation", kSamlAssertion);
    if (nameId == nullptr || confirmations.empty()) return foundation::fail(authenticationFailure("The SAML subject is incomplete."));
    bool confirmed = false;
    for (xmlNodePtr confirmation : confirmations) {
        if (attribute(confirmation, "Method") != "urn:oasis:names:tc:SAML:2.0:cm:bearer") continue;
        xmlNodePtr data = uniqueChild(confirmation, "SubjectConfirmationData", kSamlAssertion);
        if (data == nullptr || attribute(data, "Recipient") != config.m_acsUri
            || attribute(data, "InResponseTo") != expectedRequestId) continue;
        auto expiry = attribute(data, "NotOnOrAfter");
        if (!expiry) continue;
        auto parsed = parseSamlTime(*expiry);
        if (parsed && now - config.m_clockSkew < parsed.value()) confirmed = true;
    }
    const std::string externalSubject = content(nameId);
    if (!confirmed || !safeToken(externalSubject, 2048U)) {
        return foundation::fail(authenticationFailure("The SAML bearer subject confirmation is invalid."));
    }
    idp::VerifiedClaims claims;
    if (auto email = samlAttribute(assertion, "email"); email && safeToken(*email, 320U)) {
        claims.set(idp::ClaimName::Email, *email);
    }
    if (auto display = samlAttribute(assertion, "displayName"); display && detail::safePresentationText(*display)) {
        claims.set(idp::ClaimName::DisplayName, *display);
    }
    idp::ProviderEvidence evidence;
    evidence.add("protocol", "saml2");
    evidence.add("idp_entity_id", config.m_idpEntityId);
    evidence.add("signature", responseSigned && assertionSigned ? "response+assertion" : (responseSigned ? "response" : "assertion"));
    return idp::AuthenticationOutcome::create(id(), idp::ExternalSubject{externalSubject}, std::move(claims),
        idp::AssuranceLevel::Ial1,
        idp::AuthenticationStrength{},
        std::move(evidence), now);
}

} // namespace openproof::provider::enterprise
