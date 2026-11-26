#include <algorithm>
#include <cstddef>
#include <map>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <boost/asio/awaitable.hpp>

#include "coroutine_federated_callback_http.hpp"

import openproof.foundation;
import openproof.identity.provider;
import openproof.security;

namespace openproof::authentication::http {
namespace {
namespace asio = boost::asio;
namespace idp = identity::provider;
using Parameters = std::map<std::string, std::string, std::less<>>;

constexpr std::string_view kContinuation = "__Host-openproof-federation-continuation";
constexpr std::string_view kBinding = "__Host-openproof-federation-binding";
constexpr std::string_view kTransaction = "__Host-openproof-federation-transaction";
constexpr std::string_view kChallenge = "__Host-openproof-federation-challenge";
constexpr std::string_view kReturn = "__Host-openproof-federation-return";
constexpr std::string_view kMode = "__Host-openproof-federation-mode";
constexpr std::string_view kSession = "__Host-openproof-session";

// A callback that fails parsing, cookie validation, or rate/route checks must
// erase raw credentials just as reliably as a callback which reaches SQL.
// This guard is scoped to the native callback route, not delegated requests.
class SensitiveFederatedCallbackRequestGuard final {
public:
    explicit SensitiveFederatedCallbackRequestGuard(gateway::HttpRequest& request)
        : m_request(request) {}
    SensitiveFederatedCallbackRequestGuard(const SensitiveFederatedCallbackRequestGuard&) = delete;
    SensitiveFederatedCallbackRequestGuard& operator=(const SensitiveFederatedCallbackRequestGuard&) = delete;
    ~SensitiveFederatedCallbackRequestGuard() { wipe(); }
    void wipe() noexcept {
        m_request.wipeTargetQuery();
        m_request.wipeBody();
        m_request.wipeAuthorizationHeader();
        m_request.wipeCookieHeader();
    }
private:
    gateway::HttpRequest& m_request;
};


[[nodiscard]] bool isCallback(const gateway::HttpRequest& request) noexcept
{
    return request.path() == "/auth/federated/callback";
}

void secure(gateway::HttpResponse& response)
{
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
}

[[nodiscard]] std::string cookie(
    std::string_view name, std::string_view value, int seconds,
    std::string_view sameSite = "None")
{
    return std::string{name} + "=" + std::string{value}
        + "; Path=/; Max-Age=" + std::to_string(seconds)
        + "; Secure; HttpOnly; SameSite=" + std::string{sameSite};
}

void clearState(gateway::HttpResponse& response)
{
    for (auto name : {kContinuation, kBinding, kTransaction, kChallenge, kReturn, kMode})
        response.addHeader("set-cookie", cookie(name, "", 0));
}

[[nodiscard]] gateway::HttpResponse denied(
    foundation::ErrorCode code, const gateway::HttpRequest& request)
{
    const foundation::Error failure{code};
    gateway::HttpResponse response{
        foundation::errorHttpStatus(code),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    secure(response);
    clearState(response);
    return response;
}

[[nodiscard]] bool validSessionToken(std::string_view text) noexcept
{
    return !text.empty() && text.size() <= 128U
        && std::ranges::all_of(text, [](char value) {
            return (value >= 'A' && value <= 'Z')
                || (value >= 'a' && value <= 'z')
                || (value >= '0' && value <= '9')
                || value == '-' || value == '_';
        });
}

[[nodiscard]] std::optional<unsigned int> hexValue(char value) noexcept
{
    if (value >= '0' && value <= '9') return static_cast<unsigned int>(value - '0');
    if (value >= 'A' && value <= 'F') return 10U + static_cast<unsigned int>(value - 'A');
    if (value >= 'a' && value <= 'f') return 10U + static_cast<unsigned int>(value - 'a');
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> decodeQuery(std::string_view source)
{
    std::string output;
    output.reserve(source.size());
    for (std::size_t i = 0U; i < source.size(); ++i) {
        if (source[i] == '%') {
            if (i + 2U >= source.size()) {
                foundation::secureWipe(output.data(),output.size());
                return std::nullopt;
            }
            const auto high = hexValue(source[i + 1U]);
            const auto low = hexValue(source[i + 2U]);
            if (!high || !low) {
                foundation::secureWipe(output.data(),output.size());
                return std::nullopt;
            }
            output.push_back(static_cast<char>((*high << 4U) | *low));
            i += 2U;
        } else if (source[i] == '+') {
            output.push_back(' ');
        } else {
            output.push_back(source[i]);
        }
    }
    return output;
}

class SensitiveParameters final {
public:
    explicit SensitiveParameters(Parameters& values) noexcept : m_values(&values) {}
    SensitiveParameters(const SensitiveParameters&) = delete;
    SensitiveParameters& operator=(const SensitiveParameters&) = delete;
    ~SensitiveParameters() { wipe(); }
    void wipe() noexcept {
        for (auto& [key, value] : *m_values) {
            foundation::secureWipe(value.data(), value.size());
            value.clear();
        }
    }
private:
    Parameters* m_values;
};

[[nodiscard]] std::optional<Parameters> callbackParameters(const gateway::HttpRequest& request)
{
    const auto target = request.target();
    const auto question = target.find('?');
    std::string_view input;
    if (request.method()==gateway::HttpMethod::Get) {
        if (question==std::string_view::npos || !request.body().empty()) return std::nullopt;
        input=target.substr(question+1U);
    } else if (request.method()==gateway::HttpMethod::Post) {
        const auto type=request.header("content-type");
        if (!type || (*type!="application/x-www-form-urlencoded"
            && !type->starts_with("application/x-www-form-urlencoded;")))
            return std::nullopt;
        // Accept configured callback query metadata, never a second proof.
        if (question!=std::string_view::npos) {
            const auto suffix=target.substr(question+1U);
            if (!suffix.starts_with("provider=") || suffix.size()<10U || suffix.size()>137U
                || !std::ranges::all_of(suffix.substr(9U),[](char c){
                    return (c>='a' && c<='z') || (c>='A' && c<='Z')
                        || (c>='0' && c<='9') || c=='-' || c=='_';
                })) return std::nullopt;
        }
        input=request.body();
    } else return std::nullopt;
    // A percent-encoded 16 KiB Apple user object can occupy 48 KiB.
    if (input.empty() || input.size()>(request.method()==gateway::HttpMethod::Post
            ? 1024U*1024U : 64U*1024U)) return std::nullopt;
    Parameters output;
    SensitiveParameters wipeOnFailure{output};
    while (!input.empty()) {
        const auto amp = input.find('&');
        const auto pair = input.substr(0U, amp);
        const auto equals = pair.find('=');
        if (equals == std::string_view::npos) return std::nullopt;
        auto key = decodeQuery(pair.substr(0U, equals));
        auto value = decodeQuery(pair.substr(equals + 1U));
        if (!key || !value || key->empty() || key->size()>128U || output.size()>=32U
            || output.contains(*key)) {
            if (value) foundation::secureWipe(value->data(),value->size());
            return std::nullopt;
        }
        output.emplace(std::move(*key), std::move(*value));
        if (amp == std::string_view::npos) break;
        input.remove_prefix(amp + 1U);
    }
    // Moving the map does not copy credential bytes; the consumer wipes it.
    return output;
}

[[nodiscard]] std::optional<std::string> readCookie(
    const gateway::HttpRequest& request,
    std::string_view wanted, std::size_t maximum, bool& invalid)
{
    auto header = request.header("cookie");
    if (!header) return std::nullopt;
    std::optional<std::string_view> found;
    std::size_t begin = 0U;
    while (begin <= header->size()) {
        const auto end = header->find(';', begin);
        auto item = header->substr(
            begin, end == std::string_view::npos ? header->size() - begin : end - begin);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t'))
            item.remove_prefix(1U);
        const auto equal = item.find('=');
        if (equal != std::string_view::npos
            && item.substr(0U, equal) == wanted) {
            auto value = item.substr(equal + 1U);
            if (found || value.empty() || value.size() > maximum
                || !std::ranges::all_of(value, [](char c) {
                    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                        || (c >= '0' && c <= '9') || c == '-' || c == '_';
                })) {
                invalid = true;
                return std::nullopt;
            }
            found = value;
        }
        if (end == std::string_view::npos) break;
        begin = end + 1U;
    }
    return found ? std::optional<std::string>{std::string{*found}} : std::nullopt;
}

[[nodiscard]] std::optional<std::string> decodeCookie(
    std::string_view value, std::size_t maximum)
{
    auto data = foundation::fromBase64Url(value);
    if (!data || data->empty() || data->size() > maximum) return std::nullopt;
    return std::string{reinterpret_cast<const char*>(data->data()), data->size()};
}

[[nodiscard]] bool validLocalReturn(std::string_view target) noexcept
{
    return !target.empty() && target.size() <= 2048U
        && target.front() == '/' && !target.starts_with("//")
        && !target.contains('\\')
        && std::ranges::none_of(target, [](char c) {
            const auto value = static_cast<unsigned char>(c);
            return value < 0x20U || value == 0x7FU;
        });
}

[[nodiscard]] std::string encodeQueryComponent(std::string_view value)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(value.size());
    for (const char symbol : value) {
        const auto byte = static_cast<unsigned char>(symbol);
        const bool unreserved = (byte >= 'A' && byte <= 'Z')
            || (byte >= 'a' && byte <= 'z')
            || (byte >= '0' && byte <= '9')
            || byte == '-' || byte == '_' || byte == '.' || byte == '~';
        if (unreserved) {
            output.push_back(static_cast<char>(byte));
        } else {
            output.push_back('%');
            output.push_back(hex[(byte >> 4U) & 0x0fU]);
            output.push_back(hex[byte & 0x0fU]);
        }
    }
    return output;
}

[[nodiscard]] std::string appendQueryParameter(
    std::string target, std::string_view name, std::string_view value)
{
    const auto fragment = target.find('#');
    std::string suffix;
    if (fragment != std::string::npos) {
        suffix = target.substr(fragment);
        target.resize(fragment);
    }
    target.push_back(target.contains('?') ? '&' : '?');
    target.append(name);
    target.push_back('=');
    target.append(encodeQueryComponent(value));
    target.append(suffix);
    return target;
}

[[nodiscard]] gateway::HttpResponse connectionDenied(
    foundation::ErrorCode code, const gateway::HttpRequest& request, std::string target)
{
    auto location=appendQueryParameter(std::move(target),"op_error",foundation::errorCodeName(code));
    location=appendQueryParameter(std::move(location),"op_request",request.correlation().value());
    gateway::HttpResponse response{302,gateway::Headers{{"location",std::move(location)}},{}};
    secure(response);
    clearState(response);
    return response;
}

[[nodiscard]] idp::ClientContext context(const gateway::HttpRequest& request)
{
    idp::ClientContext result;
    result.setRemoteAddress(std::string{request.remoteAddress()});
    if (auto userAgent = request.header("user-agent"))
        result.setUserAgent(std::string{userAgent->substr(
            0U, std::min<std::size_t>(userAgent->size(), 1024U))});
    return result;
}

[[nodiscard]] gateway::HttpResponse unavailable()
{
    gateway::HttpResponse response{503, {}, {}};
    secure(response);
    clearState(response);
    return response;
}

} // namespace

CoroutineFederatedCallbackAdapter::CoroutineFederatedCallbackAdapter(
    AuthenticationService& authentication,
    session::CoroutineReplacingSessionIssuer& sessions,
    gateway::http::CoroutineHttpHandler& fallback)
    : m_authentication(&authentication), m_sessions(&sessions), m_fallback(&fallback)
{
}

bool CoroutineFederatedCallbackAdapter::nativeEnabledFor(
    const gateway::HttpRequest& request) const noexcept
{
    return isCallback(request) || m_fallback->nativeEnabledFor(request);
}

gateway::HttpResponse CoroutineFederatedCallbackAdapter::handle(
    gateway::HttpRequest request)
{
    request.wipeTargetQuery();
    request.wipeBody();
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();
    return unavailable();
}

asio::awaitable<gateway::HttpResponse>
CoroutineFederatedCallbackAdapter::handleAsync(gateway::HttpRequest request)
{
    if (!isCallback(request)) {
        if (m_fallback->nativeEnabledFor(request))
            co_return co_await m_fallback->handleAsync(std::move(request));
        request.wipeTargetQuery();
        request.wipeBody();
        request.wipeAuthorizationHeader();
        request.wipeCookieHeader();
        co_return unavailable();
    }
    SensitiveFederatedCallbackRequestGuard wipeRequestOnExit{request};

    // OAuth2 query and form_post, and OAuth1 query, use disjoint proof shapes.
    // The consumed transaction selects the registered provider, never query input.
    if (request.method() != gateway::HttpMethod::Get
        && request.method() != gateway::HttpMethod::Post) {
        request.wipeTargetQuery();
        request.wipeBody();
        request.wipeCookieHeader();
        co_return denied(foundation::ErrorCode::Unavailable, request);
    }

    auto values = callbackParameters(request);
    if (!values) {
        request.wipeTargetQuery();
        request.wipeCookieHeader();
        co_return denied(foundation::ErrorCode::AuthenticationFailed, request);
    }
    SensitiveParameters sensitive{*values};
    const auto code = values->find("code");
    const auto state = values->find("state");
    const auto user = values->find("user");
    const auto assertion=values->find("SAMLResponse");
    const auto relay=values->find("RelayState");
    const bool saml=assertion!=values->end() || relay!=values->end();
    const auto oauthToken=values->find("oauth_token");
    const auto oauthVerifier=values->find("oauth_verifier");
    const bool oauth1=oauthToken!=values->end() || oauthVerifier!=values->end();
    const auto bounded=[](const auto& it,const auto& end,std::size_t maximum) {
        return it!=end && !it->second.empty() && it->second.size()<=maximum
            && std::ranges::none_of(it->second,[](char c){
                const auto byte=static_cast<unsigned char>(c);
                return byte<0x20U || byte==0x7FU;
            });
    };
    const bool validProof=saml
        ? request.method()==gateway::HttpMethod::Post
            && values->size()==2U && bounded(assertion,values->end(),900U*1024U)
            && bounded(relay,values->end(),512U)
        : oauth1
        ? request.method()==gateway::HttpMethod::Get
            && bounded(oauthToken,values->end(),1024U)
            && bounded(oauthVerifier,values->end(),1024U)
            && code==values->end() && state==values->end() && user==values->end()
        : bounded(code,values->end(),4096U) && bounded(state,values->end(),512U)
            && (user==values->end() || bounded(user,values->end(),16U*1024U));
    if (values->contains("error") || values->contains("denied")
        || (!saml && request.body().size()>64U*1024U)
        || !validProof) {
        request.wipeTargetQuery();
        request.wipeCookieHeader();
        co_return denied(foundation::ErrorCode::AuthenticationFailed, request);
    }

    class CookieCopyGuard final {
    public:
        explicit CookieCopyGuard(std::optional<std::string>& value):m_value(value){}
        ~CookieCopyGuard(){
            if (m_value) foundation::secureWipe(m_value->data(),m_value->size());
        }
        CookieCopyGuard(const CookieCopyGuard&)=delete;
        CookieCopyGuard& operator=(const CookieCopyGuard&)=delete;
    private:
        std::optional<std::string>& m_value;
    };
    bool invalidCookie = false;
    auto continuation = readCookie(request, kContinuation, 256U, invalidCookie);
    auto bindingToken = readCookie(request, kBinding, 256U, invalidCookie);
    auto transaction = readCookie(request, kTransaction, 512U, invalidCookie);
    auto challenge = readCookie(request, kChallenge, 512U, invalidCookie);
    auto returning = readCookie(request, kReturn, 16U * 1024U, invalidCookie);
    auto mode = readCookie(request, kMode, 16U, invalidCookie);
    auto previous = readCookie(request, kSession, 128U, invalidCookie);
    CookieCopyGuard wipeContinuation{continuation};
    CookieCopyGuard wipeBinding{bindingToken};
    CookieCopyGuard wipeTransaction{transaction};
    CookieCopyGuard wipeChallenge{challenge};
    CookieCopyGuard wipeReturn{returning};
    CookieCopyGuard wipeMode{mode};
    CookieCopyGuard wipePrevious{previous};
    if (invalidCookie || (mode && *mode!="link") || !continuation || !bindingToken
        || !transaction || !challenge || !returning) {
        request.wipeTargetQuery();
        request.wipeCookieHeader();
        co_return denied(foundation::ErrorCode::AuthenticationFailed, request);
    }
    const auto transactionText = decodeCookie(*transaction, 512U);
    const auto challengeText = decodeCookie(*challenge, 512U);
    const auto returnTo = decodeCookie(*returning, 2048U);
    auto binding = security::sha256(*bindingToken);
    if (!transactionText || !challengeText || !returnTo || !binding
        || !validLocalReturn(*returnTo)) {
        request.wipeTargetQuery();
        request.wipeCookieHeader();
        co_return denied(foundation::ErrorCode::AuthenticationFailed, request);
    }

    auto client = context(request);
    idp::AuthenticationResponse proof{
        idp::ChallengeId{*challengeText}, client};
    if (saml) {
        proof.setParameter("SAMLResponse",idp::CredentialValue{std::move(assertion->second)});
        proof.setParameter("RelayState",idp::CredentialValue{std::move(relay->second)});
    } else if (oauth1) {
        proof.setParameter("oauth_token",idp::CredentialValue{std::move(oauthToken->second)});
        proof.setParameter("oauth_verifier",idp::CredentialValue{std::move(oauthVerifier->second)});
    } else {
        proof.setParameter("code", idp::CredentialValue{std::move(code->second)});
        proof.setParameter("state", idp::CredentialValue{std::move(state->second)});
        if (user != values->end())
            proof.setParameter("user", idp::CredentialValue{std::move(user->second)});
    }
    foundation::SecretString continuationSecret{std::move(*continuation)};
    std::optional<foundation::SecretString> previousSession;
    if (previous) previousSession.emplace(std::move(*previous));

    // Raw authorization codes, state, cookies and the original target must
    // all be removed before the first co_await; CredentialValue and
    // SecretString own their scrub-on-destroy replacements.
    sensitive.wipe();
    foundation::secureWipe(bindingToken->data(), bindingToken->size());
    bindingToken->clear();
    request.wipeTargetQuery();
    request.wipeBody();
    request.wipeAuthorizationHeader();
    request.wipeCookieHeader();

    if (mode) {
        // A link callback is never a login, even if the caller tampers with
        // the mode cookie: the coordinator consumes and checks server purpose.
        try {
            auto linked=co_await m_authentication->completeConnectionAsync(
                idp::TransactionId{*transactionText},std::move(continuationSecret),
                binding.value(),std::move(proof));
            if (!linked) co_return connectionDenied(linked.error().code(),request,*returnTo);
        } catch (...) {
            co_return connectionDenied(foundation::ErrorCode::Unavailable,request,*returnTo);
        }
        gateway::HttpResponse response{302,gateway::Headers{{"location",*returnTo}},{}};
        secure(response);
        clearState(response);
        co_return response;
    }

    foundation::Result<VerifiedAuthentication> verified =
        foundation::fail(foundation::ErrorCode::Unavailable);
    try {
        verified = co_await m_authentication->completeAsync(
            idp::TransactionId{*transactionText}, std::move(continuationSecret),
            binding.value(), std::move(proof));
    } catch (...) {
        co_return denied(foundation::ErrorCode::Unavailable, request);
    }
    if (!verified)
        co_return denied(foundation::ErrorCode::AuthenticationFailed, request);

    foundation::Result<session::CoroutineIssuedSession> issued =
        foundation::fail(foundation::ErrorCode::Unavailable);
    try {
        issued = co_await m_sessions->issueReplacingAsync(
            verified.value(), std::move(client), std::move(previousSession));
    } catch (...) {
        co_return denied(foundation::ErrorCode::Unavailable, request);
    }
    if (!issued)
        co_return denied(foundation::ErrorCode::Unavailable, request);
    if (!validSessionToken(issued->id.value())
        || !validSessionToken(issued->token.expose()))
        co_return denied(foundation::ErrorCode::Unavailable, request);

    gateway::HttpResponse response{
        302, gateway::Headers{{"location", *returnTo}}, {}};
    secure(response);
    clearState(response);
    response.addHeader("set-cookie",
        cookie(kSession, issued->token.expose(), 8 * 60 * 60, "Lax"));
    co_return response;
}

} // namespace openproof::authentication::http
