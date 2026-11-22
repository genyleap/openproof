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
            if (i + 2U >= source.size()) return std::nullopt;
            const auto high = hexValue(source[i + 1U]);
            const auto low = hexValue(source[i + 2U]);
            if (!high || !low) return std::nullopt;
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

[[nodiscard]] std::optional<Parameters> query(const gateway::HttpRequest& request)
{
    const auto target = request.target();
    const auto question = target.find('?');
    if (question == std::string_view::npos) return std::nullopt;
    auto input = target.substr(question + 1U);
    if (input.empty() || input.size() > 20U * 1024U) return std::nullopt;
    Parameters output;
    SensitiveParameters wipeOnFailure{output};
    while (!input.empty()) {
        const auto amp = input.find('&');
        const auto pair = input.substr(0U, amp);
        const auto equals = pair.find('=');
        if (equals == std::string_view::npos) return std::nullopt;
        auto key = decodeQuery(pair.substr(0U, equals));
        auto value = decodeQuery(pair.substr(equals + 1U));
        if (!key || !value || key->empty() || output.contains(*key))
            return std::nullopt;
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

    // The native opt-in initially supports only OAuth2 GET redirects.
    // SAML/POST, OAuth1 and account connection ceremonies remain disabled.
    if (request.method() != gateway::HttpMethod::Get) {
        request.wipeTargetQuery();
        request.wipeBody();
        request.wipeCookieHeader();
        co_return denied(foundation::ErrorCode::Unavailable, request);
    }

    auto values = query(request);
    if (!values) {
        request.wipeTargetQuery();
        request.wipeCookieHeader();
        co_return denied(foundation::ErrorCode::AuthenticationFailed, request);
    }
    SensitiveParameters sensitive{*values};
    const auto code = values->find("code");
    const auto state = values->find("state");
    const auto user = values->find("user");
    if (values->contains("error") || values->contains("denied")
        || values->contains("SAMLResponse") || values->contains("RelayState")
        || values->contains("oauth_token") || values->contains("oauth_verifier")
        || code == values->end() || state == values->end()
        || code->second.empty() || code->second.size() > 4096U
        || state->second.empty() || state->second.size() > 512U
        || (user != values->end() &&
            (user->second.empty() || user->second.size() > 16U * 1024U))) {
        request.wipeTargetQuery();
        request.wipeCookieHeader();
        co_return denied(foundation::ErrorCode::AuthenticationFailed, request);
    }

    bool invalidCookie = false;
    auto continuation = readCookie(request, kContinuation, 256U, invalidCookie);
    auto bindingToken = readCookie(request, kBinding, 256U, invalidCookie);
    auto transaction = readCookie(request, kTransaction, 512U, invalidCookie);
    auto challenge = readCookie(request, kChallenge, 512U, invalidCookie);
    auto returning = readCookie(request, kReturn, 16U * 1024U, invalidCookie);
    auto mode = readCookie(request, kMode, 16U, invalidCookie);
    auto previous = readCookie(request, kSession, 128U, invalidCookie);
    if (invalidCookie || mode || !continuation || !bindingToken
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
    proof.setParameter("code", idp::CredentialValue{std::move(code->second)});
    proof.setParameter("state", idp::CredentialValue{std::move(state->second)});
    if (user != values->end())
        proof.setParameter("user", idp::CredentialValue{std::move(user->second)});
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
