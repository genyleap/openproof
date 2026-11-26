#include <boost/json.hpp>
#include <algorithm>
#include <string_view>
#include <chrono>
#include <string>
#include <utility>
#include "coroutine_passkey_http.hpp"

import openproof.security;
import openproof.identity.provider;

namespace openproof::authentication::http {
namespace {
namespace pk=::openproof::provider::passkey;
namespace idp=identity::provider;
using E=foundation::ErrorCode;
using Method=gateway::HttpMethod;
bool listing(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/account/passkeys" && r.method()==Method::Get;
}
bool options(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/account/passkeys/options" && r.method()==Method::Post;
}
constexpr std::string_view prefix="/account/passkeys/";
constexpr std::string_view registrationCookie="__Host-openproof-passkey-registration";
bool owned(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/account/passkeys" || r.path().starts_with(prefix)
        || r.path()=="/auth/passkey/options" || r.path()=="/auth/passkey/verify";
}
bool encoded(std::string_view value,std::size_t limit) {
    return !value.empty() && value.size()<=limit && std::ranges::all_of(value,[](char c){
        return (c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9') || c=='-' || c=='_';
    });
}
std::optional<std::string> ceremonyCookie(const gateway::HttpRequest& r,std::string_view wanted=registrationCookie) {
    auto header=r.header("cookie");
    if (!header) return std::nullopt;
    auto rest=*header;
    std::optional<std::string> found;
    while (!rest.empty()) {
        const auto end=rest.find(';');
        auto item=rest.substr(0,end);
        if (end==std::string_view::npos) rest={}; else rest.remove_prefix(end+1U);
        while (!item.empty() && (item.front()==' ' || item.front()=='\t')) item.remove_prefix(1U);
        const auto eq=item.find('=');
        if (eq!=std::string_view::npos && item.substr(0,eq)==wanted) {
            auto value=item.substr(eq+1U);
            if (found || !encoded(value,256U)) return std::nullopt;
            found=std::string{value};
        }
    }
    return found;
}
foundation::Result<pk::RegistrationResponse> parseRegistration(gateway::HttpRequest& r) {
    const auto media=r.header("content-type");
    if (!media || (*media!="application/json" && !media->starts_with("application/json;"))
        || r.body().empty() || r.body().size()>128U*1024U)
        return foundation::fail(E::InvalidArgument);
    boost::system::error_code error;
    auto value=boost::json::parse(r.body(),error);
    r.wipeBody();
    if (error || !value.is_object() || value.as_object().size()!=3U)
        return foundation::fail(E::InvalidArgument);
    const auto field=[&](std::string_view name,std::size_t limit)->std::optional<std::string>{
        const auto* item=value.as_object().if_contains(name);
        if (!item || !item->is_string()) return std::nullopt;
        const auto& s=item->as_string();
        if (!encoded(std::string_view{s.data(),s.size()},limit)) return std::nullopt;
        return std::string{s.data(),s.size()};
    };
    auto id=field("credential_id",4096U),client=field("client_data_json",32U*1024U),
        attestation=field("attestation_object",128U*1024U);
    if (!id || !client || !attestation) return foundation::fail(E::InvalidArgument);
    return pk::RegistrationResponse{std::move(*id),std::move(*client),std::move(*attestation)};
}
void scrub(gateway::HttpRequest& r) noexcept {
    r.wipeBody(); r.wipeAuthorizationHeader(); r.wipeCookieHeader(); r.wipeTargetQuery();
}
struct Scrub final {gateway::HttpRequest& request; ~Scrub(){scrub(request);}};
gateway::HttpResponse response(int status,std::string body) {
    gateway::HttpResponse out{status,gateway::Headers{{"content-type","application/json"}},std::move(body)};
    out.setHeader("cache-control","no-store");
    out.setHeader("pragma","no-cache");
    out.setHeader("x-content-type-options","nosniff");
    out.setHeader("referrer-policy","no-referrer");
    return out;
}
gateway::HttpResponse fail(E code,const gateway::HttpRequest& r) {
    auto out=response(foundation::errorHttpStatus(code),
        foundation::toClientJson(foundation::Error{code},r.correlation().value()));
    if (code==E::AuthenticationRequired) out.setHeader("www-authenticate","Bearer");
    return out;
}
}
CoroutinePasskeyProvider::CoroutinePasskeyProvider(const pk::PasskeyConfig& config,
    const foundation::ClockSource& clock,Verify verify):m_config(&config),m_clock(&clock),m_verify(std::move(verify)) {}
idp::ProviderId CoroutinePasskeyProvider::id() const {return idp::ProviderId{"passkey"};}
idp::InteractionModel CoroutinePasskeyProvider::interactionModel() const noexcept {return idp::InteractionModel::ChallengeResponse;}
idp::AssuranceLevel CoroutinePasskeyProvider::maximumClaimableAssurance() const noexcept {return idp::AssuranceLevel::Ial2;}
foundation::Result<idp::AuthenticationChallenge> CoroutinePasskeyProvider::beginAuthentication(const idp::AuthenticationRequest&) {
    return foundation::fail(E::Unavailable);
}
foundation::Result<idp::AuthenticationOutcome> CoroutinePasskeyProvider::completeAuthentication(const idp::AuthenticationResponse&) {
    return foundation::fail(E::Unavailable);
}
boost::asio::awaitable<foundation::Result<idp::AuthenticationChallenge>>
CoroutinePasskeyProvider::beginAuthenticationAsync(idp::AuthenticationRequest request) {
    if (request.provider()!=id()) co_return foundation::fail(E::InvalidArgument);
    co_return pk::assertionOptions(*m_config,m_clock->now());
}
boost::asio::awaitable<foundation::Result<idp::AuthenticationOutcome>>
CoroutinePasskeyProvider::completeAuthenticationAsync(idp::AuthenticationResponse response) {
    const auto& fields=response.parameters();
    const auto get=[&](std::string_view name,std::size_t maximum)->std::optional<std::string>{
        const auto it=fields.find(name);
        if (it==fields.end() || !encoded(it->second.expose(),maximum)) return std::nullopt;
        return std::string{it->second.expose()};
    };
    auto credential=get("credential_id",4096U),client=get("client_data_json",32U*1024U),
        data=get("authenticator_data",128U*1024U),signature=get("signature",4096U);
    auto handle=get("user_handle",4096U);
    if (!m_verify || !credential || !client || !data || !signature
        || (fields.contains("user_handle") && !handle) || fields.size()!=(handle?5U:4U))
        co_return foundation::fail(E::AuthenticationFailed);
    auto credentialId=*credential;
    const auto now=m_clock->now();
    pk::AssertionResponse assertion{std::move(*credential),std::move(*client),std::move(*data),
        std::move(*signature),std::move(handle)};
    auto owner=co_await m_verify(response.challengeId(),std::move(assertion),now);
    if (!owner || owner->empty()) co_return foundation::fail(E::AuthenticationFailed);
    idp::ProviderEvidence evidence;
    evidence.add("protocol","webauthn_level3");
    evidence.add("credential_id",credentialId);
    evidence.add("algorithm","ES256");
    evidence.add("user_verification","required");
    co_return idp::AuthenticationOutcome::create(id(),idp::ExternalSubject{std::string{owner->value()}},
        idp::VerifiedClaims{},idp::AssuranceLevel::Ial2,
        idp::AuthenticationStrength{idp::AuthenticationFactor::Possession,true},std::move(evidence),now,
        std::string{owner->value()});
}

CoroutinePasskeyAccountAdapter::CoroutinePasskeyAccountAdapter(
    gateway::http::CoroutineHttpHandler& fallback,gateway::TokenBucketRateLimiter& limiter,
    const foundation::ClockSource& clock,const pk::PasskeyConfig& config,Authenticate authenticate,Read read,Mutate mutate,
    AuthenticationService* authentication,session::CoroutineReplacingSessionIssuer* issuer)
    :m_fallback(&fallback),m_limiter(&limiter),m_clock(&clock),m_config(&config),
    m_authenticate(std::move(authenticate)),m_read(std::move(read)),m_mutate(std::move(mutate)),
    m_authentication(authentication),m_issuer(issuer) {}

bool CoroutinePasskeyAccountAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    return owned(r) || m_fallback->nativeEnabledFor(r);
}
gateway::HttpResponse CoroutinePasskeyAccountAdapter::handle(gateway::HttpRequest r) {
    scrub(r);
    return fail(E::Unavailable,r);
}
boost::asio::awaitable<gateway::HttpResponse> CoroutinePasskeyAccountAdapter::handleAsync(gateway::HttpRequest r) {
    const bool begin=options(r);
    const bool registration=r.path()=="/account/passkeys" && r.method()==Method::Post;
    const bool removal=r.path().starts_with(prefix) && r.method()==Method::Delete;
    if (!owned(r)) {
        if (m_fallback->nativeEnabledFor(r)) co_return co_await m_fallback->handleAsync(std::move(r));
        scrub(r); co_return fail(E::Unavailable,r);
    }
    if (r.path()=="/auth/passkey/options" || r.path()=="/auth/passkey/verify")
        co_return co_await assertion(std::move(r));
    Scrub wipe{r};
    if (!begin && !listing(r) && !registration && !removal)
        co_return response(405,R"({"error":"method_not_allowed"})");
    if (!m_authenticate || ((begin || listing(r)) && !m_read) ||
        ((registration || removal) && !m_mutate)) co_return fail(E::Unavailable,r);
    if (!m_limiter->allow("passkey:"+std::string{r.remoteAddress()}+":"+std::string{r.path()}))
        co_return fail(E::RateLimited,r);
    if (r.header("authorization").value_or("").starts_with("DPoP "))
        co_return fail(E::AuthenticationFailed,r);
    if (begin || registration || removal) {
        if (auto origin=r.header("origin"); origin && *origin!=m_config->origin())
            co_return fail(E::PermissionDenied,r);
    }
    std::optional<identity::provider::ChallengeId> registrationId;
    std::optional<pk::RegistrationResponse> registrationInput;
    std::string removeId;
    if (registration) {
        auto id=ceremonyCookie(r);
        auto parsed=parseRegistration(r);
        if (!id || !parsed) co_return fail(E::InvalidArgument,r);
        registrationId.emplace(std::move(*id));
        registrationInput.emplace(std::move(parsed).value());
    } else if (removal) {
        const auto id=r.path().substr(prefix.size());
        if (!encoded(id,4096U)) co_return fail(E::InvalidArgument,r);
        removeId=std::string{id};
    }
    auto credential=gateway::takeSessionCredential(r);
    if (!credential) co_return fail(credential.error().code(),r);
    if (!credential->has_value()) co_return fail(E::AuthenticationRequired,r);
    scrub(r);
    auto actor=co_await m_authenticate(std::move(credential->value()));
    if (!actor) co_return fail(actor.error().code(),r);
    const auto now=m_clock->now();
    if (registration || removal) {
        std::optional<pk::PasskeyCredential> verified;
        if (registration) {
            auto checked=pk::verifyRegistration(*m_config,actor->identity(),*registrationId,*registrationInput,now);
            registrationInput.reset();
            if (!checked) {
                auto out=fail(checked.error().code(),r);
                out.addHeader("set-cookie",std::string{registrationCookie}+"=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
                co_return out;
            }
            removeId=checked->credentialId;
            verified.emplace(std::move(checked).value());
        }
        auto changed=co_await m_mutate(actor->identity(),actor->id(),now,std::move(removeId),
            std::move(registrationId),std::move(verified));
        auto out=changed?response(registration?201:200,registration?R"({"registered":true})":R"({"removed":true})")
            :fail(changed.error().code(),r);
        if (registration) out.addHeader("set-cookie",std::string{registrationCookie}+
            "=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
        co_return out;
    }
    std::optional<pk::RegistrationCeremony> ceremony;
    if (begin) {
        auto random=security::randomTokenBase64Url(24U);
        if (!random || now.time_since_epoch().count()<0
            || now.time_since_epoch().count()>foundation::Duration::max().count()-m_config->ceremonyLifetime().count())
            co_return fail(E::Unavailable,r);
        ceremony.emplace(pk::RegistrationCeremony{identity::provider::ChallengeId{"pkr_"+random.value()},
            actor->identity(),now+m_config->ceremonyLifetime()});
    }
    auto credentials=co_await m_read(actor->identity(),actor->id(),now,ceremony);
    if (!credentials) co_return fail(credentials.error().code(),r);
    if (ceremony) {
        std::vector<std::string> excluded;
        for (const auto& item:credentials.value()) excluded.push_back(item.credentialId);
        auto started=pk::registrationOptions(*m_config,actor->identity(),ceremony->id,excluded);
        if (!started) co_return fail(started.error().code(),r);
        boost::system::error_code error;
        auto parsed=boost::json::parse(started->publicKeyOptionsJson,error);
        if (error || !parsed.is_object()) co_return fail(E::Internal,r);
        boost::json::object body;
        body["publicKey"]=std::move(parsed);
        auto out=response(200,boost::json::serialize(body));
        const auto age=std::chrono::ceil<std::chrono::seconds>(m_config->ceremonyLifetime()).count();
        out.addHeader("set-cookie","__Host-openproof-passkey-registration="+
            std::string{started->ceremonyId.value()}+"; Path=/; Max-Age="+std::to_string(age)+
            "; Secure; HttpOnly; SameSite=Strict");
        co_return out;
    }
    boost::json::array items;
    for (const auto& item:credentials.value()) {
        items.emplace_back(boost::json::object{{"credential_id",item.credentialId},
            {"sign_count",item.signCount},{"created_at_ms",item.createdAt.time_since_epoch().count()},
            {"last_used_at_ms",item.lastUsedAt.time_since_epoch().count()}});
    }
    boost::json::object body;
    body["passkeys"]=std::move(items);
    co_return response(200,boost::json::serialize(body));
}

boost::asio::awaitable<gateway::HttpResponse> CoroutinePasskeyAccountAdapter::assertion(gateway::HttpRequest r) {
    Scrub wipe{r};
    constexpr std::string_view continuation="__Host-openproof-passkey-continuation";
    constexpr std::string_view bindingCookie="__Host-openproof-passkey-binding";
    constexpr std::string_view transaction="__Host-openproof-passkey-transaction";
    constexpr std::string_view challenge="__Host-openproof-passkey-challenge";
    const auto cookie=[](std::string_view name,std::string_view value,int age) {
        return std::string{name}+"="+std::string{value}+"; Path=/; Max-Age="+std::to_string(age)+"; Secure; HttpOnly; SameSite=Strict";
    };
    const auto clear=[&](gateway::HttpResponse& out){
        for (const auto name:{continuation,bindingCookie,transaction,challenge}) out.addHeader("set-cookie",cookie(name,"",0));
    };
    if (r.method()!=Method::Post) co_return response(405,R"({"error":"method_not_allowed"})");
    if (!m_authentication || !m_issuer) co_return fail(E::Unavailable,r);
    if (!m_limiter->allow("passkey:"+std::string{r.remoteAddress()}+":"+std::string{r.path()}))
        co_return fail(E::RateLimited,r);
    if (r.header("authorization")) co_return fail(E::AuthenticationFailed,r);
    if (auto origin=r.header("origin");origin && *origin!=m_config->origin()) co_return fail(E::PermissionDenied,r);
    idp::ClientContext client;
    client.setRemoteAddress(std::string{r.remoteAddress()});
    if (const auto agent=r.header("user-agent")) client.setUserAgent(std::string{agent->substr(0,1024U)});
    if (r.path()=="/auth/passkey/options") {
        auto random=security::randomTokenBase64Url(32U);
        if (!random) co_return fail(E::Unavailable,r);
        foundation::SecretString token{std::move(random).value()};
        auto digest=security::sha256(token.expose());
        if (!digest) co_return fail(E::Unavailable,r);
        idp::AuthenticationRequest request{idp::ProviderId{"passkey"},client};
        request.setRequestedAssurance(idp::AssuranceLevel::Ial2);
        scrub(r);
        auto started=co_await m_authentication->beginAsync(std::move(request),digest.value(),r.correlation());
        if (!started) co_return fail(started.error().code(),r);
        const auto found=started->challenge().parameters().find("public_key_options");
        if (found==started->challenge().parameters().end()) co_return fail(E::Internal,r);
        boost::system::error_code error;
        auto options=boost::json::parse(found->second,error);
        if (error || !options.is_object()) co_return fail(E::Internal,r);
        boost::json::object body; body["publicKey"]=std::move(options);
        auto out=response(200,boost::json::serialize(body));
        out.addHeader("set-cookie",cookie(continuation,started->continuationToken().expose(),300));
        out.addHeader("set-cookie",cookie(bindingCookie,token.expose(),300));
        out.addHeader("set-cookie",cookie(transaction,started->transactionId().value(),300));
        out.addHeader("set-cookie",cookie(challenge,started->challenge().id().value(),300));
        co_return out;
    }
    auto rawContinuation=ceremonyCookie(r,continuation),rawBinding=ceremonyCookie(r,bindingCookie);
    auto transactionId=ceremonyCookie(r,transaction),challengeId=ceremonyCookie(r,challenge);
    std::optional<foundation::SecretString> continuationToken,bindingToken,previous;
    if (rawContinuation) continuationToken.emplace(std::move(*rawContinuation));
    if (rawBinding) bindingToken.emplace(std::move(*rawBinding));
    if (auto rawPrevious=ceremonyCookie(r,"__Host-openproof-session")) previous.emplace(std::move(*rawPrevious));
    const auto media=r.header("content-type");
    if (!continuationToken || !bindingToken || !transactionId || !challengeId || !media
        || (*media!="application/json" && !media->starts_with("application/json;")) || r.body().size()>128U*1024U) {
        auto out=fail(E::AuthenticationFailed,r); clear(out); co_return out;
    }
    boost::system::error_code error;
    auto parsed=boost::json::parse(r.body(),error);
    r.wipeBody();
    if (error || !parsed.is_object()) {auto out=fail(E::AuthenticationFailed,r); clear(out); co_return out;}
    idp::AuthenticationResponse input{idp::ChallengeId{*challengeId},client};
    const auto add=[&](std::string_view key,std::size_t limit,bool optional){
        const auto* item=parsed.as_object().if_contains(key);
        if (!item || item->is_null()) return optional;
        if (!item->is_string() || !encoded(std::string_view{item->as_string().data(),item->as_string().size()},limit)) return false;
        input.setParameter(std::string{key},idp::CredentialValue{std::string{item->as_string().data(),item->as_string().size()}});
        return true;
    };
    if (!add("credential_id",4096U,false) || !add("client_data_json",32U*1024U,false)
        || !add("authenticator_data",128U*1024U,false) || !add("signature",4096U,false)
        || !add("user_handle",4096U,true) || parsed.as_object().size()>5U) {
        auto out=fail(E::AuthenticationFailed,r); clear(out); co_return out;
    }
    parsed=nullptr;
    auto digest=security::sha256(bindingToken->expose());
    bindingToken.reset();
    if (!digest) co_return fail(E::Unavailable,r);
    scrub(r);
    auto verified=co_await m_authentication->completeAsync(idp::TransactionId{*transactionId},
        std::move(*continuationToken),digest.value(),std::move(input));
    if (!verified || verified->outcome().provider()!=idp::ProviderId{"passkey"}
        || !idp::meetsAssurance(verified->outcome().claimedAssurance(),idp::AssuranceLevel::Ial2)) {
        auto out=fail(verified?E::AuthenticationFailed:verified.error().code(),r);
        clear(out);co_return out;
    }
    auto issued=co_await m_issuer->issueReplacingAsync(verified.value(),std::move(client),std::move(previous));
    if (!issued) {auto out=fail(issued.error().code(),r);clear(out);co_return out;}
    boost::json::object body{{"session_id",issued->id.value()},{"assurance","ial2"}};
    auto out=response(200,boost::json::serialize(body));
    clear(out);
    out.addHeader("set-cookie",cookie("__Host-openproof-session",issued->token.expose(),8*60*60));
    co_return out;
}
}
