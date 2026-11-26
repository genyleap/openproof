#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/json.hpp>
#include <atomic>
#include <chrono>
#include <exception>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include "coroutine_evidence_http.hpp"

import openproof.security;
import openproof.identity.provider;

namespace openproof::evidence::http {
namespace {
namespace asio=boost::asio;
namespace json=boost::json;
namespace idp=identity::provider;
namespace ev=verification;
using E=foundation::ErrorCode;
using Op=ev::AccountOperation;
struct WorkerState final {
    std::map<std::string,std::unique_ptr<EvidenceVerifier>,std::less<>> verifiers;
    std::atomic<bool> busy{false};
};
struct Permit final {
    explicit Permit(std::shared_ptr<WorkerState> value):state(std::move(value)) {}
    Permit(Permit&&) noexcept=default;
    Permit(const Permit&)=delete;
    ~Permit(){if(state) state->busy.store(false,std::memory_order_release);}
    std::shared_ptr<WorkerState> state;
};
asio::awaitable<foundation::Result<std::vector<Evidence>>> proofWorker(Permit permit,
    identity::core::IdentityId actor,idp::ProviderId provider,
    idp::AttributeMap inputs,idp::SecretAttributeMap secrets,foundation::Instant now)
{
    struct WipeChallenge final {
        idp::AttributeMap& inputs;
        ~WipeChallenge(){if(auto it=inputs.find("challenge");it!=inputs.end())
            foundation::secureWipe(it->second.data(),it->second.size());}
    } wipe{inputs};
    const auto found=permit.state->verifiers.find(provider.value());
    if (found==permit.state->verifiers.end()) co_return foundation::fail(E::NotFound);
    co_return found->second->verify(actor,inputs,secrets,now);
}
bool owned(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/evidence" || r.path()=="/trust" || r.path().starts_with("/evidence/");
}
void scrub(gateway::HttpRequest& r) noexcept {
    r.wipeBody();r.wipeAuthorizationHeader();r.wipeCookieHeader();r.wipeTargetQuery();
}
struct Scrub final {gateway::HttpRequest& request;~Scrub(){scrub(request);}};
gateway::HttpResponse response(int status,json::value body){
    gateway::HttpResponse out{status,gateway::Headers{{"content-type","application/json"}},json::serialize(body)};
    out.setHeader("cache-control","no-store");out.setHeader("pragma","no-cache");
    out.setHeader("x-content-type-options","nosniff");out.setHeader("referrer-policy","no-referrer");
    return out;
}
gateway::HttpResponse failure(E code,const gateway::HttpRequest& r){
    gateway::HttpResponse out{foundation::errorHttpStatus(code),gateway::Headers{{"content-type","application/json"}},
        foundation::toClientJson(foundation::Error{code},r.correlation().value())};
    out.setHeader("cache-control","no-store");out.setHeader("pragma","no-cache");
    out.setHeader("x-content-type-options","nosniff");out.setHeader("referrer-policy","no-referrer");
    if(code==E::AuthenticationRequired) out.setHeader("www-authenticate","Bearer");
    return out;
}
json::array recordsJson(const std::vector<Evidence>& records){
    json::array items;
    for(const auto& item:records){
        json::object row{{"id",item.id().str()},{"provider",item.provider().str()},
            {"kind",std::string{item.kind()}},{"claim",std::string{item.claim()}},{"value",std::string{item.value()}},
            {"confidence",item.confidence()},{"status",item.status()==EvidenceStatus::Verified?"verified":"revoked"},
            {"verified_at",foundation::toIso8601(item.verifiedAt())}};
        if(item.expiresAt()) row["expires_at"]=foundation::toIso8601(*item.expiresAt());
        items.push_back(std::move(row));
    }
    return items;
}
struct ProofInput final {
    std::string provider;
    foundation::SecretString challenge;
    idp::AttributeMap inputs;
    idp::SecretAttributeMap secrets;
};
foundation::Result<ProofInput> parse(gateway::HttpRequest& r,bool verify){
    if(r.body().empty() || r.body().size()>96U*1024U) return foundation::fail(E::InvalidArgument);
    boost::system::error_code ec;
    auto body=json::parse(r.body(),ec);
    r.wipeBody();
    if(ec || !body.is_object()) return foundation::fail(E::InvalidArgument);
    auto& object=body.as_object();
    // Wipe every parsed string (including rejected fields) before releasing it.
    struct WipeObject final {json::object& value;~WipeObject(){
        for(auto& field:value) if(field.value().is_string()){
            auto& s=field.value().as_string();foundation::secureWipe(s.data(),s.size());
        }
    }} wipe{object};
    const auto field=[&](std::string_view name,std::size_t limit)->std::optional<std::string>{
        const auto* item=object.if_contains(name);
        if(!item || !item->is_string() || item->as_string().empty() || item->as_string().size()>limit)
            return std::nullopt;
        return std::string{item->as_string().data(),item->as_string().size()};
    };
    auto provider=field("provider",200U);
    if(!provider) return foundation::fail(E::InvalidArgument);
    ProofInput out{std::move(*provider),foundation::SecretString{""},{},{}};
    if(!verify) {
        if(object.size()!=1U) return foundation::fail(E::InvalidArgument);
        return out;
    }
    auto challenge=field("challenge",256U);
    if(!challenge) return foundation::fail(E::InvalidArgument);
    out.challenge=foundation::SecretString{std::move(*challenge)};
    if(out.provider=="signed-jwt-evidence"){
        auto assertion=field("assertion",16U*1024U);
        if(!assertion || object.size()!=3U) return foundation::fail(E::InvalidArgument);
        out.secrets.emplace("assertion",idp::CredentialValue{std::move(*assertion)});
    }else if(out.provider=="x509-evidence"){
        auto certificate=field("certificate_pem",64U*1024U),signature=field("signature",12U*1024U);
        if(!certificate || !signature || object.size()!=4U) return foundation::fail(E::InvalidArgument);
        out.inputs.emplace("certificate_pem",std::move(*certificate));
        out.secrets.emplace("signature",idp::CredentialValue{std::move(*signature)});
    }else return foundation::fail(E::NotFound);
    return out;
}
}
class CoroutineEvidenceAdapter::Impl final {
public:
    explicit Impl(std::vector<std::unique_ptr<EvidenceVerifier>> verifiers)
        :state(std::make_shared<WorkerState>()),pool(1U){
        for(auto& verifier:verifiers) state->verifiers.emplace(verifier->provider().str(),std::move(verifier));
    }
    ~Impl(){pool.join();}
    std::shared_ptr<WorkerState> state;
    asio::thread_pool pool;
};
CoroutineEvidenceAdapter::CoroutineEvidenceAdapter(gateway::http::CoroutineHttpHandler& fallback,
    gateway::TokenBucketRateLimiter& limiter,const foundation::ClockSource& clock,
    std::vector<std::unique_ptr<EvidenceVerifier>> verifiers,trust::TrustPolicy policy,
    Authenticate authenticate,Store store)
    :m_impl(std::make_unique<Impl>(std::move(verifiers))),m_fallback(&fallback),m_limiter(&limiter),
    m_clock(&clock),m_policy(std::move(policy)),m_authenticate(std::move(authenticate)),m_store(std::move(store)){}
CoroutineEvidenceAdapter::~CoroutineEvidenceAdapter()=default;
bool CoroutineEvidenceAdapter::nativeEnabledFor(const gateway::HttpRequest& r)const noexcept{
    return owned(r)||m_fallback->nativeEnabledFor(r);
}
gateway::HttpResponse CoroutineEvidenceAdapter::handle(gateway::HttpRequest r){
    scrub(r);return failure(E::Unavailable,r);
}
asio::awaitable<gateway::HttpResponse> CoroutineEvidenceAdapter::handleAsync(gateway::HttpRequest r){
    if(!owned(r)){
        if(m_fallback->nativeEnabledFor(r)) co_return co_await m_fallback->handleAsync(std::move(r));
        scrub(r);co_return failure(E::Unavailable,r);
    }
    Scrub wipe{r};
    using Method=gateway::HttpMethod;
    const bool issue=r.path()=="/evidence/challenge" && r.method()==Method::Post;
    const bool verify=r.path()=="/evidence/verify" && r.method()==Method::Post;
    const bool list=r.path()=="/evidence" && r.method()==Method::Get;
    const bool assess=r.path()=="/trust" && r.method()==Method::Get;
    if(!m_limiter->allow("evidence:"+std::string{r.remoteAddress()}+":"+std::string{r.path()}))
        co_return failure(E::RateLimited,r);
    if(!issue && !verify && !list && !assess) co_return response(404,json::object{{"error","not_found"}});
    if(!m_authenticate || !m_store) co_return failure(E::Unavailable,r);
    if(r.header("authorization").value_or("").starts_with("DPoP ")) co_return failure(E::AuthenticationFailed,r);
    auto token=gateway::takeSessionCredential(r);
    if(!token) co_return failure(token.error().code(),r);
    if(!token->has_value()) co_return failure(E::AuthenticationRequired,r);
    std::optional<ProofInput> proof;
    if(issue || verify){
        auto parsed=parse(r,verify);
        if(!parsed) co_return failure(parsed.error().code(),r);
        proof.emplace(std::move(parsed).value());
        if(!m_impl->state->verifiers.contains(proof->provider)) co_return failure(E::NotFound,r);
    }
    scrub(r);
    try{
        auto actor=co_await m_authenticate(std::move(token->value()));
        if(!actor) co_return failure(actor.error().code(),r);
        const auto now=m_clock->now();
        if(list || assess){
            auto rows=co_await m_store(actor->identity(),actor->id(),now,
                ev::AccountCommand{Op::List,idp::ProviderId{""},ev::ChallengeDigest{""},{},{}});
            if(!rows) co_return failure(rows.error().code(),r);
            if(list) co_return response(200,json::object{{"evidence",recordsJson(rows.value())}});
            auto assessment=trust::assessEvidence(actor->identity(),rows.value(),m_policy,now);
            if(!assessment) co_return failure(assessment.error().code(),r);
            json::array ids;
            for(const auto& id:assessment->evidenceIds()) ids.emplace_back(id);
            co_return response(200,json::object{{"identity",actor->identity().str()},
                {"trust_score",assessment->trustScore()},{"risk_score",assessment->riskScore()},
                {"confidence",assessment->confidence()},{"evidence_ids",std::move(ids)}});
        }
        const idp::ProviderId provider{proof->provider};
        if(issue){
            auto raw=security::randomTokenBase64Url(32U);
            if(!raw) co_return failure(raw.error().code(),r);
            foundation::SecretString challenge{std::move(raw).value()};
            auto digest=security::sha256(challenge.expose());
            if(!digest) co_return failure(digest.error().code(),r);
            const auto expiry=now+std::chrono::minutes{5};
            auto stored=co_await m_store(actor->identity(),actor->id(),now,
                ev::AccountCommand{Op::Issue,provider,ev::ChallengeDigest{foundation::toHex(digest.value())},expiry,{}});
            if(!stored) co_return failure(stored.error().code(),r);
            json::object body{{"provider",proof->provider},{"challenge",challenge.expose()},
                {"subject",actor->identity().str()},{"expires_at",foundation::toIso8601(expiry)}};
            if(proof->provider=="x509-evidence")
                body["proof_message"]="OpenProof Evidence Proof\n"+challenge.expose()+"\n"+actor->identity().str();
            co_return response(201,std::move(body));
        }
        // Admission precedes challenge consumption; cancelled requests cannot
        // release a permit until the worker frame has actually finished.
        bool expected=false;
        if(!m_impl->state->busy.compare_exchange_strong(expected,true,std::memory_order_acq_rel))
            co_return failure(E::RateLimited,r);
        Permit permit{m_impl->state};
        auto digest=security::sha256(proof->challenge.expose());
        if(!digest) co_return failure(digest.error().code(),r);
        auto consumed=co_await m_store(actor->identity(),actor->id(),now,
            ev::AccountCommand{Op::Consume,provider,ev::ChallengeDigest{foundation::toHex(digest.value())},{},{}});
        if(!consumed) co_return failure(consumed.error().code(),r);
        proof->inputs.emplace("challenge",proof->challenge.expose());
        auto verified=co_await asio::co_spawn(m_impl->pool,
            proofWorker(std::move(permit),actor->identity(),provider,std::move(proof->inputs),std::move(proof->secrets),now),
            asio::use_awaitable);
        if(!verified) co_return failure(verified.error().code(),r);
        auto persisted=co_await m_store(actor->identity(),actor->id(),m_clock->now(),
            ev::AccountCommand{Op::Persist,provider,ev::ChallengeDigest{""},{},std::move(verified).value()});
        if(!persisted) co_return failure(persisted.error().code(),r);
        co_return response(201,json::object{{"evidence",recordsJson(persisted.value())}});
    }catch(const std::exception&){co_return failure(E::Unavailable,r);}
}
}
