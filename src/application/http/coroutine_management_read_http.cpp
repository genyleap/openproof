#include <boost/json.hpp>
#include <algorithm>
#include <string_view>
#include <utility>
#include "coroutine_management_read_http.hpp"

import openproof.identity.provider;
import openproof.security;

namespace openproof::application::http {
namespace {
using E=foundation::ErrorCode;
using Method=gateway::HttpMethod;
std::optional<ManagementRead> operation(const gateway::HttpRequest& r) noexcept {
    if (r.method()!=Method::Get) return std::nullopt;
    if (r.path()=="/admin/applications") return ManagementRead::Applications;
    if (r.path()=="/admin/clients") return ManagementRead::Clients;
    if (r.path()=="/admin/clients/jar-key") return ManagementRead::JarKey;
    if (r.path()=="/admin/resources") return ManagementRead::Resources;
    if (r.path()=="/admin/service-identities") return ManagementRead::ServiceIdentity;
    return std::nullopt;
}
std::optional<ApplicationMutation> mutation(const gateway::HttpRequest& r) noexcept {
    if (r.method()!=Method::Post) return std::nullopt;
    if (r.path()=="/admin/applications") return ApplicationMutation::Create;
    if (r.path()=="/admin/applications/suspend") return ApplicationMutation::Suspend;
    if (r.path()=="/admin/applications/activate") return ApplicationMutation::Activate;
    if (r.path()=="/admin/applications/revoke") return ApplicationMutation::Revoke;
    return std::nullopt;
}
foundation::Result<ApplicationMutationCommand> parseMutation(gateway::HttpRequest& r,ApplicationMutation op) {
    namespace json=boost::json;
    const auto media=r.header("content-type");
    if (!media || (*media!="application/json" && !media->starts_with("application/json;"))
        || r.body().empty() || r.body().size()>32U*1024U)
        return foundation::fail(E::InvalidArgument);
    boost::system::error_code error;
    auto value=json::parse(r.body(),error);
    r.wipeBody();
    if (error || !value.is_object()) return foundation::fail(E::InvalidArgument);
    const auto& object=value.as_object();
    const auto field=[&](std::string_view name,std::size_t limit)->std::optional<std::string> {
        const auto* item=object.if_contains(name);
        if (!item || !item->is_string()) return std::nullopt;
        const auto& text=item->as_string();
        if (text.empty() || text.size()>limit
            || std::ranges::any_of(text,[](unsigned char c){return c<0x20U || c==0x7fU;}))
            return std::nullopt;
        return std::string{text.data(),text.size()};
    };
    if (op!=ApplicationMutation::Create) {
        auto id=field("application_id",200U);
        if (object.size()!=1U || !id) return foundation::fail(E::InvalidArgument);
        return ApplicationMutationCommand{op,ApplicationId{std::move(*id)}, {}, {}};
    }
    auto identifier=field("identifier",64U),name=field("name",120U),environment=field("environment",32U);
    if (object.size()!=3U || !identifier || !name || !environment)
        return foundation::fail(E::InvalidArgument);
    Environment parsed;
    if (*environment=="development") parsed=Environment::Development;
    else if (*environment=="staging") parsed=Environment::Staging;
    else if (*environment=="production") parsed=Environment::Production;
    else return foundation::fail(E::InvalidArgument);
    auto id=security::randomTokenBase64Url(24U);
    if (!id) return foundation::fail(id.error());
    return ApplicationMutationCommand{op,ApplicationId{std::move(id).value()},std::move(*identifier),
        std::move(*name),parsed};
}
void scrub(gateway::HttpRequest& r) noexcept {
    r.wipeBody(); r.wipeAuthorizationHeader(); r.wipeCookieHeader(); r.wipeTargetQuery();
}
struct Scrub {gateway::HttpRequest& request; ~Scrub(){scrub(request);}};
gateway::HttpResponse response(int status,std::string body) {
    gateway::HttpResponse result{status,gateway::Headers{{"content-type","application/json"}},std::move(body)};
    result.setHeader("cache-control","no-store");
    result.setHeader("pragma","no-cache");
    result.setHeader("x-content-type-options","nosniff");
    result.setHeader("referrer-policy","no-referrer");
    return result;
}
gateway::HttpResponse failure(E code,const gateway::HttpRequest& r) {
    auto denied=response(foundation::errorHttpStatus(code),foundation::toClientJson(foundation::Error{code},r.correlation().value()));
    if (code==E::AuthenticationRequired) denied.setHeader("www-authenticate","Bearer");
    return denied;
}
foundation::Result<std::optional<std::string>> filter(const gateway::HttpRequest& r,ManagementRead op) {
    if (op==ManagementRead::Applications || op==ManagementRead::Resources)
        return std::optional<std::string>{};
    const auto target=r.target();
    const auto q=target.find('?');
    if (q==std::string_view::npos) return foundation::fail(E::InvalidArgument);
    const auto key=op==ManagementRead::Clients?std::string_view{"application_id="}:std::string_view{"client_id="};
    auto value=target.substr(q+1U);
    if (!value.starts_with(key)) return foundation::fail(E::InvalidArgument);
    value.remove_prefix(key.size());
    if (value.empty() || value.size()>256U || value.find_first_of("&%+")!=std::string_view::npos
        || std::ranges::any_of(value,[](unsigned char c){return c<0x20U || c==0x7fU;}))
        return foundation::fail(E::InvalidArgument);
    return std::optional<std::string>{std::string{value}};
}
}

CoroutineManagementReadAdapter::CoroutineManagementReadAdapter(
    gateway::http::CoroutineHttpHandler& fallback,gateway::TokenBucketRateLimiter& limiter,
    Authenticate authenticate,Read read,Mutate mutate)
    : m_fallback(&fallback),m_limiter(&limiter),m_authenticate(std::move(authenticate)),m_read(std::move(read)),
      m_mutate(std::move(mutate)) {}

bool CoroutineManagementReadAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    return operation(r).has_value() || mutation(r).has_value() || m_fallback->nativeEnabledFor(r);
}

gateway::HttpResponse CoroutineManagementReadAdapter::handle(gateway::HttpRequest r) {
    scrub(r);
    return failure(E::Unavailable,r);
}

boost::asio::awaitable<gateway::HttpResponse> CoroutineManagementReadAdapter::handleAsync(gateway::HttpRequest r) {
    const auto op=operation(r);
    const auto write=mutation(r);
    if (!op && !write) {
        if (m_fallback->nativeEnabledFor(r)) co_return co_await m_fallback->handleAsync(std::move(r));
        scrub(r);
        co_return failure(E::Unavailable,r);
    }
    Scrub wipe{r};
    if (!m_authenticate || (op && !m_read) || (write && !m_mutate))
        co_return failure(E::Unavailable,r);
    if (!m_limiter->allow("idp-admin-ip:"+std::string{r.remoteAddress()}))
        co_return failure(E::RateLimited,r);
    if (r.header("authorization").value_or("").starts_with("DPoP "))
        co_return failure(E::AuthenticationFailed,r);
    std::optional<std::string> selected;
    std::optional<ApplicationMutationCommand> command;
    if (op) {
        auto parsed=filter(r,*op);
        if (!parsed) co_return failure(parsed.error().code(),r);
        selected=std::move(parsed).value();
    } else {
        auto parsed=parseMutation(r,*write);
        if (!parsed) co_return failure(parsed.error().code(),r);
        command.emplace(std::move(parsed).value());
    }
    auto credential=gateway::takeSessionCredential(r);
    if (!credential) co_return failure(credential.error().code(),r);
    if (!credential->has_value()) co_return failure(E::AuthenticationRequired,r);
    scrub(r);
    auto actor=co_await m_authenticate(std::move(credential->value()));
    if (!actor) co_return failure(actor.error().code(),r);
    if (!identity::provider::meetsAssurance(actor->assurance(),identity::provider::AssuranceLevel::Ial2))
        co_return failure(E::AssuranceInsufficient,r);
    if (!m_limiter->allow("idp-admin-identity:"+std::string{actor->identity().value()}))
        co_return failure(E::RateLimited,r);
    if (command) {
        const auto status=command->operation==ApplicationMutation::Create?201:200;
        auto changed=co_await m_mutate(std::move(*command),actor->identity(),actor->id());
        if (!changed) co_return failure(changed.error().code(),r);
        foundation::JsonObjectWriter body;
        body.add("id",changed->id().value()).add("identifier",changed->identifier())
            .add("name",changed->displayName()).add("environment",environmentName(changed->environment()))
            .add("status",applicationStatusName(changed->status()));
        co_return response(status,body.build());
    }
    auto data=co_await m_read(*op,actor->identity(),actor->id(),std::move(selected));
    if (!data) co_return failure(data.error().code(),r);
    co_return response(200,std::move(data).value());
}
}
