#include <boost/json.hpp>
#include <algorithm>
#include <string_view>
#include <utility>
#include "coroutine_management_read_http.hpp"

import openproof.identity.provider;
import openproof.security;
import openproof.application.http;

namespace openproof::application::http {
namespace {
using E=foundation::ErrorCode;
using Method=gateway::HttpMethod;
std::optional<ManagementRead> operation(const gateway::HttpRequest& r) noexcept {
    if (r.method()!=Method::Get) return std::nullopt;
    if (r.path()=="/admin/console") return ManagementRead::Console;
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
std::optional<client::ManagementMutation> clientMutation(const gateway::HttpRequest& r) noexcept {
    using Op=client::ManagementMutation;
    if (r.method()!=Method::Post) return std::nullopt;
    if (r.path()=="/admin/clients") return Op::Create;
    if (r.path()=="/admin/clients/suspend") return Op::Suspend;
    if (r.path()=="/admin/clients/activate") return Op::Activate;
    if (r.path()=="/admin/clients/revoke") return Op::Revoke;
    if (r.path()=="/admin/clients/rotate-secret") return Op::RotateSecret;
    return std::nullopt;
}
foundation::Result<client::ManagementMutationCommand> parseClientMutation(
    gateway::HttpRequest& r,client::ManagementMutation op)
{
    namespace json=boost::json;
    const auto media=r.header("content-type");
    if (!media || (*media!="application/json" && !media->starts_with("application/json;"))
        || r.body().empty() || r.body().size()>80U*1024U)
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
    if (op!=client::ManagementMutation::Create) {
        auto id=field("client_id",256U);
        if (object.size()!=1U || !id) return foundation::fail(E::InvalidArgument);
        return client::ManagementMutationCommand{op,client::ClientId{std::move(*id)},
            std::nullopt,{},client::ClientKind::Web,{},{},std::nullopt};
    }
    auto app=field("application_id",256U),name=field("name",120U),kind=field("kind",32U);
    const auto* uris=object.if_contains("redirect_uris");
    const auto* scopes=object.if_contains("scopes");
    if (object.size()!=5U || !app || !name || !kind || !uris || !uris->is_array()
        || uris->as_array().size()>32U || !scopes || !scopes->is_array()
        || scopes->as_array().empty() || scopes->as_array().size()>64U)
        return foundation::fail(E::InvalidArgument);
    client::ClientKind parsed;
    if (*kind=="web") parsed=client::ClientKind::Web;
    else if (*kind=="native") parsed=client::ClientKind::Native;
    else if (*kind=="browser") parsed=client::ClientKind::Browser;
    else if (*kind=="service") parsed=client::ClientKind::Service;
    else return foundation::fail(E::InvalidArgument);
    std::vector<client::RedirectUri> redirects;
    for (const auto& uri:uris->as_array()) {
        if (!uri.is_string() || uri.as_string().size()>2048U) return foundation::fail(E::InvalidArgument);
        auto item=client::RedirectUri::create(std::string{uri.as_string().data(),uri.as_string().size()},parsed);
        if (!item) return foundation::fail(item.error());
        redirects.push_back(std::move(item).value());
    }
    std::vector<client::Scope> grants;
    for (const auto& scope:scopes->as_array()) {
        if (!scope.is_string() || scope.as_string().size()>128U) return foundation::fail(E::InvalidArgument);
        auto item=client::Scope::create(std::string{scope.as_string().data(),scope.as_string().size()});
        if (!item) return foundation::fail(item.error());
        grants.push_back(std::move(item).value());
    }
    auto id=security::randomTokenBase64Url(24U);
    if (!id) return foundation::fail(id.error());
    return client::ManagementMutationCommand{op,client::ClientId{"opc_"+id.value()},
        ApplicationId{std::move(*app)},std::move(*name),parsed,std::move(redirects),std::move(grants),std::nullopt};
}
bool jarMutation(const gateway::HttpRequest& r) noexcept {
    return r.path()=="/admin/clients/jar-key"
        && (r.method()==Method::Post || r.method()==Method::Delete);
}
struct JarCommand final {
    client::ClientId id;
    std::optional<std::string> kid,pem;
};
foundation::Result<JarCommand> parseJarMutation(gateway::HttpRequest& r) {
    if (r.method()==Method::Delete) {
        auto target=r.target();
        constexpr std::string_view prefix="/admin/clients/jar-key?client_id=";
        if (!target.starts_with(prefix)) return foundation::fail(E::InvalidArgument);
        auto id=target.substr(prefix.size());
        if (id.empty() || id.size()>256U || id.find_first_of("&%+")!=std::string_view::npos
            || std::ranges::any_of(id,[](unsigned char c){return c<0x20U || c==0x7fU;}))
            return foundation::fail(E::InvalidArgument);
        return JarCommand{client::ClientId{std::string{id}},std::nullopt,std::nullopt};
    }
    const auto media=r.header("content-type");
    if (!media || (*media!="application/json" && !media->starts_with("application/json;"))
        || r.body().empty() || r.body().size()>32U*1024U)
        return foundation::fail(E::InvalidArgument);
    boost::system::error_code error;
    auto value=boost::json::parse(r.body(),error);
    r.wipeBody();
    if (error || !value.is_object()) return foundation::fail(E::InvalidArgument);
    const auto& object=value.as_object();
    const auto field=[&](std::string_view name,std::size_t maximum,bool multiline)->std::optional<std::string> {
        const auto* item=object.if_contains(name);
        if (!item || !item->is_string()) return std::nullopt;
        const auto& s=item->as_string();
        if (s.empty() || s.size()>maximum || std::ranges::any_of(s,[&](unsigned char c) {
            return (c<0x20U && !(multiline && (c=='\r' || c=='\n' || c=='\t'))) || c==0x7fU;
        })) return std::nullopt;
        return std::string{s.data(),s.size()};
    };
    auto id=field("client_id",256U,false),kid=field("key_id",128U,false),pem=field("public_key_pem",16U*1024U,true);
    if (object.size()!=3U || !id || !kid || !pem) return foundation::fail(E::InvalidArgument);
    return JarCommand{client::ClientId{std::move(*id)},std::move(kid),std::move(pem)};
}
std::optional<resource::ResourceMutation> resourceMutation(const gateway::HttpRequest& r) noexcept {
    using Op=resource::ResourceMutation;
    if (r.method()!=Method::Post) return std::nullopt;
    if (r.path()=="/admin/resources") return Op::Create;
    if (r.path()=="/admin/resources/suspend") return Op::Suspend;
    if (r.path()=="/admin/resources/activate") return Op::Activate;
    if (r.path()=="/admin/resources/revoke") return Op::Revoke;
    return std::nullopt;
}
foundation::Result<resource::ResourceMutationCommand> parseResourceMutation(
    gateway::HttpRequest& r,resource::ResourceMutation op)
{
    const auto media=r.header("content-type");
    if (!media || (*media!="application/json" && !media->starts_with("application/json;"))
        || r.body().empty() || r.body().size()>48U*1024U)
        return foundation::fail(E::InvalidArgument);
    boost::system::error_code error;
    auto value=boost::json::parse(r.body(),error);
    r.wipeBody();
    if (error || !value.is_object()) return foundation::fail(E::InvalidArgument);
    const auto& object=value.as_object();
    const auto field=[&](std::string_view name,std::size_t maximum)->std::optional<std::string> {
        const auto* item=object.if_contains(name);
        if (!item || !item->is_string()) return std::nullopt;
        const auto& s=item->as_string();
        if (s.empty() || s.size()>maximum || std::ranges::any_of(s,[](unsigned char c){
            return c<0x20U || c==0x7fU;
        })) return std::nullopt;
        return std::string{s.data(),s.size()};
    };
    auto audience=field("audience",2048U);
    if (!audience) return foundation::fail(E::InvalidArgument);
    if (op!=resource::ResourceMutation::Create) {
        if (object.size()!=1U) return foundation::fail(E::InvalidArgument);
        return resource::ResourceMutationCommand{op,resource::ResourceId{""},std::move(*audience),{},{}};
    }
    auto name=field("name",120U);
    const auto* scopes=object.if_contains("scopes");
    if (object.size()!=3U || !name || !scopes || !scopes->is_array()
        || scopes->as_array().empty() || scopes->as_array().size()>256U)
        return foundation::fail(E::InvalidArgument);
    std::vector<std::string> grants;
    for (const auto& scope:scopes->as_array()) {
        if (!scope.is_string() || scope.as_string().size()>128U) return foundation::fail(E::InvalidArgument);
        std::string parsed{scope.as_string().data(),scope.as_string().size()};
        if (!client::Scope::create(parsed)) return foundation::fail(E::InvalidArgument);
        grants.push_back(std::move(parsed));
    }
    auto id=security::randomTokenBase64Url(18U);
    if (!id) return foundation::fail(id.error());
    return resource::ResourceMutationCommand{op,resource::ResourceId{"opr_"+id.value()},
        std::move(*audience),std::move(*name),std::move(grants)};
}
std::optional<resource::ServiceMutation> serviceMutation(const gateway::HttpRequest& r) noexcept {
    using Op=resource::ServiceMutation;
    if (r.method()!=Method::Post) return std::nullopt;
    if (r.path()=="/admin/service-identities") return Op::Provision;
    if (r.path()=="/admin/service-identities/activate") return Op::Activate;
    if (r.path()=="/admin/service-identities/deactivate") return Op::Deactivate;
    return std::nullopt;
}
foundation::Result<resource::ServiceMutationCommand> parseServiceMutation(
    gateway::HttpRequest& r,resource::ServiceMutation op)
{
    const auto media=r.header("content-type");
    if (!media || (*media!="application/json" && !media->starts_with("application/json;"))
        || r.body().empty() || r.body().size()>192U*1024U)
        return foundation::fail(E::InvalidArgument);
    boost::system::error_code error;
    auto value=boost::json::parse(r.body(),error);
    r.wipeBody();
    if (error || !value.is_object()) return foundation::fail(E::InvalidArgument);
    const auto& object=value.as_object();
    const auto* client=object.if_contains("client_id");
    if (!client || !client->is_string() || client->as_string().empty() || client->as_string().size()>256U
        || std::ranges::any_of(client->as_string(),[](unsigned char c){return c<0x20U || c==0x7fU;}))
        return foundation::fail(E::InvalidArgument);
    client::ClientId id{std::string{client->as_string().data(),client->as_string().size()}};
    if (op!=resource::ServiceMutation::Provision) {
        if (object.size()!=1U) return foundation::fail(E::InvalidArgument);
        return resource::ServiceMutationCommand{op,std::move(id),identity::core::IdentityId{""},{},{}};
    }
    const auto* audiences=object.if_contains("audiences");
    const auto* scopes=object.if_contains("scopes");
    if (object.size()!=3U || !audiences || !audiences->is_array() || audiences->as_array().empty()
        || audiences->as_array().size()>64U || !scopes || !scopes->is_array()
        || scopes->as_array().empty() || scopes->as_array().size()>256U)
        return foundation::fail(E::InvalidArgument);
    std::vector<std::string> targets,grants;
    for (const auto& audience:audiences->as_array()) {
        if (!audience.is_string() || audience.as_string().empty() || audience.as_string().size()>2048U
            || std::ranges::any_of(audience.as_string(),[](unsigned char c){return c<=0x20U || c==0x7fU;}))
            return foundation::fail(E::InvalidArgument);
        targets.emplace_back(audience.as_string().data(),audience.as_string().size());
    }
    for (const auto& scope:scopes->as_array()) {
        if (!scope.is_string() || scope.as_string().size()>128U) return foundation::fail(E::InvalidArgument);
        std::string parsed{scope.as_string().data(),scope.as_string().size()};
        if (!client::Scope::create(parsed)) return foundation::fail(E::InvalidArgument);
        grants.push_back(std::move(parsed));
    }
    auto random=security::randomTokenBase64Url(24U);
    if (!random) return foundation::fail(random.error());
    return resource::ServiceMutationCommand{op,std::move(id),identity::core::IdentityId{"opsi_"+random.value()},
        std::move(targets),std::move(grants)};
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
gateway::HttpResponse consoleFailure(E code,const gateway::HttpRequest& r,bool console) {
    if (!console || (code!=E::AuthenticationRequired && code!=E::AuthenticationFailed && code!=E::AssuranceInsufficient))
        return failure(code,r);
    const bool needsLogin=code!=E::AssuranceInsufficient;
    gateway::HttpResponse result{303,gateway::Headers{{"location",
        needsLogin?"/login?return_to=%2Fadmin%2Fconsole":"/account/security"},
        {"cache-control","no-store"},{"pragma","no-cache"},{"x-content-type-options","nosniff"},
        {"referrer-policy","no-referrer"}},{}};
    if (needsLogin) result.addHeader("set-cookie",
        "__Host-openproof-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
    return result;
}
foundation::Result<std::optional<std::string>> filter(const gateway::HttpRequest& r,ManagementRead op) {
    if (op==ManagementRead::Applications || op==ManagementRead::Resources || op==ManagementRead::Console)
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
    Authenticate authenticate,Read read,Mutate mutate,std::optional<ClientContext> clients,MutateResource resources,MutateService services)
    : m_fallback(&fallback),m_limiter(&limiter),m_authenticate(std::move(authenticate)),m_read(std::move(read)),
      m_mutate(std::move(mutate)),m_clients(std::move(clients)),m_resources(std::move(resources)),m_services(std::move(services)) {}

bool CoroutineManagementReadAdapter::nativeEnabledFor(const gateway::HttpRequest& r) const noexcept {
    return operation(r).has_value() || mutation(r).has_value() || clientMutation(r).has_value()
        || jarMutation(r) || resourceMutation(r).has_value() || serviceMutation(r).has_value()
        || m_fallback->nativeEnabledFor(r);
}

gateway::HttpResponse CoroutineManagementReadAdapter::handle(gateway::HttpRequest r) {
    scrub(r);
    return failure(E::Unavailable,r);
}

boost::asio::awaitable<gateway::HttpResponse> CoroutineManagementReadAdapter::handleAsync(gateway::HttpRequest r) {
    const auto op=operation(r);
    const auto write=mutation(r);
    const auto clientWrite=clientMutation(r);
    const bool jarWrite=jarMutation(r);
    const auto resourceWrite=resourceMutation(r);
    const auto serviceWrite=serviceMutation(r);
    if (!op && !write && !clientWrite && !jarWrite && !resourceWrite && !serviceWrite) {
        if (m_fallback->nativeEnabledFor(r)) co_return co_await m_fallback->handleAsync(std::move(r));
        scrub(r);
        co_return failure(E::Unavailable,r);
    }
    Scrub wipe{r};
    if (!m_authenticate || (op && !m_read) || (write && !m_mutate)
        || (clientWrite && (!m_clients || !m_clients->mutate))
        || (jarWrite && (!m_clients || !m_clients->mutateJarKey))
        || (resourceWrite && !m_resources) || (serviceWrite && !m_services))
        co_return failure(E::Unavailable,r);
    if (!m_limiter->allow("idp-admin-ip:"+std::string{r.remoteAddress()}))
        co_return failure(E::RateLimited,r);
    if (r.header("authorization").value_or("").starts_with("DPoP "))
        co_return failure(E::AuthenticationFailed,r);
    std::optional<std::string> selected;
    std::optional<ApplicationMutationCommand> command;
    std::optional<client::ManagementMutationCommand> clientCommand;
    std::optional<JarCommand> jarCommand;
    std::optional<resource::ResourceMutationCommand> resourceCommand;
    std::optional<resource::ServiceMutationCommand> serviceCommand;
    if (op) {
        auto parsed=filter(r,*op);
        if (!parsed) co_return failure(parsed.error().code(),r);
        selected=std::move(parsed).value();
    } else if (write) {
        auto parsed=parseMutation(r,*write);
        if (!parsed) co_return failure(parsed.error().code(),r);
        command.emplace(std::move(parsed).value());
    } else if (clientWrite) {
        auto parsed=parseClientMutation(r,*clientWrite);
        if (!parsed) co_return failure(parsed.error().code(),r);
        clientCommand.emplace(std::move(parsed).value());
    } else if (jarWrite) {
        auto parsed=parseJarMutation(r);
        if (!parsed) co_return failure(parsed.error().code(),r);
        jarCommand.emplace(std::move(parsed).value());
    } else if (resourceWrite) {
        auto parsed=parseResourceMutation(r,*resourceWrite);
        if (!parsed) co_return failure(parsed.error().code(),r);
        resourceCommand.emplace(std::move(parsed).value());
    } else {
        auto parsed=parseServiceMutation(r,*serviceWrite);
        if (!parsed) co_return failure(parsed.error().code(),r);
        serviceCommand.emplace(std::move(parsed).value());
    }
    const bool console=op==ManagementRead::Console;
    auto credential=gateway::takeSessionCredential(r);
    if (!credential) co_return consoleFailure(credential.error().code(),r,console);
    if (!credential->has_value()) co_return consoleFailure(E::AuthenticationRequired,r,console);
    scrub(r);
    auto actor=co_await m_authenticate(std::move(credential->value()));
    if (!actor) co_return consoleFailure(actor.error().code(),r,console);
    if (!identity::provider::meetsAssurance(actor->assurance(),identity::provider::AssuranceLevel::Ial2))
        co_return consoleFailure(E::AssuranceInsufficient,r,console);
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
    if (serviceCommand) {
        const auto status=serviceCommand->operation==resource::ServiceMutation::Provision?201:200;
        auto changed=co_await m_services(std::move(*serviceCommand),actor->identity(),actor->id());
        if (!changed) co_return failure(changed.error().code(),r);
        boost::json::object body;
        body["identity_id"]=std::string{changed->identity().value()};
        body["client_id"]=std::string{changed->client().value()};
        body["active"]=changed->active();
        boost::json::array audiences,scopes;
        for (const auto& audience:changed->audiences()) audiences.emplace_back(audience);
        for (const auto& scope:changed->scopes()) scopes.emplace_back(scope);
        body["audiences"]=std::move(audiences);
        body["scopes"]=std::move(scopes);
        co_return response(status,boost::json::serialize(body));
    }
    if (resourceCommand) {
        const auto status=resourceCommand->operation==resource::ResourceMutation::Create?201:200;
        auto changed=co_await m_resources(std::move(*resourceCommand),actor->identity(),actor->id());
        if (!changed) co_return failure(changed.error().code(),r);
        boost::json::object body;
        body["id"]=std::string{changed->id().value()};
        body["audience"]=std::string{changed->audience()};
        body["name"]=std::string{changed->displayName()};
        body["status"]=changed->status()==resource::ResourceStatus::Active?"active":
            changed->status()==resource::ResourceStatus::Suspended?"suspended":"revoked";
        boost::json::array scopes;
        for (const auto& scope:changed->scopes()) scopes.emplace_back(scope);
        body["scopes"]=std::move(scopes);
        co_return response(status,boost::json::serialize(body));
    }
    if (jarCommand) {
        const bool registration=jarCommand->kid.has_value();
        const std::string id{jarCommand->id.value()};
        auto changed=co_await m_clients->mutateJarKey(std::move(jarCommand->id),
            std::move(jarCommand->kid),std::move(jarCommand->pem),actor->identity(),actor->id());
        if (!changed) co_return failure(changed.error().code(),r);
        if (!registration) co_return gateway::HttpResponse{204,{},{}};
        foundation::JsonObjectWriter body;
        body.add("client_id",id).add("registered",true);
        co_return response(200,body.build());
    }
    if (clientCommand) {
        using Op=client::ManagementMutation;
        const auto op=clientCommand->operation;
        std::optional<foundation::SecretString> secret;
        if (op==Op::RotateSecret || (op==Op::Create && !client::clientIsPublic(clientCommand->kind))) {
            auto raw=security::randomTokenBase64Url(32U);
            if (!raw) co_return failure(E::Unavailable,r);
            secret.emplace("ops_"+raw.value());
            foundation::secureWipe(raw->data(),raw->size());
            auto digest=security::hmacSha256(m_clients->key,secret->expose());
            if (!digest) co_return failure(E::Unavailable,r);
            clientCommand->digest.emplace(digest.value());
        }
        auto changed=co_await m_clients->mutate(std::move(*clientCommand),actor->identity(),actor->id());
        if (!changed) co_return failure(changed.error().code(),r);
        boost::json::object body;
        if (op==Op::RotateSecret) {
            body["client_id"]=std::string{changed->id().value()};
        } else {
            body["id"]=std::string{changed->id().value()};
            body["application_id"]=std::string{changed->applicationId().value()};
            body["name"]=std::string{changed->displayName()};
            body["kind"]=std::string{client::clientKindName(changed->kind())};
            body["status"]=std::string{client::clientStatusName(changed->status())};
            boost::json::array redirects,scopes;
            for (const auto& uri:changed->redirectUris()) redirects.emplace_back(std::string{uri.value()});
            for (const auto& scope:changed->scopes()) scopes.emplace_back(std::string{scope.value()});
            body["redirect_uris"]=std::move(redirects);
            body["scopes"]=std::move(scopes);
        }
        if (op==Op::Create || op==Op::RotateSecret)
            body["client_secret_returned_once"]=secret.has_value();
        // Serialize the raw credential only after successful commit, without
        // copying it into a non-wiping boost::json::value.
        auto output=boost::json::serialize(body);
        if (secret) {
            output.pop_back();
            output.append(",\"client_secret\":\"").append(secret->expose()).append("\"}");
        }
        co_return response(op==Op::Create?201:200,std::move(output));
    }
    auto data=co_await m_read(*op,actor->identity(),actor->id(),std::move(selected));
    if (!data) co_return consoleFailure(data.error().code(),r,console);
    if (console) {
        auto nonce=security::randomTokenBase64Url(24U);
        if (!nonce) co_return failure(nonce.error().code(),r);
        co_return renderAdministrationConsole(std::move(nonce).value());
    }
    co_return response(200,std::move(data).value());
}
}
