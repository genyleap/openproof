module;

#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/json.hpp>

module openproof.application.http;

import openproof.security;

namespace openproof::application::http {
namespace {

namespace json = boost::json;
constexpr std::size_t kMaximumBody = 32U * 1024U;

[[nodiscard]] gateway::HttpResponse jsonResponse(int status, json::value body)
{
    gateway::HttpResponse response{
        status, gateway::Headers{{"content-type", "application/json"}},
        json::serialize(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    return response;
}

[[nodiscard]] foundation::Result<json::object> parseObject(const gateway::HttpRequest& request)
{
    if (request.body().empty() || request.body().size() > kMaximumBody) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The management request is invalid.");
    }
    const auto contentType = request.header("content-type");
    if (!contentType || (*contentType != "application/json"
        && !contentType->starts_with("application/json;"))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The management request is invalid.");
    }
    boost::system::error_code parseError;
    json::value parsed = json::parse(request.body(), parseError);
    if (parseError || !parsed.is_object()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The management request is invalid.");
    }
    return std::move(parsed).as_object();
}

[[nodiscard]] bool validText(std::string_view value, std::size_t maximum) noexcept
{
    return !value.empty() && value.size() <= maximum
        && std::ranges::none_of(value, [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return byte < 0x20U || byte == 0x7FU;
           });
}

[[nodiscard]] foundation::Result<std::string>
requiredString(const json::object& object, std::string_view key, std::size_t maximum)
{
    const json::value* value = object.if_contains(key);
    if (value == nullptr || !value->is_string()
        || !validText(value->as_string(), maximum)) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The management request is invalid.");
    }
    return std::string{value->as_string()};
}

[[nodiscard]] foundation::Result<std::string>
requiredMultilineString(const json::object& object, std::string_view key, std::size_t maximum)
{
    const json::value* value = object.if_contains(key);
    if (value == nullptr || !value->is_string() || value->as_string().empty()
        || value->as_string().size() > maximum
        || std::ranges::any_of(value->as_string(), [](char symbol) {
               const auto byte = static_cast<unsigned char>(symbol);
               return (byte < 0x20U && symbol != '\n' && symbol != '\r') || byte == 0x7FU;
           })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The management request is invalid.");
    }
    return std::string{value->as_string()};
}

[[nodiscard]] foundation::Result<std::vector<std::string>>
requiredStrings(const json::object& object, std::string_view key,
                std::size_t maximumItems, std::size_t maximumLength,
                bool allowEmpty = false)
{
    const json::value* value = object.if_contains(key);
    if (value == nullptr || !value->is_array()
        || (!allowEmpty && value->as_array().empty())
        || value->as_array().size() > maximumItems) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The management request is invalid.");
    }
    std::vector<std::string> result;
    result.reserve(value->as_array().size());
    for (const json::value& item : value->as_array()) {
        if (!item.is_string() || !validText(item.as_string(), maximumLength)) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                    "The management request is invalid.");
        }
        result.emplace_back(item.as_string());
    }
    return result;
}

[[nodiscard]] bool onlyFields(const json::object& object,
                              std::initializer_list<std::string_view> allowed)
{
    return std::ranges::all_of(object, [&](const auto& item) {
        return std::ranges::find(allowed, std::string_view{item.key()}) != allowed.end();
    });
}

[[nodiscard]] foundation::Result<Environment> environment(std::string_view value)
{
    if (value == "development") return Environment::Development;
    if (value == "staging") return Environment::Staging;
    if (value == "production") return Environment::Production;
    return foundation::fail(foundation::ErrorCode::InvalidArgument,
                            "The application environment is invalid.");
}

[[nodiscard]] foundation::Result<client::ClientKind> clientKind(std::string_view value)
{
    if (value == "web") return client::ClientKind::Web;
    if (value == "native") return client::ClientKind::Native;
    if (value == "browser") return client::ClientKind::Browser;
    if (value == "service") return client::ClientKind::Service;
    return foundation::fail(foundation::ErrorCode::InvalidArgument,
                            "The client kind is invalid.");
}

[[nodiscard]] std::optional<std::string_view> queryParameter(
    std::string_view target, std::string_view expected)
{
    const auto question = target.find('?');
    if (question == std::string_view::npos) return std::nullopt;
    std::string_view query = target.substr(question + 1U);
    const std::string prefix = std::string{expected} + "=";
    if (!query.starts_with(prefix) || query.find('&') != std::string_view::npos) {
        return std::nullopt;
    }
    const std::string_view value = query.substr(prefix.size());
    if (!validText(value, 256U) || value.find('%') != std::string_view::npos
        || value.find('+') != std::string_view::npos) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] json::object applicationJson(const Application& value)
{
    json::object output;
    output["id"] = std::string{value.id().value()};
    output["identifier"] = std::string{value.identifier()};
    output["name"] = std::string{value.displayName()};
    output["environment"] = std::string{environmentName(value.environment())};
    output["status"] = std::string{applicationStatusName(value.status())};
    return output;
}

[[nodiscard]] json::object clientJson(const client::Client& value)
{
    json::object output;
    output["id"] = std::string{value.id().value()};
    output["application_id"] = std::string{value.applicationId().value()};
    output["name"] = std::string{value.displayName()};
    output["kind"] = std::string{client::clientKindName(value.kind())};
    output["status"] = std::string{client::clientStatusName(value.status())};
    json::array redirects;
    for (const auto& redirect : value.redirectUris()) redirects.emplace_back(std::string{redirect.value()});
    json::array scopes;
    for (const auto& scope : value.scopes()) scopes.emplace_back(std::string{scope.value()});
    output["redirect_uris"] = std::move(redirects);
    output["scopes"] = std::move(scopes);
    return output;
}

}

ApplicationManagementHttpApi::ApplicationManagementHttpApi(
    ApplicationRegistry& applications, ApplicationRepository& applicationRepository,
    client::ClientManager& clients, client::ClientRepository& clientRepository,
    resource::ResourceRegistry& resources,
    resource::ServiceIdentityService& serviceIdentities, oauth::JarService& jar,
    session::SessionService& sessions, organization::MembershipRepository& memberships,
    gateway::TokenBucketRateLimiter& limiter,
    identity::core::OrganizationId organization, gateway::HttpHandler& fallback)
    : m_applications(&applications), m_applicationRepository(&applicationRepository),
      m_clients(&clients), m_clientRepository(&clientRepository),
      m_resources(&resources), m_serviceIdentities(&serviceIdentities), m_jar(&jar),
      m_sessions(&sessions), m_memberships(&memberships), m_limiter(&limiter),
      m_organization(std::move(organization)), m_fallback(&fallback)
{
}

foundation::Result<identity::core::IdentityId>
ApplicationManagementHttpApi::authorize(gateway::HttpRequest& request) const
{
    auto credential = gateway::takeSessionCredential(request);
    if (!credential || !credential->has_value()) {
        return foundation::fail(credential
            ? foundation::Error{foundation::ErrorCode::AuthenticationRequired}
            : credential.error());
    }
    auto authenticated = m_sessions->authenticate(credential->value());
    if (!authenticated) return foundation::fail(authenticated.error());
    if (!identity::provider::meetsAssurance(authenticated->session().assurance(),
                                             identity::provider::AssuranceLevel::Ial2)) {
        return foundation::fail(foundation::ErrorCode::AssuranceInsufficient);
    }
    const auto& actor = authenticated->session().identity();
    auto membership = m_memberships->find(m_organization, actor);
    if (!membership) return foundation::fail(membership.error());
    if (!membership->has_value()
        || !membership->value().hasRole(organization::Role{"owner"})) {
        return foundation::fail(foundation::ErrorCode::PermissionDenied);
    }
    return actor;
}

gateway::HttpResponse ApplicationManagementHttpApi::error(
    const foundation::Error& failure, const gateway::HttpRequest& request) const
{
    gateway::HttpResponse response{
        foundation::errorHttpStatus(failure.code()),
        gateway::Headers{{"content-type", "application/json"}},
        foundation::toClientJson(failure, request.correlation().value())};
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    if (failure.code() == foundation::ErrorCode::AuthenticationRequired) {
        response.setHeader("www-authenticate", "Bearer");
    }
    return response;
}

gateway::HttpResponse ApplicationManagementHttpApi::handle(gateway::HttpRequest request)
{
    const bool managed = request.path() == "/admin/console"
        || request.path() == "/admin/applications"
        || request.path().starts_with("/admin/applications/")
        || request.path() == "/admin/clients"
        || request.path().starts_with("/admin/clients/")
        || request.path() == "/admin/resources"
        || request.path().starts_with("/admin/resources/")
        || request.path() == "/admin/service-identities"
        || request.path().starts_with("/admin/service-identities/");
    if (!managed) return m_fallback->handle(std::move(request));
    if (!m_limiter->allow("idp-admin-ip:" + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    auto actor = authorize(request);
    if (!actor) return error(actor.error(), request);
    if (!m_limiter->allow("idp-admin-identity:" + std::string{actor->value()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }

    if (request.method() == gateway::HttpMethod::Get
        && request.path() == "/admin/console") return consolePage(std::move(request));
    if (request.method() == gateway::HttpMethod::Get
        && request.path() == "/admin/applications") return listApplications(std::move(request));
    if (request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/applications") return createApplication(std::move(request));
    if (request.method() == gateway::HttpMethod::Post
        && request.path().starts_with("/admin/applications/")) {
        const std::string action{request.path().substr(std::string_view{"/admin/applications/"}.size())};
        return changeApplication(std::move(request), action);
    }
    if (request.method() == gateway::HttpMethod::Get
        && request.path() == "/admin/clients") return listClients(std::move(request));
    if (request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/clients") return createClient(std::move(request));
    if (request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/clients/rotate-secret") return rotateClientSecret(std::move(request));
    if (request.method() == gateway::HttpMethod::Get
        && request.path() == "/admin/clients/jar-key") return jarKey(std::move(request));
    if (request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/clients/jar-key") return registerJarKey(std::move(request));
    if (request.method() == gateway::HttpMethod::Delete
        && request.path() == "/admin/clients/jar-key") return removeJarKey(std::move(request));
    if (request.method() == gateway::HttpMethod::Post
        && request.path().starts_with("/admin/clients/")) {
        const std::string action{request.path().substr(std::string_view{"/admin/clients/"}.size())};
        return changeClient(std::move(request), action);
    }
    if (request.method() == gateway::HttpMethod::Get
        && request.path() == "/admin/resources") return listResources(std::move(request));
    if (request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/resources") return createResource(std::move(request));
    if (request.method() == gateway::HttpMethod::Post
        && request.path().starts_with("/admin/resources/")) {
        const std::string action{request.path().substr(std::string_view{"/admin/resources/"}.size())};
        return changeResource(std::move(request), action);
    }
    if (request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/service-identities") {
        return provisionServiceIdentity(std::move(request));
    }
    if (request.method() == gateway::HttpMethod::Get
        && request.path() == "/admin/service-identities") {
        return serviceIdentity(std::move(request));
    }
    if (request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/service-identities/activate") {
        return changeServiceIdentity(std::move(request), true);
    }
    if (request.method() == gateway::HttpMethod::Post
        && request.path() == "/admin/service-identities/deactivate") {
        return changeServiceIdentity(std::move(request), false);
    }
    return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
}

gateway::HttpResponse ApplicationManagementHttpApi::consolePage(gateway::HttpRequest request)
{
    auto nonce = security::randomTokenBase64Url(24U);
    if (!nonce) return error(nonce.error(), request);
    const std::string scriptNonce = nonce.value();
    std::string body = R"HTML(<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OpenProof Admin Console</title><style>body{font:14px system-ui,sans-serif;max-width:1200px;margin:0 auto;padding:24px}h1{margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px}.card{border:1px solid #bbb;border-radius:10px;padding:16px}form{display:grid;gap:8px;margin-top:10px}input,select,button,textarea{font:inherit;padding:8px}pre{white-space:pre-wrap;word-break:break-word;background:#f4f4f4;padding:10px;border-radius:8px;max-height:360px;overflow:auto}.ok{color:#075}.error{color:#900}</style></head><body><h1>OpenProof Admin Console</h1><p>Owner access with IAL2 is required. Secrets returned once are shown only in the operation result.</p><div id="status"></div><div class="grid"><section class="card"><h2>Members</h2><button data-load="/admin/local-members" data-target="members">Refresh</button><pre id="members"></pre><form id="memberCreate"><input name="subject" placeholder="email / local subject" required><input name="roles" placeholder="roles, comma-separated" value="member" required><button>Create local member</button></form></section><section class="card"><h2>Applications</h2><button data-load="/admin/applications" data-target="applications">Refresh</button><pre id="applications"></pre><form id="applicationCreate"><input name="identifier" placeholder="identifier" required><input name="name" placeholder="display name" required><select name="environment"><option>production</option><option>staging</option><option>development</option></select><button>Create application</button></form><form id="applicationState"><input name="application_id" placeholder="application id" required><select name="action"><option>activate</option><option>suspend</option><option>revoke</option></select><button>Change application state</button></form></section><section class="card"><h2>OAuth clients</h2><form id="clientList"><input name="application_id" placeholder="application id" required><button>List clients</button></form><pre id="clients"></pre><form id="clientCreate"><input name="application_id" placeholder="application id" required><input name="name" placeholder="client name" required><select name="kind"><option>web</option><option>native</option><option>browser</option><option>service</option></select><textarea name="redirect_uris" placeholder="redirect URIs, one per line"></textarea><input name="scopes" placeholder="scopes, space-separated" required><button>Create client</button></form><form id="clientState"><input name="client_id" placeholder="client id" required><select name="action"><option>activate</option><option>suspend</option><option>revoke</option></select><button>Change client state</button></form><form id="clientRotate"><input name="client_id" placeholder="client id" required><button>Rotate client secret</button></form></section><section class="card"><h2>JAR signing key</h2><form id="jarFind"><input name="client_id" placeholder="client id" required><button>Load JAR key</button></form><pre id="jar"></pre><form id="jarRegister"><input name="client_id" placeholder="client id" required><input name="key_id" placeholder="key id" required><textarea name="public_key_pem" placeholder="RSA public key PEM" required></textarea><button>Register / replace key</button></form><form id="jarRemove"><input name="client_id" placeholder="client id" required><button>Remove JAR key</button></form></section><section class="card"><h2>Resources</h2><button data-load="/admin/resources" data-target="resources">Refresh</button><pre id="resources"></pre><form id="resourceCreate"><input name="audience" placeholder="audience/resource URI" required><input name="name" placeholder="display name" required><input name="scopes" placeholder="scopes, space-separated" required><button>Register resource</button></form><form id="resourceState"><input name="audience" placeholder="audience" required><select name="action"><option>activate</option><option>suspend</option><option>revoke</option></select><button>Change resource state</button></form></section><section class="card"><h2>Service identity</h2><form id="serviceFind"><input name="client_id" placeholder="service client id" required><button>Load</button></form><pre id="service"></pre><form id="serviceCreate"><input name="client_id" placeholder="service client id" required><input name="audiences" placeholder="audiences, one per line" required><input name="scopes" placeholder="scopes, space-separated" required><button>Provision</button></form><form id="serviceState"><input name="client_id" placeholder="service client id" required><select name="action"><option>activate</option><option>deactivate</option></select><button>Change service state</button></form></section><section class="card"><h2>Member lifecycle</h2><form id="memberAction"><input name="identity_id" placeholder="identity id" required><select name="action"><option>suspend</option><option>reinstate</option><option>remove</option></select><button>Apply</button></form><form id="memberRoles"><input name="identity_id" placeholder="identity id" required><input name="roles" placeholder="roles, comma-separated" required><button>Replace roles</button></form><form id="memberReset"><input name="identity_id" placeholder="identity id" required><button>Reset credentials</button></form></section></div><pre id="operation"></pre><script nonce=")HTML" + scriptNonce + R"HTML(">
const q=s=>document.querySelector(s), status=q('#status'), op=q('#operation');
const values=f=>Object.fromEntries(new FormData(f));
const splitComma=v=>v.split(',').map(x=>x.trim()).filter(Boolean);
const splitSpace=v=>v.split(/\s+/).map(x=>x.trim()).filter(Boolean);
const splitLines=v=>v.split(/\n+/).map(x=>x.trim()).filter(Boolean);
async function api(url,method='GET',body){const r=await fetch(url,{method,headers:body?{'content-type':'application/json'}:{},body:body?JSON.stringify(body):undefined,credentials:'same-origin'});const text=await r.text();let data=text;try{data=text?JSON.parse(text):null}catch{}if(!r.ok)throw new Error(typeof data==='string'?data:JSON.stringify(data));return data}
function show(el,data){el.textContent=JSON.stringify(data,null,2)}function result(data){show(op,data);status.textContent='Operation completed';status.className='ok'}function fail(e){status.textContent=e.message;status.className='error'}
document.querySelectorAll('[data-load]').forEach(b=>b.onclick=async()=>{try{show(q('#'+b.dataset.target),await api(b.dataset.load))}catch(e){fail(e)}});
const memberCreate=q('#memberCreate');memberCreate.insertAdjacentHTML('afterbegin','<input name="identity_id" placeholder="new identity id" required>');
memberCreate.onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/local-members','POST',{identity_id:v.identity_id,subject:v.subject,roles:splitComma(v.roles)}))}catch(x){fail(x)}};
q('#applicationCreate').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/applications','POST',v))}catch(x){fail(x)}};
q('#applicationState').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/applications/'+v.action,'POST',{application_id:v.application_id}))}catch(x){fail(x)}};
q('#clientList').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);show(q('#clients'),await api('/admin/clients?application_id='+encodeURIComponent(v.application_id)))}catch(x){fail(x)}};
q('#clientCreate').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/clients','POST',{application_id:v.application_id,name:v.name,kind:v.kind,redirect_uris:splitLines(v.redirect_uris),scopes:splitSpace(v.scopes)}))}catch(x){fail(x)}};
q('#clientState').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/clients/'+v.action,'POST',{client_id:v.client_id}))}catch(x){fail(x)}};
q('#clientRotate').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/clients/rotate-secret','POST',{client_id:v.client_id}))}catch(x){fail(x)}};
q('#jarFind').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);show(q('#jar'),await api('/admin/clients/jar-key?client_id='+encodeURIComponent(v.client_id)))}catch(x){fail(x)}};
q('#jarRegister').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/clients/jar-key','POST',{client_id:v.client_id,key_id:v.key_id,public_key_pem:v.public_key_pem}))}catch(x){fail(x)}};
q('#jarRemove').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/clients/jar-key?client_id='+encodeURIComponent(v.client_id),'DELETE'))}catch(x){fail(x)}};
q('#resourceCreate').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/resources','POST',{audience:v.audience,name:v.name,scopes:splitSpace(v.scopes)}))}catch(x){fail(x)}};
q('#resourceState').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/resources/'+v.action,'POST',{audience:v.audience}))}catch(x){fail(x)}};
q('#serviceFind').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);show(q('#service'),await api('/admin/service-identities?client_id='+encodeURIComponent(v.client_id)))}catch(x){fail(x)}};
q('#serviceCreate').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/service-identities','POST',{client_id:v.client_id,audiences:splitLines(v.audiences),scopes:splitSpace(v.scopes)}))}catch(x){fail(x)}};
q('#serviceState').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/service-identities/'+v.action,'POST',{client_id:v.client_id}))}catch(x){fail(x)}};
q('#memberAction').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/local-members/'+v.action,'POST',{identity_id:v.identity_id}))}catch(x){fail(x)}};
q('#memberRoles').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/local-members/roles','PUT',{identity_id:v.identity_id,roles:splitComma(v.roles)}))}catch(x){fail(x)}};
q('#memberReset').onsubmit=async e=>{e.preventDefault();try{const v=values(e.target);result(await api('/admin/local-members/credentials/reset','POST',{identity_id:v.identity_id}))}catch(x){fail(x)}};
Promise.allSettled([['/admin/local-members','#members'],['/admin/applications','#applications'],['/admin/resources','#resources']].map(async([u,t])=>show(q(t),await api(u))));
</script></body></html>)HTML";
    gateway::HttpResponse response{
        200, gateway::Headers{{"content-type", "text/html; charset=utf-8"}}, std::move(body)};
    response.setHeader("cache-control", "no-store");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
    response.setHeader("content-security-policy",
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" + scriptNonce
        + "'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    return response;
}

gateway::HttpResponse ApplicationManagementHttpApi::listApplications(gateway::HttpRequest request)
{
    auto applications = m_applicationRepository->list();
    if (!applications) return error(applications.error(), request);
    json::array items;
    for (const auto& value : applications.value()) {
        if (value.owner() == m_organization) items.emplace_back(applicationJson(value));
    }
    json::object body; body["applications"] = std::move(items);
    return jsonResponse(200, std::move(body));
}

gateway::HttpResponse ApplicationManagementHttpApi::createApplication(gateway::HttpRequest request)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"identifier", "name", "environment"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    }
    auto identifier = requiredString(body.value(), "identifier", 64U);
    auto name = requiredString(body.value(), "name", 120U);
    auto environmentText = requiredString(body.value(), "environment", 32U);
    if (!identifier || !name || !environmentText) return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    auto parsedEnvironment = environment(environmentText.value());
    if (!parsedEnvironment) return error(parsedEnvironment.error(), request);
    auto created = m_applications->registerApplication(
        m_organization, std::move(identifier).value(), std::move(name).value(), parsedEnvironment.value());
    if (!created) return error(created.error(), request);
    return jsonResponse(201, applicationJson(created.value()));
}

gateway::HttpResponse ApplicationManagementHttpApi::changeApplication(
    gateway::HttpRequest request, std::string_view action)
{
    if (action != "suspend" && action != "activate" && action != "revoke") {
        return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    }
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"application_id"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto id = requiredString(body.value(), "application_id", 256U);
    if (!id) return error(id.error(), request);
    ApplicationId applicationId{id.value()};
    auto found = m_applicationRepository->findById(applicationId);
    if (!found || !found->has_value() || found->value().owner() != m_organization) {
        return error(found ? foundation::Error{foundation::ErrorCode::NotFound} : found.error(), request);
    }
    foundation::Result<Application> changed = action == "suspend"
        ? m_applications->suspend(applicationId)
        : action == "activate" ? m_applications->activate(applicationId)
                                : m_applications->revoke(applicationId);
    return changed ? jsonResponse(200, applicationJson(changed.value())) : error(changed.error(), request);
}

gateway::HttpResponse ApplicationManagementHttpApi::listClients(gateway::HttpRequest request)
{
    const auto applicationIdText = queryParameter(request.target(), "application_id");
    if (!applicationIdText) return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    ApplicationId applicationId{std::string{*applicationIdText}};
    auto application = m_applicationRepository->findById(applicationId);
    if (!application || !application->has_value() || application->value().owner() != m_organization) {
        return error(application ? foundation::Error{foundation::ErrorCode::NotFound} : application.error(), request);
    }
    auto clients = m_clientRepository->clientsOf(applicationId);
    if (!clients) return error(clients.error(), request);
    json::array items;
    for (const auto& value : clients.value()) items.emplace_back(clientJson(value));
    json::object body; body["clients"] = std::move(items);
    return jsonResponse(200, std::move(body));
}

gateway::HttpResponse ApplicationManagementHttpApi::createClient(gateway::HttpRequest request)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"application_id", "name", "kind", "redirect_uris", "scopes"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    }
    auto applicationIdText = requiredString(body.value(), "application_id", 256U);
    auto name = requiredString(body.value(), "name", 120U);
    auto kindText = requiredString(body.value(), "kind", 32U);
    auto redirects = requiredStrings(body.value(), "redirect_uris", 32U, 2048U, true);
    auto scopes = requiredStrings(body.value(), "scopes", 64U, 128U);
    if (!applicationIdText || !name || !kindText || !redirects || !scopes) return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    ApplicationId applicationId{applicationIdText.value()};
    auto application = m_applicationRepository->findById(applicationId);
    if (!application || !application->has_value() || application->value().owner() != m_organization) {
        return error(application ? foundation::Error{foundation::ErrorCode::NotFound} : application.error(), request);
    }
    auto kind = clientKind(kindText.value());
    if (!kind) return error(kind.error(), request);
    auto registration = m_clients->registerClient(
        applicationId, std::move(name).value(), kind.value(),
        std::move(redirects).value(), std::move(scopes).value());
    if (!registration) return error(registration.error(), request);
    json::object response = clientJson(registration->client());
    if (registration->secret()) response["client_secret"] = registration->secret()->expose();
    response["client_secret_returned_once"] = registration->secret().has_value();
    return jsonResponse(201, std::move(response));
}

gateway::HttpResponse ApplicationManagementHttpApi::rotateClientSecret(gateway::HttpRequest request)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"client_id"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto id = requiredString(body.value(), "client_id", 256U);
    if (!id) return error(id.error(), request);
    client::ClientId clientId{id.value()};
    auto found = m_clientRepository->findById(clientId);
    if (!found || !found->has_value()) return error(found ? foundation::Error{foundation::ErrorCode::NotFound} : found.error(), request);
    auto application = m_applicationRepository->findById(found->value().applicationId());
    if (!application || !application->has_value() || application->value().owner() != m_organization) return error(application ? foundation::Error{foundation::ErrorCode::NotFound} : application.error(), request);
    auto secret = m_clients->rotateSecret(clientId);
    if (!secret) return error(secret.error(), request);
    json::object response; response["client_id"] = clientId.value(); response["client_secret"] = secret->expose(); response["client_secret_returned_once"] = true;
    return jsonResponse(200, std::move(response));
}

gateway::HttpResponse ApplicationManagementHttpApi::jarKey(gateway::HttpRequest request)
{
    const auto clientIdText = queryParameter(request.target(), "client_id");
    if (!clientIdText) return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    const client::ClientId clientId{std::string{*clientIdText}};
    auto found = m_clientRepository->findById(clientId);
    if (!found || !found->has_value()) {
        return error(found ? foundation::Error{foundation::ErrorCode::NotFound} : found.error(), request);
    }
    auto application = m_applicationRepository->findById(found->value().applicationId());
    if (!application || !application->has_value() || application->value().owner() != m_organization) {
        return error(application ? foundation::Error{foundation::ErrorCode::NotFound} : application.error(), request);
    }
    auto key = m_jar->key(clientId);
    if (!key) return error(key.error(), request);
    json::object response;
    response["client_id"] = std::string{clientId.value()};
    response["key_id"] = std::string{key->keyId()};
    response["public_key_pem"] = std::string{key->publicKeyPem()};
    return jsonResponse(200, std::move(response));
}

gateway::HttpResponse ApplicationManagementHttpApi::registerJarKey(gateway::HttpRequest request)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"client_id", "key_id", "public_key_pem"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    }
    auto clientIdText = requiredString(body.value(), "client_id", 256U);
    auto keyId = requiredString(body.value(), "key_id", 128U);
    auto publicKeyPem = requiredMultilineString(body.value(), "public_key_pem", 16U * 1024U);
    if (!clientIdText || !keyId || !publicKeyPem) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    const client::ClientId clientId{clientIdText.value()};
    auto found = m_clientRepository->findById(clientId);
    if (!found || !found->has_value()) {
        return error(found ? foundation::Error{foundation::ErrorCode::NotFound} : found.error(), request);
    }
    auto application = m_applicationRepository->findById(found->value().applicationId());
    if (!application || !application->has_value() || application->value().owner() != m_organization) {
        return error(application ? foundation::Error{foundation::ErrorCode::NotFound} : application.error(), request);
    }
    auto status = m_jar->registerKey(
        clientId, std::move(keyId).value(), std::move(publicKeyPem).value());
    if (!status) return error(status.error(), request);
    json::object response;
    response["client_id"] = std::string{clientId.value()};
    response["registered"] = true;
    return jsonResponse(200, std::move(response));
}

gateway::HttpResponse ApplicationManagementHttpApi::removeJarKey(gateway::HttpRequest request)
{
    const auto clientIdText = queryParameter(request.target(), "client_id");
    if (!clientIdText) return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    const client::ClientId clientId{std::string{*clientIdText}};
    auto found = m_clientRepository->findById(clientId);
    if (!found || !found->has_value()) {
        return error(found ? foundation::Error{foundation::ErrorCode::NotFound} : found.error(), request);
    }
    auto application = m_applicationRepository->findById(found->value().applicationId());
    if (!application || !application->has_value() || application->value().owner() != m_organization) {
        return error(application ? foundation::Error{foundation::ErrorCode::NotFound} : application.error(), request);
    }
    auto status = m_jar->removeKey(clientId);
    if (!status) return error(status.error(), request);
    return gateway::HttpResponse{204, {}, {}};
}

gateway::HttpResponse ApplicationManagementHttpApi::changeClient(
    gateway::HttpRequest request, std::string_view action)
{
    if (action != "suspend" && action != "activate" && action != "revoke") return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"client_id"})) return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    auto id = requiredString(body.value(), "client_id", 256U);
    if (!id) return error(id.error(), request);
    client::ClientId clientId{id.value()};
    auto found = m_clientRepository->findById(clientId);
    if (!found || !found->has_value()) return error(found ? foundation::Error{foundation::ErrorCode::NotFound} : found.error(), request);
    auto application = m_applicationRepository->findById(found->value().applicationId());
    if (!application || !application->has_value() || application->value().owner() != m_organization) return error(application ? foundation::Error{foundation::ErrorCode::NotFound} : application.error(), request);
    foundation::Result<client::Client> changed = action == "suspend"
        ? m_clients->suspend(clientId)
        : action == "activate" ? m_clients->activate(clientId) : m_clients->revoke(clientId);
    return changed ? jsonResponse(200, clientJson(changed.value())) : error(changed.error(), request);
}


namespace {
[[nodiscard]] json::object resourceJson(const resource::ResourceServer& value)
{
    json::object output;
    output["id"] = std::string{value.id().value()};
    output["audience"] = std::string{value.audience()};
    output["name"] = std::string{value.displayName()};
    output["status"] = value.status() == resource::ResourceStatus::Active ? "active"
        : value.status() == resource::ResourceStatus::Suspended ? "suspended" : "revoked";
    json::array scopes;
    for (const auto& scope : value.scopes()) scopes.emplace_back(scope);
    output["scopes"] = std::move(scopes);
    return output;
}

[[nodiscard]] json::object serviceIdentityJson(const resource::ServiceIdentity& value)
{
    json::object output;
    output["identity_id"] = std::string{value.identity().value()};
    output["client_id"] = std::string{value.client().value()};
    output["active"] = value.active();
    json::array audiences;
    for (const auto& audience : value.audiences()) audiences.emplace_back(audience);
    output["audiences"] = std::move(audiences);
    json::array scopes;
    for (const auto& scope : value.scopes()) scopes.emplace_back(scope);
    output["scopes"] = std::move(scopes);
    return output;
}
}

gateway::HttpResponse ApplicationManagementHttpApi::listResources(gateway::HttpRequest request)
{
    auto values = m_resources->list();
    if (!values) return error(values.error(), request);
    json::array items;
    for (const auto& value : values.value()) items.emplace_back(resourceJson(value));
    json::object body;
    body["resources"] = std::move(items);
    return jsonResponse(200, std::move(body));
}

gateway::HttpResponse ApplicationManagementHttpApi::createResource(gateway::HttpRequest request)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"audience", "name", "scopes"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    }
    auto audience = requiredString(body.value(), "audience", 2048U);
    auto name = requiredString(body.value(), "name", 120U);
    auto scopes = requiredStrings(body.value(), "scopes", 256U, 128U);
    if (!audience || !name || !scopes) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    auto created = m_resources->registerResource(
        std::move(audience).value(), std::move(name).value(), std::move(scopes).value());
    return created ? jsonResponse(201, resourceJson(created.value())) : error(created.error(), request);
}

gateway::HttpResponse ApplicationManagementHttpApi::changeResource(
    gateway::HttpRequest request, std::string_view action)
{
    resource::ResourceStatus status{};
    if (action == "activate") status = resource::ResourceStatus::Active;
    else if (action == "suspend") status = resource::ResourceStatus::Suspended;
    else if (action == "revoke") status = resource::ResourceStatus::Revoked;
    else return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"audience"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    }
    auto audience = requiredString(body.value(), "audience", 2048U);
    if (!audience) return error(audience.error(), request);
    auto changed = m_resources->setStatus(audience.value(), status);
    return changed ? jsonResponse(200, resourceJson(changed.value())) : error(changed.error(), request);
}

gateway::HttpResponse ApplicationManagementHttpApi::provisionServiceIdentity(
    gateway::HttpRequest request)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"client_id", "audiences", "scopes"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    }
    auto id = requiredString(body.value(), "client_id", 256U);
    auto audiences = requiredStrings(body.value(), "audiences", 64U, 2048U);
    auto scopes = requiredStrings(body.value(), "scopes", 256U, 128U);
    if (!id || !audiences || !scopes) {
        return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    }
    auto created = m_serviceIdentities->provision(
        client::ClientId{std::move(id).value()}, std::move(audiences).value(),
        std::move(scopes).value());
    return created ? jsonResponse(201, serviceIdentityJson(created.value()))
                   : error(created.error(), request);
}

gateway::HttpResponse ApplicationManagementHttpApi::serviceIdentity(gateway::HttpRequest request)
{
    const auto clientId = queryParameter(request.target(), "client_id");
    if (!clientId) return error(foundation::Error{foundation::ErrorCode::InvalidArgument}, request);
    auto found = m_serviceIdentities->find(client::ClientId{std::string{*clientId}});
    return found ? jsonResponse(200, serviceIdentityJson(found.value())) : error(found.error(), request);
}

gateway::HttpResponse ApplicationManagementHttpApi::changeServiceIdentity(
    gateway::HttpRequest request, bool active)
{
    auto body = parseObject(request);
    if (!body || !onlyFields(body.value(), {"client_id"})) {
        return error(body ? foundation::Error{foundation::ErrorCode::InvalidArgument} : body.error(), request);
    }
    auto id = requiredString(body.value(), "client_id", 256U);
    if (!id) return error(id.error(), request);
    auto changed = m_serviceIdentities->setActive(
        client::ClientId{std::move(id).value()}, active);
    return changed ? jsonResponse(200, serviceIdentityJson(changed.value()))
                   : error(changed.error(), request);
}

}
