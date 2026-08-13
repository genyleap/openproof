module;

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/json.hpp>

module openproof.enterprise.scim.http;

import openproof.security;

namespace openproof::enterprise::scim::http {
namespace {
namespace json = boost::json;
constexpr std::string_view kUserSchema{"urn:ietf:params:scim:schemas:core:2.0:User"};
constexpr std::string_view kGroupSchema{"urn:ietf:params:scim:schemas:core:2.0:Group"};
constexpr std::string_view kListSchema{"urn:ietf:params:scim:api:messages:2.0:ListResponse"};
constexpr std::string_view kErrorSchema{"urn:ietf:params:scim:api:messages:2.0:Error"};
constexpr std::string_view kPatchSchema{"urn:ietf:params:scim:api:messages:2.0:PatchOp"};
constexpr std::size_t kMaximumBody = 1024U * 1024U;

void secure(gateway::HttpResponse& response)
{
    response.setHeader("cache-control", "no-store");
    response.setHeader("pragma", "no-cache");
    response.setHeader("x-content-type-options", "nosniff");
    response.setHeader("referrer-policy", "no-referrer");
}

[[nodiscard]] gateway::HttpResponse scimResponse(int status, json::value body)
{
    gateway::HttpResponse response{status,
        gateway::Headers{{"content-type", "application/scim+json"}}, json::serialize(body)};
    secure(response);
    return response;
}

[[nodiscard]] foundation::Result<json::object> parseObject(const gateway::HttpRequest& request)
{
    const auto contentType = request.header("content-type");
    if (request.body().empty() || request.body().size() > kMaximumBody || !contentType
        || (!contentType->starts_with("application/scim+json")
            && !contentType->starts_with("application/json"))) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    boost::system::error_code ec;
    auto parsed = json::parse(request.body(), ec);
    if (ec || !parsed.is_object()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return std::move(parsed).as_object();
}

[[nodiscard]] std::optional<unsigned int> hex(char symbol) noexcept
{
    if (symbol >= '0' && symbol <= '9') return static_cast<unsigned int>(symbol - '0');
    if (symbol >= 'A' && symbol <= 'F') return 10U + static_cast<unsigned int>(symbol - 'A');
    if (symbol >= 'a' && symbol <= 'f') return 10U + static_cast<unsigned int>(symbol - 'a');
    return std::nullopt;
}

[[nodiscard]] foundation::Result<std::string> urlDecode(std::string_view value)
{
    std::string output;
    output.reserve(value.size());
    for (std::size_t i = 0U; i < value.size(); ++i) {
        if (value[i] == '%') {
            if (i + 2U >= value.size()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
            auto hi = hex(value[i + 1U]); auto lo = hex(value[i + 2U]);
            if (!hi || !lo) return foundation::fail(foundation::ErrorCode::InvalidArgument);
            output.push_back(static_cast<char>((*hi << 4U) | *lo));
            i += 2U;
        } else if (value[i] == '+') output.push_back(' ');
        else output.push_back(value[i]);
    }
    return output;
}

using Query = std::map<std::string, std::string, std::less<>>;
[[nodiscard]] foundation::Result<Query> query(const gateway::HttpRequest& request)
{
    const auto target = request.target();
    const auto question = target.find('?');
    if (question == std::string_view::npos) return Query{};
    std::string_view input = target.substr(question + 1U);
    Query output;
    while (!input.empty()) {
        const auto amp = input.find('&');
        auto item = input.substr(0U, amp);
        const auto eq = item.find('=');
        if (eq == std::string_view::npos) return foundation::fail(foundation::ErrorCode::InvalidArgument);
        auto key = urlDecode(item.substr(0U, eq)); auto value = urlDecode(item.substr(eq + 1U));
        if (!key || !value || key->empty() || output.contains(key.value())) return foundation::fail(foundation::ErrorCode::InvalidArgument);
        output.emplace(std::move(key).value(), std::move(value).value());
        if (amp == std::string_view::npos) break;
        input.remove_prefix(amp + 1U);
    }
    return output;
}

[[nodiscard]] foundation::Result<std::optional<std::string>> optionalString(
    const json::object& object, std::string_view name, std::size_t maximum)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || value->is_null()) return std::optional<std::string>{};
    if (!value->is_string()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    std::string text{value->as_string()};
    if (text.empty() || text.size() > maximum || std::ranges::any_of(text, [](char symbol) {
            const auto byte = static_cast<unsigned char>(symbol);
            return byte < 0x20U || byte == 0x7FU;
        })) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    }
    return std::optional<std::string>{std::move(text)};
}

[[nodiscard]] foundation::Result<std::string> requiredString(const json::object& object,
                                                             std::string_view name,
                                                             std::size_t maximum)
{
    auto value = optionalString(object, name, maximum);
    if (!value) return foundation::fail(value.error());
    if (!value->has_value()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return std::move(value).value().value();
}

[[nodiscard]] foundation::Result<bool> booleanValue(const json::object& object,
                                                    std::string_view name, bool fallback)
{
    const auto* value = object.if_contains(name);
    if (value == nullptr || value->is_null()) return fallback;
    if (!value->is_bool()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    return value->as_bool();
}

[[nodiscard]] foundation::Result<std::optional<std::string>> primaryEmail(const json::object& object)
{
    const auto* emails = object.if_contains("emails");
    if (emails == nullptr || emails->is_null()) return std::optional<std::string>{};
    if (!emails->is_array()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    std::optional<std::string> first;
    for (const auto& item : emails->as_array()) {
        if (!item.is_object()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
        auto value = optionalString(item.as_object(), "value", 320U);
        if (!value) return foundation::fail(value.error());
        if (!value->has_value()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
        if (!first) first = value->value();
        const auto* primary = item.as_object().if_contains("primary");
        if (primary != nullptr && !primary->is_bool()) {
            return foundation::fail(foundation::ErrorCode::InvalidArgument);
        }
        if (primary != nullptr && primary->as_bool()) return std::optional<std::string>{value->value()};
    }
    return first;
}

[[nodiscard]] foundation::Result<std::vector<identity::core::IdentityId>> members(const json::object& object)
{
    const auto* values = object.if_contains("members");
    if (values == nullptr || values->is_null()) return std::vector<identity::core::IdentityId>{};
    if (!values->is_array() || values->as_array().size() > 10000U) return foundation::fail(foundation::ErrorCode::InvalidArgument);
    std::vector<identity::core::IdentityId> output;
    output.reserve(values->as_array().size());
    for (const auto& item : values->as_array()) {
        if (!item.is_object()) return foundation::fail(foundation::ErrorCode::InvalidArgument);
        auto value = requiredString(item.as_object(), "value", 256U);
        if (!value) return foundation::fail(value.error());
        output.emplace_back(std::move(value).value());
    }
    return output;
}

[[nodiscard]] std::string versionTag(foundation::Instant updatedAt)
{
    return "W/\"" + std::to_string(updatedAt.time_since_epoch().count()) + "\"";
}

[[nodiscard]] foundation::Status validateIfMatch(
    const gateway::HttpRequest& request, foundation::Instant updatedAt)
{
    const auto condition = request.header("if-match");
    if (!condition || *condition == "*" || *condition == versionTag(updatedAt)) {
        return foundation::ok();
    }
    return foundation::fail(
        foundation::ErrorCode::FailedPrecondition,
        "The SCIM resource changed after the supplied If-Match version.");
}

[[nodiscard]] bool containsSchema(const json::value* value, std::string_view expected)
{
    if (value == nullptr || !value->is_array()) {
        return false;
    }
    return std::ranges::any_of(value->as_array(), [expected](const json::value& item) {
        if (!item.is_string()) {
            return false;
        }
        const auto& text = item.as_string();
        return std::string_view{text.data(), text.size()} == expected;
    });
}

[[nodiscard]] json::object userJson(const UserView& value)
{
    json::object output;
    output["schemas"] = json::array{std::string{kUserSchema}};
    output["id"] = value.record.identity().value();
    if (value.record.externalId()) output["externalId"] = *value.record.externalId();
    output["userName"] = value.record.userName();
    output["active"] = value.status == identity::core::IdentityStatus::Active;
    if (value.profile) {
        if (value.profile->displayName()) output["displayName"] = *value.profile->displayName();
        if (value.profile->email()) {
            json::object email;
            email["value"] = *value.profile->email();
            email["primary"] = true;
            output["emails"] = json::array{std::move(email)};
        }
    }
    json::object meta;
    meta["resourceType"] = "User";
    meta["created"] = foundation::toIso8601(value.record.createdAt());
    meta["lastModified"] = foundation::toIso8601(value.record.updatedAt());
    meta["location"] = "/scim/v2/Users/" + std::string{value.record.identity().value()};
    meta["version"] = versionTag(value.record.updatedAt());
    output["meta"] = std::move(meta);
    return output;
}

[[nodiscard]] json::object groupJson(const GroupView& value)
{
    json::object output;
    output["schemas"] = json::array{std::string{kGroupSchema}};
    output["id"] = value.record.id().value();
    if (value.record.externalId()) output["externalId"] = *value.record.externalId();
    output["displayName"] = value.record.displayName();
    json::array groupMembers;
    for (const auto& member : value.members) {
        json::object item;
        item["value"] = member.value();
        item["$ref"] = "/scim/v2/Users/" + std::string{member.value()};
        groupMembers.push_back(std::move(item));
    }
    output["members"] = std::move(groupMembers);
    json::object meta;
    meta["resourceType"] = "Group";
    meta["created"] = foundation::toIso8601(value.record.createdAt());
    meta["lastModified"] = foundation::toIso8601(value.record.updatedAt());
    meta["location"] = "/scim/v2/Groups/" + std::string{value.record.id().value()};
    meta["version"] = versionTag(value.record.updatedAt());
    output["meta"] = std::move(meta);
    return output;
}

[[nodiscard]] json::object listResponse(json::array resources, std::size_t total,
                                        std::size_t startIndex = 1U)
{
    json::object output;
    output["schemas"] = json::array{std::string{kListSchema}};
    output["totalResults"] = total;
    output["startIndex"] = startIndex;
    output["itemsPerPage"] = resources.size();
    output["Resources"] = std::move(resources);
    return output;
}

[[nodiscard]] std::optional<std::pair<std::string, std::string>> equalityFilter(std::string_view filter)
{
    const auto eq = filter.find(" eq ");
    if (eq == std::string_view::npos) return std::nullopt;
    std::string attribute{filter.substr(0U, eq)};
    auto value = filter.substr(eq + 4U);
    if (value.size() < 2U || value.front() != '"' || value.back() != '"') return std::nullopt;
    value.remove_prefix(1U); value.remove_suffix(1U);
    if (value.contains('"') || value.contains('\\')) return std::nullopt;
    return std::pair{std::move(attribute), std::string{value}};
}

[[nodiscard]] foundation::Error invalidSyntax()
{
    return foundation::Error{foundation::ErrorCode::InvalidArgument, "Invalid SCIM request."};
}

} // namespace

Api::Api(Service& service, foundation::SecretString bearerToken,
         gateway::TokenBucketRateLimiter& rateLimiter, gateway::HttpHandler& fallback)
    : m_service(&service), m_bearerToken(std::move(bearerToken)),
      m_rateLimiter(&rateLimiter), m_fallback(&fallback) {}

bool Api::authorized(const gateway::HttpRequest& request) const
{
    const auto authorization = request.header("authorization");
    constexpr std::string_view prefix{"Bearer "};
    return authorization && authorization->starts_with(prefix)
        && authorization->size() == prefix.size() + m_bearerToken.size()
        && security::constantTimeEquals(authorization->substr(prefix.size()), m_bearerToken.expose());
}

gateway::HttpResponse Api::error(const foundation::Error& failure,
                                 const gateway::HttpRequest&) const
{
    int status = foundation::errorHttpStatus(failure.code());
    if (failure.code() == foundation::ErrorCode::AlreadyExists) status = 409;
    json::object body;
    body["schemas"] = json::array{std::string{kErrorSchema}};
    body["status"] = std::to_string(status);
    body["detail"] = failure.message();
    if (failure.code() == foundation::ErrorCode::AlreadyExists) body["scimType"] = "uniqueness";
    else if (failure.code() == foundation::ErrorCode::InvalidArgument) body["scimType"] = "invalidValue";
    else if (failure.code() == foundation::ErrorCode::NotFound) body["scimType"] = "noTarget";
    return scimResponse(status, std::move(body));
}

gateway::HttpResponse Api::handle(gateway::HttpRequest request)
{
    if (request.path() != "/scim/v2" && !request.path().starts_with("/scim/v2/")) {
        return m_fallback->handle(std::move(request));
    }
    if (!m_rateLimiter->allow(std::string{"scim-ip:"} + std::string{request.remoteAddress()})) {
        return error(foundation::Error{foundation::ErrorCode::RateLimited}, request);
    }
    if (!authorized(request)) {
        auto response = error(foundation::Error{foundation::ErrorCode::AuthenticationRequired}, request);
        response.setHeader("www-authenticate", "Bearer realm=\"OpenProof SCIM\"");
        return response;
    }
    if (request.path() == "/scim/v2/ServiceProviderConfig" && request.method() == gateway::HttpMethod::Get) {
        return serviceProviderConfig(request);
    }
    if (request.path() == "/scim/v2/ResourceTypes" && request.method() == gateway::HttpMethod::Get) {
        return resourceTypes(request);
    }
    if (request.path() == "/scim/v2/Schemas" && request.method() == gateway::HttpMethod::Get) {
        return schemas(request);
    }
    if (request.path() == "/scim/v2/Users") return users(std::move(request));
    if (request.path().starts_with("/scim/v2/Users/")) {
        const auto id = request.path().substr(std::string_view{"/scim/v2/Users/"}.size());
        if (id.empty() || id.contains('/')) return error(invalidSyntax(), request);
        return user(std::move(request), identity::core::IdentityId{std::string{id}});
    }
    if (request.path() == "/scim/v2/Groups") return groups(std::move(request));
    if (request.path().starts_with("/scim/v2/Groups/")) {
        const auto id = request.path().substr(std::string_view{"/scim/v2/Groups/"}.size());
        if (id.empty() || id.contains('/')) return error(invalidSyntax(), request);
        return group(std::move(request), GroupId{std::string{id}});
    }
    return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
}

gateway::HttpResponse Api::users(gateway::HttpRequest request)
{
    if (request.method() == gateway::HttpMethod::Get) {
        auto parameters = query(request);
        if (!parameters) return error(parameters.error(), request);
        json::array resources;
        std::size_t total = 0U;
        if (const auto it = parameters->find("filter"); it != parameters->end()) {
            auto filter = equalityFilter(it->second);
            if (!filter || filter->first != "userName") return error(invalidSyntax(), request);
            auto found = m_service->userByName(filter->second);
            if (!found) return error(found.error(), request);
            if (found->has_value()) { resources.push_back(userJson(found->value())); total = 1U; }
        } else {
            auto values = m_service->users();
            if (!values) return error(values.error(), request);
            total = values->size();
            for (const auto& value : values.value()) resources.push_back(userJson(value));
        }
        return scimResponse(200, listResponse(std::move(resources), total));
    }
    if (request.method() != gateway::HttpMethod::Post) return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    auto body = parseObject(request);
    if (!body) return error(body.error(), request);
    auto userName = requiredString(body.value(), "userName", 320U);
    if (!userName) return error(userName.error(), request);
    auto externalId = optionalString(body.value(), "externalId", 1024U);
    auto active = booleanValue(body.value(), "active", true);
    auto displayName = optionalString(body.value(), "displayName", 512U);
    auto email = primaryEmail(body.value());
    if (!externalId || !active || !displayName || !email) return error(invalidSyntax(), request);
    auto created = m_service->createUser(std::move(userName).value(), std::move(externalId).value(),
        active.value(), std::move(displayName).value(), std::move(email).value());
    if (!created) return error(created.error(), request);
    auto response = scimResponse(201, userJson(created.value()));
    response.setHeader("location", "/scim/v2/Users/" + std::string{created->record.identity().value()});
    response.setHeader("etag", versionTag(created->record.updatedAt()));
    return response;
}

gateway::HttpResponse Api::user(gateway::HttpRequest request, identity::core::IdentityId id)
{
    if (request.method() == gateway::HttpMethod::Get) {
        auto value = m_service->user(id);
        if (!value) return error(value.error(), request);
        auto response = scimResponse(200, userJson(value.value()));
        response.setHeader("etag", versionTag(value->record.updatedAt()));
        return response;
    }
    if (request.method() == gateway::HttpMethod::Delete) {
        if (request.header("if-match")) {
            auto current = m_service->user(id);
            if (!current) return error(current.error(), request);
            auto condition = validateIfMatch(request, current->record.updatedAt());
            if (!condition) return error(condition.error(), request);
        }
        auto status = m_service->removeUser(id);
        if (!status) return error(status.error(), request);
        gateway::HttpResponse response{204, {}, {}};
        secure(response);
        return response;
    }
    if (request.method() == gateway::HttpMethod::Put) {
        if (request.header("if-match")) {
            auto current = m_service->user(id);
            if (!current) return error(current.error(), request);
            auto condition = validateIfMatch(request, current->record.updatedAt());
            if (!condition) return error(condition.error(), request);
        }
        auto body = parseObject(request);
        if (!body) return error(body.error(), request);
        auto userName = requiredString(body.value(), "userName", 320U);
        if (!userName) return error(userName.error(), request);
        auto externalId = optionalString(body.value(), "externalId", 1024U);
        auto active = booleanValue(body.value(), "active", true);
        auto displayName = optionalString(body.value(), "displayName", 512U);
        auto email = primaryEmail(body.value());
        if (!externalId || !active || !displayName || !email) return error(invalidSyntax(), request);
        auto value = m_service->replaceUser(id, std::move(userName).value(), std::move(externalId).value(),
            active.value(), std::move(displayName).value(), std::move(email).value());
        if (!value) return error(value.error(), request);
        auto response = scimResponse(200, userJson(value.value()));
        response.setHeader("etag", versionTag(value->record.updatedAt()));
        return response;
    }
    if (request.method() == gateway::HttpMethod::Patch) {
        auto current = m_service->user(id);
        auto body = parseObject(request);
        if (!current || !body) return error(current ? body.error() : current.error(), request);
        const auto* schemasValue = body->if_contains("schemas");
        const auto* operationsValue = body->if_contains("Operations");
        if (!containsSchema(schemasValue, kPatchSchema)
            || operationsValue == nullptr || !operationsValue->is_array()) {
            return error(invalidSyntax(), request);
        }
        auto condition = validateIfMatch(request, current->record.updatedAt());
        if (!condition) return error(condition.error(), request);
        std::string userName{current->record.userName()};
        auto externalId = current->record.externalId();
        bool active = current->status == identity::core::IdentityStatus::Active;
        auto displayName = current->profile ? current->profile->displayName() : std::optional<std::string>{};
        auto email = current->profile ? current->profile->email() : std::optional<std::string>{};
        for (const auto& operationValue : operationsValue->as_array()) {
            if (!operationValue.is_object()) return error(invalidSyntax(), request);
            const auto& operation = operationValue.as_object();
            auto op = requiredString(operation, "op", 16U);
            if (!op || (op.value() != "replace" && op.value() != "Replace")) return error(invalidSyntax(), request);
            auto path = optionalString(operation, "path", 128U);
            if (!path) return error(invalidSyntax(), request);
            const auto* value = operation.if_contains("value");
            if (!path->has_value()) {
                if (value == nullptr || !value->is_object()) return error(invalidSyntax(), request);
                const auto& patch = value->as_object();
                auto patchedUserName = optionalString(patch, "userName", 320U);
                auto patchedExternalId = optionalString(patch, "externalId", 1024U);
                auto patchedDisplayName = optionalString(patch, "displayName", 512U);
                auto patchedEmail = primaryEmail(patch);
                auto patchedActive = booleanValue(patch, "active", active);
                if (!patchedUserName || !patchedExternalId || !patchedDisplayName || !patchedEmail || !patchedActive) {
                    return error(invalidSyntax(), request);
                }
                if (patchedUserName->has_value()) userName = patchedUserName->value();
                if (patchedExternalId->has_value()) externalId = patchedExternalId->value();
                if (patchedDisplayName->has_value()) displayName = patchedDisplayName->value();
                if (patchedEmail->has_value()) email = patchedEmail->value();
                active = patchedActive.value();
                continue;
            }
            if (value == nullptr) return error(invalidSyntax(), request);
            const auto& pathValue = path->value();
            if (pathValue == "active" && value->is_bool()) active = value->as_bool();
            else if (pathValue == "userName" && value->is_string()) userName = std::string{value->as_string()};
            else if (pathValue == "displayName" && value->is_string()) displayName = std::string{value->as_string()};
            else if (pathValue == "externalId" && value->is_string()) externalId = std::string{value->as_string()};
            else return error(invalidSyntax(), request);
        }
        auto updated = m_service->replaceUser(id, std::move(userName), std::move(externalId), active,
                                              std::move(displayName), std::move(email));
        if (!updated) return error(updated.error(), request);
        auto response = scimResponse(200, userJson(updated.value()));
        response.setHeader("etag", versionTag(updated->record.updatedAt()));
        return response;
    }
    return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
}

gateway::HttpResponse Api::groups(gateway::HttpRequest request)
{
    if (request.method() == gateway::HttpMethod::Get) {
        auto parameters = query(request);
        if (!parameters) return error(parameters.error(), request);
        json::array resources;
        std::size_t total = 0U;
        if (const auto it = parameters->find("filter"); it != parameters->end()) {
            auto filter = equalityFilter(it->second);
            if (!filter || filter->first != "displayName") return error(invalidSyntax(), request);
            auto found = m_service->groupByName(filter->second);
            if (!found) return error(found.error(), request);
            if (found->has_value()) { resources.push_back(groupJson(found->value())); total = 1U; }
        } else {
            auto values = m_service->groups();
            if (!values) return error(values.error(), request);
            total = values->size();
            for (const auto& value : values.value()) resources.push_back(groupJson(value));
        }
        return scimResponse(200, listResponse(std::move(resources), total));
    }
    if (request.method() != gateway::HttpMethod::Post) return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
    auto body = parseObject(request);
    if (!body) return error(body.error(), request);
    auto displayName = requiredString(body.value(), "displayName", 512U);
    auto groupMembers = members(body.value());
    if (!displayName || !groupMembers) return error(displayName ? groupMembers.error() : displayName.error(), request);
    auto externalId = optionalString(body.value(), "externalId", 1024U);
    if (!externalId) return error(invalidSyntax(), request);
    auto created = m_service->createGroup(std::move(displayName).value(), std::move(externalId).value(),
                                          std::move(groupMembers).value());
    if (!created) return error(created.error(), request);
    auto response = scimResponse(201, groupJson(created.value()));
    response.setHeader("location", "/scim/v2/Groups/" + std::string{created->record.id().value()});
    response.setHeader("etag", versionTag(created->record.updatedAt()));
    return response;
}

gateway::HttpResponse Api::group(gateway::HttpRequest request, GroupId id)
{
    if (request.method() == gateway::HttpMethod::Get) {
        auto value = m_service->group(id);
        if (!value) return error(value.error(), request);
        auto response = scimResponse(200, groupJson(value.value()));
        response.setHeader("etag", versionTag(value->record.updatedAt()));
        return response;
    }
    if (request.method() == gateway::HttpMethod::Delete) {
        if (request.header("if-match")) {
            auto current = m_service->group(id);
            if (!current) return error(current.error(), request);
            auto condition = validateIfMatch(request, current->record.updatedAt());
            if (!condition) return error(condition.error(), request);
        }
        auto status = m_service->removeGroup(id);
        if (!status) return error(status.error(), request);
        gateway::HttpResponse response{204, {}, {}};
        secure(response);
        return response;
    }
    if (request.method() == gateway::HttpMethod::Put) {
        if (request.header("if-match")) {
            auto current = m_service->group(id);
            if (!current) return error(current.error(), request);
            auto condition = validateIfMatch(request, current->record.updatedAt());
            if (!condition) return error(condition.error(), request);
        }
        auto body = parseObject(request);
        if (!body) return error(body.error(), request);
        auto displayName = requiredString(body.value(), "displayName", 512U);
        auto groupMembers = members(body.value());
        if (!displayName || !groupMembers) return error(displayName ? groupMembers.error() : displayName.error(), request);
        auto externalId = optionalString(body.value(), "externalId", 1024U);
        if (!externalId) return error(invalidSyntax(), request);
        auto value = m_service->replaceGroup(id, std::move(displayName).value(), std::move(externalId).value(),
                                             std::move(groupMembers).value());
        if (!value) return error(value.error(), request);
        auto response = scimResponse(200, groupJson(value.value()));
        response.setHeader("etag", versionTag(value->record.updatedAt()));
        return response;
    }
    if (request.method() == gateway::HttpMethod::Patch) {
        auto current = m_service->group(id);
        auto body = parseObject(request);
        if (!current || !body) return error(current ? body.error() : current.error(), request);
        const auto* schemasValue = body->if_contains("schemas");
        const auto* operationsValue = body->if_contains("Operations");
        if (!containsSchema(schemasValue, kPatchSchema)
            || operationsValue == nullptr || !operationsValue->is_array()) {
            return error(invalidSyntax(), request);
        }
        auto condition = validateIfMatch(request, current->record.updatedAt());
        if (!condition) return error(condition.error(), request);
        std::string displayName{current->record.displayName()};
        auto externalId = current->record.externalId();
        auto groupMembers = current->members;
        for (const auto& operationValue : operationsValue->as_array()) {
            if (!operationValue.is_object()) return error(invalidSyntax(), request);
            const auto& operation = operationValue.as_object();
            auto op = requiredString(operation, "op", 16U);
            auto path = optionalString(operation, "path", 256U);
            const auto* value = operation.if_contains("value");
            if (!op || !path || !path->has_value()) return error(invalidSyntax(), request);
            const auto& pathValue = path->value();
            const bool replace = op.value() == "replace" || op.value() == "Replace";
            const bool add = op.value() == "add" || op.value() == "Add";
            const bool remove = op.value() == "remove" || op.value() == "Remove";
            if (replace && pathValue == "displayName" && value && value->is_string()) displayName = std::string{value->as_string()};
            else if (replace && pathValue == "externalId" && value && value->is_string()) externalId = std::string{value->as_string()};
            else if ((replace || add) && pathValue == "members" && value && value->is_array()) {
                json::object wrapper; wrapper["members"] = *value;
                auto parsed = members(wrapper);
                if (!parsed) return error(parsed.error(), request);
                if (replace) groupMembers = std::move(parsed).value();
                else groupMembers.insert(groupMembers.end(), parsed->begin(), parsed->end());
            } else if (remove && pathValue.starts_with("members[value eq \"") && pathValue.ends_with("\"]")) {
                auto text = std::string_view{pathValue};
                text.remove_prefix(std::string_view{"members[value eq \""}.size());
                text.remove_suffix(2U);
                identity::core::IdentityId member{std::string{text}};
                std::erase(groupMembers, member);
            } else return error(invalidSyntax(), request);
        }
        auto updated = m_service->replaceGroup(id, std::move(displayName), std::move(externalId), std::move(groupMembers));
        if (!updated) return error(updated.error(), request);
        auto response = scimResponse(200, groupJson(updated.value()));
        response.setHeader("etag", versionTag(updated->record.updatedAt()));
        return response;
    }
    return error(foundation::Error{foundation::ErrorCode::NotFound}, request);
}

gateway::HttpResponse Api::serviceProviderConfig(const gateway::HttpRequest&) const
{
    json::object body;
    body["schemas"] = json::array{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"};
    body["patch"] = json::object{{"supported", true}};
    body["bulk"] = json::object{{"supported", false}, {"maxOperations", 0}, {"maxPayloadSize", 0}};
    body["filter"] = json::object{{"supported", true}, {"maxResults", 10000}};
    body["changePassword"] = json::object{{"supported", false}};
    body["sort"] = json::object{{"supported", false}};
    body["etag"] = json::object{{"supported", true}};
    body["authenticationSchemes"] = json::array{json::object{
        {"type", "oauthbearertoken"}, {"name", "Bearer Token"},
        {"description", "Operator-provisioned SCIM bearer token"}, {"primary", true}}};
    return scimResponse(200, std::move(body));
}

gateway::HttpResponse Api::resourceTypes(const gateway::HttpRequest&) const
{
    json::array resources;
    resources.push_back(json::object{{"schemas", json::array{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}},
        {"id", "User"}, {"name", "User"}, {"endpoint", "/Users"}, {"schema", std::string{kUserSchema}}});
    resources.push_back(json::object{{"schemas", json::array{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}},
        {"id", "Group"}, {"name", "Group"}, {"endpoint", "/Groups"}, {"schema", std::string{kGroupSchema}}});
    return scimResponse(200, listResponse(std::move(resources), 2U));
}

gateway::HttpResponse Api::schemas(const gateway::HttpRequest&) const
{
    json::array resources;
    resources.push_back(json::object{{"id", std::string{kUserSchema}}, {"name", "User"},
        {"description", "OpenProof SCIM user schema"}});
    resources.push_back(json::object{{"id", std::string{kGroupSchema}}, {"name", "Group"},
        {"description", "OpenProof SCIM group schema"}});
    return scimResponse(200, listResponse(std::move(resources), 2U));
}

} // namespace openproof::enterprise::scim::http
