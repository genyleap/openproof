module;

#include <optional>

export module openproof.enterprise.scim.http;

import openproof.enterprise.scim;
import openproof.foundation;
import openproof.gateway;
import openproof.identity.core;

export namespace openproof::enterprise::scim::http {

// Shared wire helpers for the native read path. No repository calls.
[[nodiscard]] foundation::Result<ReadRequest> parseReadRequest(const gateway::HttpRequest& request);
[[nodiscard]] gateway::HttpResponse renderReadResult(const ReadRequest& request,ReadResult result);
[[nodiscard]] foundation::Result<MutationRequest> parseMutationRequest(const gateway::HttpRequest& request);
[[nodiscard]] gateway::HttpResponse renderMutationResult(const MutationRequest& request,ReadResult result);
[[nodiscard]] gateway::HttpResponse renderScimError(const foundation::Error& failure);
[[nodiscard]] std::optional<gateway::HttpResponse> renderDiscovery(const gateway::HttpRequest& request);

/** @brief RFC 7644 SCIM 2.0 Users/Groups HTTP provisioning surface. */
class Api final : public gateway::HttpHandler {
public:
    Api(Service& service, foundation::SecretString bearerToken,
        gateway::TokenBucketRateLimiter& rateLimiter,
        gateway::HttpHandler& fallback);

    [[nodiscard]] gateway::HttpResponse handle(gateway::HttpRequest request) override;

private:
    [[nodiscard]] gateway::HttpResponse users(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse user(gateway::HttpRequest request,
                                             identity::core::IdentityId id);
    [[nodiscard]] gateway::HttpResponse groups(gateway::HttpRequest request);
    [[nodiscard]] gateway::HttpResponse group(gateway::HttpRequest request, GroupId id);
    [[nodiscard]] gateway::HttpResponse serviceProviderConfig(const gateway::HttpRequest& request) const;
    [[nodiscard]] gateway::HttpResponse resourceTypes(const gateway::HttpRequest& request) const;
    [[nodiscard]] gateway::HttpResponse schemas(const gateway::HttpRequest& request) const;
    [[nodiscard]] bool authorized(const gateway::HttpRequest& request) const;
    [[nodiscard]] gateway::HttpResponse error(const foundation::Error& failure,
                                              const gateway::HttpRequest& request) const;

    Service* m_service;
    foundation::SecretString m_bearerToken;
    gateway::TokenBucketRateLimiter* m_rateLimiter;
    gateway::HttpHandler* m_fallback;
};

} // namespace openproof::enterprise::scim::http
