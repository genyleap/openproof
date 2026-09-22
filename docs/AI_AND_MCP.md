# OpenProof for LLMs and MCP

OpenProof's public AI integration surface is intentionally documentation-first and read-only. AI clients should receive the same public protocol contract as human developers without gaining an administrative path into a live identity deployment.

## Canonical machine-readable sources

- `https://docs.genyleap.com/llms.txt` - compact Genyleap documentation index.
- `https://docs.genyleap.com/llms-full.txt` - expanded documentation corpus.
- `https://docs.genyleap.com/openproof/llms.txt` - OpenProof-focused index.
- `https://docs.genyleap.com/openproof/llms-full.txt` - expanded OpenProof reference.
- `https://docs.genyleap.com/openproof/api/openapi.yaml` - OpenAPI 3.1 HTTP contract.
- `https://docs.genyleap.com/openproof/handbook` - deployment and developer handbook.
- `https://docs.genyleap.com/openproof/mcp` - public read-only documentation MCP endpoint.

The OpenAPI contract remains authoritative for endpoint/method/schema details. The handbook explains deployment and integration patterns around that contract.

## Public documentation MCP

The public MCP server is designed to expose only public OpenProof knowledge.

Recommended tools:

- `search_openproof_docs(query)`
- `get_openproof_guide(topic)`
- `get_openproof_endpoint(method, path)`
- `get_openproof_example(language, use_case)`
- `get_openproof_checklist(kind)`

All tools must be marked read-only, non-destructive and idempotent. They must not read:

- `/etc/openproof`;
- provider/client secrets;
- PostgreSQL credentials;
- signing/private keys;
- live user/session/token state;
- internal server logs.

The docs MCP is not an administrative integration.

## Agent boundaries

An AI agent integrating an application should:

1. discover OpenProof through the public issuer/OpenAPI docs;
2. generate OAuth/OIDC integration code from documented flows;
3. keep secret values represented as environment/secret-store placeholders;
4. never include real access/refresh tokens, client secrets or private keys in prompts;
5. use request IDs for operational correlation;
6. distinguish public/browser clients from confidential web/service clients;
7. preserve PKCE/state/nonce validation and ID-token verification;
8. avoid inventing undocumented endpoints.

A separate operator-authorized automation system may manage infrastructure, but it should use its own authentication, audit and least-privilege controls rather than extending the public documentation MCP.

## Retrieval guidance

For RAG/indexing, prioritize content in this order:

1. `docs/openapi.yaml` for endpoint/schema facts;
2. `docs/HANDBOOK.md` for deployment/integration workflow;
3. `docs/API_GUIDE.md` for detailed protocol examples;
4. `docs/CONFIGURATION.md` for typed configuration behavior;
5. `docs/PROVIDER_SETUP.md` for provider-specific requirements;
6. `docs/OPERATIONS.md` for production operations.

If sources disagree, treat the current OpenAPI contract and current implementation-aligned handbook as the first items to reconcile, and report the discrepancy instead of silently guessing.

## Prompting template for coding assistants

A safe integration prompt can look like:

```text
Use only the OpenProof public documentation and OpenAPI contract.
Issuer: https://auth.example.com
Client type: browser
Redirect URI: https://app.example.com/oauth/callback
Scopes: openid profile offline_access

Implement Authorization Code + PKCE S256.
Validate state, returned issuer and ID-token signature/claims.
Do not hard-code secrets or log tokens.
```

## MCP client connection

Compatible clients can connect to:

```text
https://docs.genyleap.com/openproof/mcp
```

This endpoint is intentionally public because it exposes documentation only. A live OpenProof deployment's own identity APIs remain independently authenticated and are not proxied through the docs MCP.
