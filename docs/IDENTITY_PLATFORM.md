# OpenProof Identity Platform

## Purpose

OpenProof is the centralized identity and API security boundary for products.
A relying product owns its business data, but delegates account credentials,
authentication, MFA, sessions, OAuth grants and identity proof to OpenProof.

A product such as a marketplace, ride-hailing service or messenger should store
only the canonical OpenProof subject identifier it needs to associate with its
business records. It must not copy an OpenProof password, TOTP seed, refresh
credential or session store into the product database.

## Product model

An `Application` is one logical product. An application can have multiple OAuth
clients so credentials and redirect policies can be managed independently:

- `web`: confidential server-side web client;
- `browser`: public browser client using Authorization Code + PKCE;
- `native`: public desktop/mobile client using Authorization Code + PKCE;
- `service`: confidential back-channel registration reserved for service-facing
  management/integration. Version 1.0 does not issue client-credentials access
  tokens.

Application identifiers are tenant-scoped. OAuth client identifiers are unique
and stable. Revocation is terminal; suspension is reversible.

## Interactive SSO flow

1. The product creates an Authorization Code + PKCE request.
2. The user is redirected to `/oauth/authorize`.
3. OpenProof uses the existing central OpenProof session when available; otherwise
   the browser is redirected to the OpenProof-owned `/login` page.
4. OpenProof authenticates the user through its provider SPI and local
   password/TOTP provider.
5. A one-time authorization code is returned only to the exact registered
   redirect URI.
6. The product exchanges the code plus PKCE verifier at `/oauth/token`.
7. OpenProof returns an opaque access token, rotating refresh token, and an RS256
   ID Token when the `openid` scope was granted.
8. The product uses the canonical `sub` from OpenProof as its user reference.

A user that already has a central OpenProof account therefore signs into every
registered product with the same identity and does not create a second product-
local credential set.

## Protocol endpoints

- `GET /oauth/authorize`
- `POST /oauth/token`
- `GET|POST /oauth/userinfo`
- `POST /oauth/introspect`
- `POST /oauth/revoke`
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET|POST /login`

The protocol profile uses OAuth 2.0 Authorization Code + PKCE following the OAuth
2.0 Security Best Current Practice and is aligned with the OAuth 2.1 draft. The
project does not claim that OAuth 2.1 is a final RFC.

## Management API

IAL2-authenticated tenant owners can manage product registrations through:

- `GET|POST /admin/applications`
- `POST /admin/applications/suspend`
- `POST /admin/applications/activate`
- `POST /admin/applications/revoke`
- `GET /admin/clients?application_id=...`
- `POST /admin/clients`
- `POST /admin/clients/rotate-secret`
- `POST /admin/clients/suspend`
- `POST /admin/clients/activate`
- `POST /admin/clients/revoke`

Confidential client secrets are returned once after durable success. Only their
keyed digest is persisted.

## Token model

Access and refresh tokens are opaque. The database stores HMAC fingerprints,
not bearer plaintext. Default server composition uses a 15-minute access-token
lifetime and a 30-day refresh-token lifetime.

Refresh tokens rotate on every successful refresh. A replay of a consumed token
revokes its token family, including access tokens already issued from that
family. This is enforced by the repository contract and PostgreSQL transaction
locking.

## OIDC subject and claims

The ID Token always uses the canonical OpenProof `IdentityId` as `sub`; Google,
GitHub, wallet, email, ENS, Farcaster or any other external subject cannot become
the canonical key.

`profile` and `email` UserInfo claims are returned only when their corresponding
scopes are present. The profile aggregate remains independent from credentials
and identity lifecycle state.

## Gateway integration

A protected route can accept either an OpenProof platform session or an OAuth
access token. Delegated access carries the validated client ID and scopes. A
route can require a scope in addition to its existing role/assurance policy.

The gateway removes caller-supplied authentication and identity headers and
creates a signed trusted context for the upstream. This lets a product receive a
canonical identity without implementing authentication itself.

## SDKs

- `sdk/cpp`: C++26 module SDK; PKCE, state, nonce, token and UserInfo requests.
- `sdk/javascript`: WebCrypto/sessionStorage browser SDK.
- `sdk/swift`: Apple SDK using CryptoKit.
- `sdk/kotlin`: Kotlin/JVM/Android SDK.

Public clients never embed a client secret. HTTP transport is intentionally kept
outside the SDK core so products can use their platform-native networking stack.

## Tegra reference consumer

`examples/tegra-client` demonstrates the product boundary. Tegra owns products,
orders and product-specific authorization data; OpenProof owns sign-in and token
issuance. The actual Tegra repository was not included in this source input, so
this release contains a compilable reference adapter rather than modifying an
unprovided external codebase.

## Evidence and trust

Evidence is provider-neutral verified information associated with a canonical
identity. Providers integrate through `EvidenceVerifier`; the core contains no
hard-coded GitHub, Farcaster, ENS or wallet credentials.

Trust is derived from currently active evidence and current risk signals. It is
not persisted as permanent truth. Expired or revoked evidence is omitted on the
next assessment automatically.

## Account enrollment boundary

Version 1.0 centralizes login and member provisioning. The first owner is created
with the offline bootstrap ceremony; additional local identities are provisioned
through the OpenProof administration plane. Products never create or store local
passwords. A public self-service registration ceremony requires deployment-
specific anti-abuse and verification policy and is intentionally not opened by
this security-sensitive core by default.
