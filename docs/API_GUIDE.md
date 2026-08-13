# OpenProof API integration guide

This guide is the product-facing Golden Path for using OpenProof as the shared
identity core behind multiple applications. In production replace
`https://identity.example.com` with the public TLS origin in `[oidc].issuer`.
JSON requests require `Content-Type: application/json`; OAuth token requests use
`application/x-www-form-urlencoded`.

OpenProof exposes two different credentials:

- the `__Host-openproof-session` browser cookie for OpenProof account/admin
  self-service;
- OAuth access tokens for applications and APIs. Product backends should use
  OAuth/OIDC—not copy the OpenProof session cookie into their own domain.

## 1. Register and verify a consumer

Enable `[account]` and configure its authenticated delivery webhook first. The
delivery service sends the returned verification identifier and secret to the
user by email/SMS; those secrets are not logged or returned by the public API.

```bash
curl --fail-with-body https://identity.example.com/account/signup \
  -H 'Content-Type: application/json' \
  -d '{
    "email":"rider@example.com",
    "password":"correct horse battery staple",
    "display_name":"Example Rider"
  }'
```

Success is `201` with `identity_id` and `verification_required: true`. Complete
the one-time verification received through the delivery channel:

```bash
curl --fail-with-body https://identity.example.com/account/email/verify \
  -H 'Content-Type: application/json' \
  -d '{"verification_id":"VERIFICATION_ID","secret":"ONE_TIME_SECRET"}'
```

Resend uses `POST /account/email/resend` with `{"email":"..."}` and always
returns an enumeration-safe accepted response.

## 2. Sign in with password and MFA

Login is a two-step, cookie-bound ceremony. Keep the cookie jar between calls;
do not attempt to recreate the pre-authentication cookies yourself.

```bash
curl --fail-with-body -c openproof.cookies \
  https://identity.example.com/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"subject":"rider@example.com"}'
```

The `202` response contains `transaction_id` and `challenge_id`. Send them with
the password and, when configured, the current TOTP code:

```bash
curl --fail-with-body -b openproof.cookies -c openproof.cookies \
  https://identity.example.com/auth/mfa/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "transaction_id":"TRANSACTION_ID",
    "challenge_id":"CHALLENGE_ID",
    "password":"correct horse battery staple",
    "totp":"123456"
  }'
```

Success sets the secure OpenProof session cookie. Supported session operations:

| Operation | Call | Result |
|---|---|---|
| Rotate | `POST /auth/session/rotate` | Replaces the session bearer |
| Logout current | `POST /auth/logout` | Revokes current session, `204` |
| Logout all | `POST /auth/logout-all` | Revokes all identity sessions, `204` |
| Generate recovery codes | `POST /auth/recovery-codes` | IAL2 required; codes returned once |

For Google, Apple, Microsoft, GitHub, SAML and other configured providers, query
`GET /auth/providers`, then navigate the browser to:

```text
/auth/federated/start?provider=google&return_to=%2Foauth%2Fauthorize%3F...
```

The callback is `/auth/federated/callback`; upstream consoles must register the
exact public callback URI.

## 3. Connect a product with OAuth/OIDC

An active IAL2 owner creates one application and one or more OAuth clients. The
built-in UI is `GET /admin/console`; the API equivalent is:

```bash
curl --fail-with-body -b owner.cookies \
  https://identity.example.com/admin/applications \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"ride-app","name":"Ride App","environment":"production"}'
```

To provision a local operator/member directly, choose a stable internal
identifier distinct from the login subject. The generated password and TOTP
secret are returned once and must be handed off through a secure channel:

```bash
curl --fail-with-body -b owner.cookies \
  https://identity.example.com/admin/local-members \
  -H 'Content-Type: application/json' \
  -d '{
    "identity_id":"dispatch-operator-42",
    "subject":"operator@example.com",
    "roles":["dispatcher"]
  }'
```

Then register the product client. Use `native` for Android/iOS, `browser` for a
public browser client, `web` for a confidential backend and `service` for
machine-to-machine use.

```bash
curl --fail-with-body -b owner.cookies \
  https://identity.example.com/admin/clients \
  -H 'Content-Type: application/json' \
  -d '{
    "application_id":"APPLICATION_ID",
    "name":"Ride mobile",
    "kind":"native",
    "redirect_uris":["com.example.ride:/oauth/callback"],
    "scopes":["openid","profile","offline_access"]
  }'
```

Confidential clients receive `client_secret` exactly once. Store it in the
product backend secret store. Public/native/browser clients receive no secret.

Use Authorization Code + PKCE S256. The shipped SDKs generate the verifier,
challenge, state and nonce and validate returned state/issuer. JavaScript:

```javascript
import { OpenProofIdentity } from "@openproof/identity";

const identity = new OpenProofIdentity({
  issuer: "https://identity.example.com",
  clientId: "CLIENT_ID",
  redirectUri: "https://app.example.com/oauth/callback",
  scopes: ["openid", "profile", "offline_access"]
});
await identity.login();
```

At the callback, compare `state`, require returned `iss` to equal the configured
issuer, then exchange the code with the saved verifier. The SDK performs those
checks, verifies the RS256 ID Token against JWKS and returns verified claims in
`id_token_claims` with `await identity.handleCallback()`.
The equivalent direct HTTP exchange is:

```bash
curl --fail-with-body https://identity.example.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=CLIENT_ID' \
  --data-urlencode 'code=AUTHORIZATION_CODE' \
  --data-urlencode 'redirect_uri=https://app.example.com/oauth/callback' \
  --data-urlencode 'code_verifier=PKCE_VERIFIER'
```

Non-JavaScript clients must validate the ID token signature with
`/.well-known/jwks.json`, and validate at least `iss`, `aud`, `exp`, `iat` and
the original `nonce`. Discovery is at `/.well-known/openid-configuration`.

## 4. Read the current user

Product APIs should validate/introspect the access token and authorize its
audience/scope. A product client can read standard identity claims through:

```bash
curl --fail-with-body https://identity.example.com/oauth/userinfo \
  -H 'Authorization: Bearer ACCESS_TOKEN'
```

Refresh without prompting the user:

```bash
curl --fail-with-body https://identity.example.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode 'client_id=CLIENT_ID' \
  --data-urlencode 'refresh_token=REFRESH_TOKEN'
```

Every successful refresh rotates the refresh token. Persist the new token
atomically and discard the old one; replay revokes the entire family.

For an API-specific token, first create a resource:

```bash
curl --fail-with-body -b owner.cookies \
  https://identity.example.com/admin/resources \
  -H 'Content-Type: application/json' \
  -d '{
    "audience":"https://api.example.com/rides",
    "name":"Ride API",
    "scopes":["rides:read","rides:request"]
  }'
```

Request that exact resource/audience in the authorization request. The gateway
can then enforce both `required_scope` and `required_audience` on each protected
route.

## 5. Password reset and profile self-service

Start reset with an enumeration-safe request:

```bash
curl --fail-with-body https://identity.example.com/account/password/forgot \
  -H 'Content-Type: application/json' \
  -d '{"email":"rider@example.com"}'
```

Complete it using the delivered one-time proof:

```bash
curl --fail-with-body https://identity.example.com/account/password/reset \
  -H 'Content-Type: application/json' \
  -d '{
    "verification_id":"VERIFICATION_ID",
    "secret":"ONE_TIME_SECRET",
    "new_password":"a new long unique password"
  }'
```

Profile calls use the OpenProof session cookie:

```bash
curl --fail-with-body -b openproof.cookies \
  https://identity.example.com/account/profile

curl --fail-with-body -X PATCH -b openproof.cookies \
  https://identity.example.com/account/profile \
  -H 'Content-Type: application/json' \
  -d '{"display_name":"New Name","locale":"fa-IR"}'
```

Email and phone ownership are separate verified ceremonies:

- `POST /account/email/change` → `{"email":"new@example.com"}`
- `POST /account/email/change/verify` → verification identifier and secret
- `POST /account/phone` → `{"phone_number":"+989121234567"}`
- `POST /account/phone/verify` → verification identifier and secret

## 6. Passkeys

Passkey registration requires an authenticated OpenProof session:

1. `POST /account/passkeys/options`
2. call `navigator.credentials.create()` with the returned WebAuthn options;
3. `POST /account/passkeys` with the browser credential result;
4. list with `GET /account/passkeys`; remove with
   `DELETE /account/passkeys/{credential-id}`.

Passkey login is:

1. `POST /auth/passkey/options`;
2. `navigator.credentials.get()`;
3. `POST /auth/passkey/verify` with the assertion.

Do not transform base64url fields or construct authenticator data manually; use
the platform WebAuthn API and preserve the returned challenge exactly.

Other challenge/response providers also use a cookie-bound start/complete pair:

- Web3: `POST /auth/web3/start` with
  `{"provider":"ethereum","address":"0x..."}` (or `solana`; Farcaster also
  requires `fid`), sign the exact returned `message`, then call
  `POST /auth/web3/complete` with `{"message":"...","signature":"..."}`.
- LDAP: `POST /auth/ldap/start` with `{"username":"..."}`, then preserve its
  cookies and send the returned `transaction_id`, `challenge_id`, `username`
  and `username_binding` plus `password` to `POST /auth/ldap/complete`.

Never allow a wallet or LDAP client to substitute its own challenge,
transaction identifier or username binding.

## 7. Service-to-service authentication

Create a `service` client, provision its allowed audiences/scopes with
`POST /admin/service-identities`, then call:

```bash
curl --fail-with-body https://identity.example.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'client_id=CLIENT_ID' \
  --data-urlencode 'client_secret=CLIENT_SECRET' \
  --data-urlencode 'scope=rides:dispatch' \
  --data-urlencode 'resource=https://api.example.com/dispatch'
```

The result is an access token only; there is no refresh token or human session.
OpenProof currently advertises `client_secret_post` and `none` in Discovery;
do not send HTTP Basic credentials. Confidential token, PAR, device and
revocation calls put `client_id` and `client_secret` in the form body. Public
clients send `client_id` and omit the secret.

A trusted product backend can introspect a token without parsing it itself:

```bash
curl --fail-with-body https://identity.example.com/oauth/introspect \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'client_id=CONFIDENTIAL_CLIENT_ID' \
  --data-urlencode 'client_secret=CLIENT_SECRET' \
  --data-urlencode 'token=ACCESS_TOKEN'
```

The full machine-readable contract—including all account, passkey, federation,
OAuth, evidence, administration and SCIM methods—is in `docs/openapi.yaml`.

## 8. Identity evidence and trust

Authenticated users request a provider-bound one-time challenge:

```bash
curl --fail-with-body -b openproof.cookies \
  https://identity.example.com/evidence/challenge \
  -H 'Content-Type: application/json' \
  -d '{"provider":"signed-jwt-evidence"}'
```

Verify with `POST /evidence/verify` and
`{"provider":"signed-jwt-evidence","challenge":"...","assertion":"..."}`.
For X.509 use `provider: x509-evidence`, `certificate_pem` and `signature`.
Read accepted evidence with `GET /evidence` and the current derived assessment
with `GET /trust`. Trust is evidence for product policy; it never grants access
implicitly.

## 9. Enterprise provisioning

SCIM uses its own operator-generated bearer, not a user OAuth token:

```bash
curl --fail-with-body https://identity.example.com/scim/v2/Users \
  -H 'Authorization: Bearer SCIM_BEARER' \
  -H 'Content-Type: application/scim+json' \
  -d '{
    "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName":"driver@example.com",
    "displayName":"Example Driver",
    "active":true
  }'
```

Users and Groups support list, create, get, replace, patch and delete under
`/scim/v2/Users` and `/scim/v2/Groups`. Preserve `ETag` and send `If-Match` on
updates to prevent overwriting concurrent provisioning changes.

## Error contract and client rules

Errors are JSON with a stable error code, client-safe message and request ID.
Clients may branch on the code, never on prose. `401` means authentication is
required/invalid, `403` means authority or assurance is insufficient, `409`
means a state conflict and `429` requires backoff. Responses carrying secrets
set `Cache-Control: no-store`.

Never log passwords, TOTP/recovery codes, verification secrets, authorization
codes, access/refresh tokens, client secrets, cookies, DPoP proofs or private
keys. Correlate failures with the returned request ID instead.
