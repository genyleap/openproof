# Provider setup guide

OpenProof keeps provider credentials outside source control and fails closed when
provider configuration is incomplete or inconsistent. This guide is the operator
checklist for enabling every supported sign-in family.

## Common redirect-provider rules

OpenProof currently uses one canonical redirect callback for Google, GitHub, X,
Microsoft, Apple, LinkedIn and Telegram:

```
https://identity.example.com/auth/federated/callback
```

Set it with `OPENPROOF_FEDERATION_CALLBACK_URI` and register the exact same URI
in every upstream provider console. Scheme, host, path, port and trailing slash
must match exactly. Do not register a development callback in production
credentials.

Recommended production boundary:

- OpenProof itself listens only on loopback behind TLS termination.
- Nginx overwrites `X-Forwarded-For` and `X-Forwarded-Proto`.
- Provider secrets live in `/etc/openproof/providers.env` or a secret manager,
  never in Git.
- After any provider change, run
  `opp check-config --config /etc/openproof/openproof.toml`.
- Confirm the provider appears in `GET /auth/providers` before exposing its UI
  button.

For Genyleap production the canonical callback remains:

```
https://genyleap.com/openproof/auth/federated/callback
```

The optional `openproof.genyleap.com` hostname can expose the same service, but
it should not silently replace the registered callback unless every provider
console and `OPENPROOF_FEDERATION_CALLBACK_URI` are changed together.

## Google

Create an OAuth 2.0 Web application in Google Cloud, configure the exact callback
as an authorized redirect URI, and enable the standard OpenID Connect identity
scopes used by the application (`openid profile email`).

Required environment:

```
OPENPROOF_GOOGLE_CLIENT_ID=...
OPENPROOF_GOOGLE_CLIENT_SECRET=...
OPENPROOF_GOOGLE_ISSUER=https://accounts.google.com
```

Keep the consent-screen publishing/test-user state consistent with the accounts
that are expected to sign in.

## GitHub

Create a GitHub OAuth App and set its Authorization callback URL to the canonical
OpenProof callback. Use the OAuth App client ID and client secret:

```
OPENPROOF_GITHUB_CLIENT_ID=...
OPENPROOF_GITHUB_CLIENT_SECRET=...
```

The callback is shared by login and authenticated account-linking flows; do not
create a second callback for linking.

## X

OpenProof uses X OAuth 1.0a three-legged sign-in. In the X developer application,
enable user authentication, OAuth 1.0a, and register the exact callback URL.

```
OPENPROOF_X_API_KEY=...
OPENPROOF_X_API_SECRET=...
```

Do not substitute OAuth 2.0 client credentials for these variables. Callback
mismatches and applications without three-legged user authentication enabled
will fail before OpenProof can complete the exchange.

## Microsoft

Create an app registration in Microsoft Entra ID, add a Web redirect URI equal
to the canonical callback, and create a client secret. OpenProof intentionally
requires a tenant-specific v2 issuer instead of `common`,
`organizations`, `consumers`, or an issuer template.

```
OPENPROOF_MICROSOFT_CLIENT_ID=...
OPENPROOF_MICROSOFT_CLIENT_SECRET=...
OPENPROOF_MICROSOFT_ISSUER=https://login.microsoftonline.com/TENANT_ID/v2.0
```

The application should be permitted to request the OIDC identity scopes used by
the deployment.

## Apple

Create/configure a Services ID for web sign-in. Associate the production web
domain and add the exact OpenProof callback as a return URL. Configure Sign in
with Apple for the Services ID.

Use either a pre-generated client-secret JWT:

```
OPENPROOF_APPLE_CLIENT_ID=SERVICES_ID
OPENPROOF_APPLE_CLIENT_SECRET=SIGNED_CLIENT_SECRET_JWT
OPENPROOF_APPLE_ISSUER=https://appleid.apple.com
```

or allow OpenProof to generate short-lived client secrets from the Apple key:

```
OPENPROOF_APPLE_CLIENT_ID=SERVICES_ID
OPENPROOF_APPLE_TEAM_ID=TEAM_ID
OPENPROOF_APPLE_KEY_ID=KEY_ID
OPENPROOF_APPLE_PRIVATE_KEY_FILE=/run/openproof/secrets/AuthKey_KEY_ID.p8
OPENPROOF_APPLE_ISSUER=https://appleid.apple.com
```

Keep the `.p8` key owner-readable only. Apple may return name data only on the
first successful authorization; OpenProof treats that data as presentation
metadata rather than identity authority.

## LinkedIn

Create a LinkedIn application, enable the **Sign In with LinkedIn using OpenID
Connect** product, and register the exact OpenProof callback in the application's
authorized redirect URLs.

```
OPENPROOF_LINKEDIN_CLIENT_ID=...
OPENPROOF_LINKEDIN_CLIENT_SECRET=...
OPENPROOF_LINKEDIN_ISSUER=https://www.linkedin.com/oauth
```

Use the OIDC product/scopes, not legacy profile APIs. The client must be treated
as confidential and the configured redirect must match byte-for-byte.

## Telegram

Create the Telegram application/bot identity used for web sign-in and configure
its allowed web origin/redirect according to Telegram's current OAuth/OIDC
console or BotFather flow. Register the canonical callback and keep the ID-token
algorithm at RS256 for the current OpenProof implementation.

```
OPENPROOF_TELEGRAM_CLIENT_ID=...
OPENPROOF_TELEGRAM_CLIENT_SECRET=...
OPENPROOF_TELEGRAM_ISSUER=https://oauth.telegram.org
```

If Telegram approves the browser step but OpenProof rejects the callback, verify
the exact callback, client credentials, issuer and signing algorithm first.

## Passkeys / WebAuthn

Passkeys are first-party rather than an external OAuth provider:

```
OPENPROOF_WEBAUTHN_RP_ID=identity.example.com
OPENPROOF_WEBAUTHN_ORIGIN=https://identity.example.com
OPENPROOF_WEBAUTHN_RP_NAME=OpenProof
```

The RP ID must be the origin host or a valid parent-domain suffix, and the origin
must be the exact HTTPS browser origin.

## EVM wallets / SIWE

EOA authentication does not require a chain RPC. Enable the wallet provider and
bind signatures to the public OpenProof domain/URI:

```
OPENPROOF_WEB3_DOMAIN=identity.example.com
OPENPROOF_WEB3_URI=https://identity.example.com/auth/web3
OPENPROOF_ETHEREUM_WALLET_ENABLED=true
```

Configure `OPENPROOF_ETHEREUM_RPC_ENDPOINTS` only for chains where
ERC-1271/ERC-6492 smart-account verification is needed. WalletConnect/Reown is a
client transport; its Project ID belongs in the client deployment and is not an
OpenProof server credential.

## Farcaster

Farcaster uses FIP-11/SIWF plus an Optimism RPC for custody/auth-address checks:

```
OPENPROOF_WEB3_DOMAIN=identity.example.com
OPENPROOF_WEB3_URI=https://identity.example.com/auth/web3
OPENPROOF_FARCASTER_RPC_ENDPOINT=https://optimism-rpc.example
OPENPROOF_FARCASTER_CHAIN_ID=10
```

The canonical IdRegistry and KeyRegistry are defaults. Override them only for a
controlled environment.

## LDAP

Use one `ldaps://` endpoint with certificate validation:

```
OPENPROOF_LDAP_URI=ldaps://directory.example.com
OPENPROOF_LDAP_BASE_DN=dc=example,dc=com
OPENPROOF_LDAP_CA_FILE=/run/openproof/certs/ldap-ca.pem
```

Optional service-bind and attribute variables are documented in
`docs/02-CONFIGURATION.md`. Plain LDAP fallback is intentionally unsupported.

## SAML

Configure the IdP SSO URL, both entity IDs, the pinned IdP signing certificate,
and use the exact federation callback as the ACS:

```
OPENPROOF_SAML_IDP_SSO_URL=https://idp.example.com/sso
OPENPROOF_SAML_SP_ENTITY_ID=https://identity.example.com/saml
OPENPROOF_SAML_IDP_ENTITY_ID=https://idp.example.com/
OPENPROOF_SAML_IDP_CERTIFICATE_PEM=...
OPENPROOF_FEDERATION_CALLBACK_URI=https://identity.example.com/auth/federated/callback
```

OpenProof validates destination, response correlation, issuer, audience,
conditions, bearer subject confirmation and XML signatures.

## Production verification checklist

After configuring a provider:

1. Keep real secret values only in the deployment secret channel.
2. Restart only after `opp check-config` succeeds.
3. Verify `GET /auth/providers` advertises the provider.
4. Test both a new sign-in and linking the provider to an already-authenticated
   identity.
5. Verify a provider account already linked elsewhere produces a user-facing
   conflict instead of being silently moved.
6. Confirm profile metadata is optional and never used to auto-link identities
   by email.
7. Check service logs for a request/reference ID rather than exposing raw backend
   errors to the browser.

See `deploy/providers.env.example`, `deploy/openproof.env.example`, and
`docs/02-CONFIGURATION.md` for the complete variable reference.
