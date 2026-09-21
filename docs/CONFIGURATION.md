# Configuration Reference

Configuration is typed and total: `PlatformConfig` either loads fully valid or
returns an error. There is no partially-initialized configuration, and no silent
default is substituted for a malformed value — a misread security setting is
indistinguishable from a deliberately weakened one.

The schema is closed. A known key with the wrong TOML type, an unknown setting,
an unknown top-level section, or a section represented by a scalar is rejected.
Defaults apply only when a known setting is absent; they never replace a value
that was present but malformed.

Precedence, lowest to highest:

```
built-in defaults  <  TOML file  <  environment variables
```

Environment variables win so that a deployment can change a setting without
rebuilding the image it ships in.

---

## Classification

Every value carries one of four classifications (`ConfigClassification`):

| Classification | Meaning |
|---|---|
| `Public` | Safe to expose, including to unauthenticated clients |
| `Private` | Operational detail; operators only |
| `Secret` | Credential material; never logged, never returned |
| `Runtime` | Derived at startup; not written by an operator |

`Secret` values are represented as `openproof::foundation::Secret<std::string>`, which
has no formatter and no implicit conversion — so the classification is enforced
by the type system rather than by reviewer discipline.

---

## Settings

### `[server]`

| Key | Type | Default | Environment override | Class |
|---|---|---|---|---|
| `bind_address` | string | `127.0.0.1` | `OPENPROOF_SERVER_BIND_ADDRESS` | Public |
| `port` | integer 1–65535 | `8443` | `OPENPROOF_SERVER_PORT` | Public |
| `trust_proxy_client_ip` | boolean | `false` | `OPENPROOF_SERVER_TRUST_PROXY_CLIENT_IP` | Private |

The default binds to loopback rather than `0.0.0.0`: exposure should be a
deliberate act.

When `trust_proxy_client_ip=true`, the listener must remain on `127.0.0.1` or
`::1`. Every request must contain exactly one syntactically valid IP address in
`X-Forwarded-For`; missing values, proxy chains and malformed addresses are
rejected. The header is consumed and removed before routing. Enable this only
when the reverse proxy is the exclusive ingress and overwrites—not appends to—
the client-provided header. This preserves per-client rate limiting behind TLS.

### `[logging]`

| Key | Type | Default | Environment override | Class |
|---|---|---|---|---|
| `level` | `trace` \| `debug` \| `info` \| `warn`(`warning`) \| `error` \| `critical`(`fatal`) | `info` | `OPENPROOF_LOGGING_LEVEL` | Private |
| `console` | boolean | `true` | `OPENPROOF_LOGGING_CONSOLE` | Private |

Level names parse case-insensitively. An unrecognized level is an error, not a
fallback to `info`.

Booleans accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`.

### `[operations]`

| Key | Type | Default | Class |
|---|---|---|---|
| `metrics_enabled` | boolean | `false` | Private |
| `metrics_bearer_token` | secret reference resolving to at least 32 bytes | unset | Secret |
| `metrics_maximum_series` | integer 128–10,000 | `512` | Private |

When enabled, `GET /metrics` exposes Prometheus text only after an exact
`Authorization: Bearer ...` match using constant-time comparison. `HEAD
/metrics` performs the same authentication without returning a body. Enabling
the endpoint without a sufficiently strong token fails configuration loading;
unknown keys, wrong types and an out-of-range series ceiling also fail closed.

The built-in HTTP series use only the finite `method` and `status_class` labels.
They are held in a fixed-size atomic matrix and therefore cannot grow with
traffic; `metrics_maximum_series` bounds additional registry series.
Raw paths, query strings, tenant/user/client identifiers, IP addresses and
credentials are never labels. Keep the endpoint on the loopback/private
management plane: the shipped public Nginx configuration returns `404` for
`/metrics` even when application metrics are enabled.

### `[security]`

| Key | Type | Default | Class |
|---|---|---|---|
| `token_signing_key` | secret reference | unset | Secret |
| `master_key_version` | integer 1–2147483647 | `1` | Private |
| `credential_encryption_key` | secret reference resolving to exactly 32 bytes | derived legacy key | Secret |
| `credential_encryption_key_version` | integer 1–2147483647 | `1` | Private |
| `password_pepper` | secret reference resolving to at least 32 bytes | derived legacy key | Secret |
| `recovery_code_pepper` | secret reference resolving to at least 32 bytes | derived legacy key | Secret |
| `audit_chain_key` | secret reference resolving to at least 32 bytes | derived legacy key | Secret |
| `oauth_client_secret_key` | secret reference resolving to at least 32 bytes | derived legacy key | Secret |

Required by `opp server`, with a minimum resolved length of 32 bytes. The process
derives independent session and trusted-context keys using HMAC domain labels;
the configured master is not used directly as either operational key.

`credential_encryption_key` is the versioned AES-256-GCM envelope key for
persisted TOTP seeds. New deployments should configure it explicitly. When it
is absent at version `1`, OpenProof derives the legacy TOTP key from
`token_signing_key` so existing databases remain readable. Any version other
than `1` requires an explicit key. A key file may end with one line ending,
which the secret-reference loader strips; `openssl rand -base64 24` therefore
produces exactly 32 key bytes after loading.

The four additional dedicated keys protect long-lived one-way state: password
hashes, recovery-code digests, the append-only audit chain and confidential
OAuth client-secret digests. Version-1 deployments may omit them for backward
compatibility, in which case domain-separated values are derived from
`token_signing_key`. New deployments should configure all four plus the TOTP
key immediately. A `master_key_version` greater than `1` fails configuration
validation unless every persistent key is explicit; this prevents an operator
from silently making dormant passwords or client secrets unverifiable during a
master cutover.

### `[gateway]`

| Key | Type | Default | Class |
|---|---|---|---|
| `enabled` | boolean | `false` | Public |
| `route_prefix` | origin path prefix | `/` | Public |
| `upstream_host` | hostname or IP | unset | Private |
| `upstream_port` | integer 1–65535 | unset | Private |
| `upstream_tls` | boolean | `true` | Private |
| `upstream_ca_file` | path | system trust store | Private |
| `rate_limit_capacity` | integer 1–1000000 | `1000` | Private |
| `rate_limit_refill_per_second` | integer 1–1000000 | `100` | Private |
| `rate_limit_maximum_keys` | integer 1–1000000 | `100000` | Private |

When enabled, host and port are mandatory. A CA file is rejected for a plaintext
upstream. Route prefixes must be canonical segment prefixes: no query, fragment,
control character, `//` prefix or trailing slash (except `/`).

### `[database]`

| Key | Type | Default | Environment override | Class |
|---|---|---|---|---|
| `connection_string` | secret reference | unset | `OPENPROOF_DATABASE_URL` | Secret |
| `pool_size` | integer 1–256 | `8` | — | Private |
| `migration_directory` | path | `migrations` | — | Private |

`OPENPROOF_DATABASE_URL` is accepted directly because process environments are
already secret-bearing deployment channels; the TOML value must still use an
`env:`, `file:` or `hexfile:` reference. Enabling authentication requires a database. The
process opens a bounded pool and applies every checksummed migration before it
opens the listener.

### `[account]`

The consumer account lifecycle is disabled by default. When enabled it requires
`[auth].enabled = true`, PostgreSQL, and an authenticated verification-delivery
webhook. Verification secrets are persisted only as keyed digests and are sent
to the configured delivery service over the operator-selected TLS connection.

| Key | Type | Default | Class |
|---|---|---|---|
| `enabled` | boolean | `false` | Public |
| `phone_provider_id` | non-empty string | `phone` | Private |
| `delivery_host` | hostname/IP | unset | Private |
| `delivery_port` | integer 1–65535 | unset | Private |
| `delivery_tls` | boolean | `true` | Private |
| `delivery_path` | origin path | `/v1/openproof/verification` | Private |
| `delivery_ca_file` | path | system trust store | Private |
| `delivery_authorization` | secret reference | unset | Secret |

The webhook receives the verification identifier, delivery kind, destination and
one-time secret needed to construct the user-facing email/SMS action. Non-2xx
responses fail the request; the server does not silently report successful
delivery. Public/self-service routes include signup and email verification,
forgot/reset password, authenticated profile maintenance, verified email change,
and phone verification.

### `[auth]`

| Key | Type | Default | Class |
|---|---|---|---|
| `enabled` | boolean | `false` | Public |
| `provider_id` | non-empty string | `local` | Private |
| `organization_id` | non-empty string when enabled | unset | Private |
| `protected_route_prefix` | canonical boundary containing every policy path | `/` | Public |
| `route_policies` | array of closed route-policy tables | required when enabled | Private |

When enabled, the configured organization must already exist and be active.
Only method/path pairs declared by `route_policies` exist in the protected
router; an undeclared pair returns `404` and cannot fall through to a broader
allow. Every declared route requires a valid session, active identity,
organization and membership. The auth plane owns `/auth` and `/auth/*`, while
the administration plane owns `/admin` and `/admin/*`; policies cannot claim
either namespace. Public account enrollment and recovery are exposed only when `[account].enabled`
is true; administrative membership changes remain owner-only. Gateway route policy
administration is intentionally static process configuration.

Each `[[auth.route_policies]]` table accepts exactly these fields:

| Key | Required | Meaning |
|---|---|---|
| `path_prefix` | yes | Canonical path prefix inside `protected_route_prefix` |
| `methods` | yes | Non-empty unique subset of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS` |
| `required_roles` | yes | One to 16 unique organization roles |
| `role_match` | no | `any` (default) or `all` |
| `minimum_assurance` | no | `ial1` (default), `ial2`, `ial3`, or `ial4` |
| `required_scope` | no | OAuth scope required for delegated bearer access |
| `required_audience` | no | Exact OAuth resource/audience required for delegated bearer access |

```toml
[[auth.route_policies]]
path_prefix = "/api/reports"
methods = ["GET", "POST"]
required_roles = ["report-reader", "report-admin"]
role_match = "any"
minimum_assurance = "ial2"
```

Policies are immutable for the process lifetime and validated before the
listener opens. Empty/duplicate rules, duplicate method/path pairs, unknown
fields, unsupported methods, invalid roles and policies outside the configured
boundary fail startup. Role and assurance evaluation uses only the trusted
authorization request rebuilt from PostgreSQL. Missing/invalid authentication
returns `401`; an authenticated subject failing membership, role or assurance
checks returns `403`. Every rejected authenticated decision is atomically added
to the HMAC audit chain and security-event outbox.

| Method and path | Purpose | Authentication |
|---|---|---|
| `POST /auth/login` | Begin a single-use, client-bound local login | none |
| `POST /auth/mfa/verify` | Verify password plus optional TOTP or one-time recovery code, then issue a session | pre-auth cookies |
| `POST /auth/session/rotate` | Atomically replace the current session | session cookie or Bearer |
| `POST /auth/logout` | Revoke the current session | session cookie or Bearer |
| `POST /auth/logout-all` | Revoke every session for the identity | session cookie or Bearer |
| `POST /auth/recovery-codes` | Replace and return ten one-time codes | IAL2 session |

Requests use strict JSON with a 16 KiB limit and reject unknown fields. Cookies
are `Secure`, `HttpOnly`, and `SameSite=Strict`; auth responses are `no-store`.
Supplying both a Bearer and session cookie is rejected as ambiguous. A front
proxy must preserve `Set-Cookie` and the client address used for rate limiting.

## Owner administration API

The administration plane reserves `/admin` and `/admin/*`. It manages local
members in the configured organization:

| Method and path | Purpose | Authentication |
|---|---|---|
| `POST /admin/local-members` | Atomically create a local identity, link, active membership, roles, password and TOTP | Active IAL2 session whose identity has the active `owner` role |
| `PUT /admin/local-members/roles` | Replace the member's complete role set | Active IAL2 owner |
| `POST /admin/local-members/suspend` | Suspend an active membership | Active IAL2 owner |
| `POST /admin/local-members/reinstate` | Reinstate a suspended membership | Active IAL2 owner |
| `POST /admin/local-members/remove` | Permanently remove a membership and its roles | Active IAL2 owner |
| `POST /admin/local-members/credentials/reset` | Rotate the local password and TOTP seed and delete recovery codes | Active IAL2 owner |

The owner check is performed from authoritative PostgreSQL state inside the
same serializable transaction as the mutation. The HTTP layer deliberately does
not trust a role carried in the session. Requests are strict JSON, limited to
16 KiB, and accept exactly these fields:

```json
{
  "identity_id": "member-42",
  "subject": "member@example.test",
  "roles": ["member"]
}
```

`identity_id` is the canonical internal identifier and must differ from the
provider `subject`. Roles must be a non-empty set of at most 16 unique values.
The client cannot choose either credential. After a successful atomic commit,
the server returns `201 Created`:

```json
{
  "identity_id": "member-42",
  "initial_password": "generated-base64url-secret",
  "totp_secret_base32": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
}
```

The 256-bit password and 160-bit TOTP seed are generated with the platform
CSPRNG, returned only in this response, and never written to audit or outbox
payloads. The response is `no-store`; the administrator must transfer the
credentials over the trusted TLS-protected channel and the recipient should
enroll the TOTP immediately. Any validation, authorization, uniqueness,
credential, audit or outbox failure rolls back the entire operation. A denied
or failed response contains no generated secret.

Role replacement accepts exactly `identity_id` and a non-empty unique `roles`
array. Lifecycle and credential-reset requests accept exactly `identity_id`.
Role and lifecycle mutations return `204 No Content`; credential reset returns
`200 OK` with the same one-time `initial_password` and `totp_secret_base32`
fields used during creation. Reset is allowed only for an active membership.

Every administrative mutation is serialized and committed atomically with its
HMAC-chained audit record and outbox event. The actor is re-authorized from
authoritative PostgreSQL state inside that transaction, and all active sessions
of the target member are revoked before commit. Removing a membership is
terminal and clears its roles; suspension retains roles but makes them
ineffective. The final active owner cannot lose the `owner` role, be suspended,
or be removed. Credential reset replaces the password and encrypted TOTP seed,
resets TOTP replay state, deletes every recovery code, and returns new secrets
only after commit. A removed member's canonical identity and local credential
record remain as durable identity-layer data, but no longer authorize access to
the organization.

## Initial owner bootstrap

`bootstrap-admin` is the only supported way to initialize a fresh deployment.
It is an offline operator ceremony, not an HTTP registration endpoint:

```bash
export OPENPROOF_BOOTSTRAP_PASSWORD="use-a-long-unique-password"

opp bootstrap-admin \
  --config examples/openproof.toml \
  --organization-name "Example Organization" \
  --identity-id "initial-owner" \
  --subject "owner@example.test"
```

The organization id and local provider id come from `[auth]`. The canonical
identity id must differ from the external login subject. Passwords must contain
16–1024 bytes and are accepted only through `OPENPROOF_BOOTSTRAP_PASSWORD`; no
secret-valued command-line option exists.

The command applies migrations, generates a 160-bit TOTP seed, and atomically
creates the organization, human identity, explicitly verified provider link,
active `owner` membership, scrypt password verifier, AES-256-GCM-encrypted TOTP
credential, HMAC-chained audit record and security-event outbox entry. A
serializable transaction plus a deployment-wide advisory lock rejects every
attempt after the first organization exists. The Base32 seed is printed only
after commit and only once; capture it securely, enroll it, then unset the
password environment variable.

---

## Secret references

**A secret is never written literally in a configuration file.** The file holds a
reference, and the loader dereferences it:

| Form | Resolves to |
|---|---|
| `env:NAME` | The value of environment variable `NAME` |
| `file:/path` | The contents of `/path`, with one trailing line ending stripped |
| `hexfile:/path` | Lower/uppercase hexadecimal decoded to exact binary bytes; one trailing line ending is allowed |

Anything else — including a plain literal — is rejected with
`INVALID_ARGUMENT`. Rejecting literals is the point: a configuration file is
routinely committed, copied into an image, attached to a ticket and printed
during debugging, and a scheme that merely *discourages* inline secrets
eventually gets one anyway.

The rejection message deliberately does not echo the offending text. If an
operator did inline a credential, quoting it back would copy it straight into
the logs.

An `env:` reference to an unset variable fails with `FAILED_PRECONDITION`; a
`file:` or `hexfile:` reference to a missing file fails with `NOT_FOUND`.
Malformed or odd-length hexadecimal is rejected. `hexfile:` is intended for
binary-safe secret-store files and the legacy persistent-key materialization
ceremony; it never treats encoded bytes as their printable hex text. None of
these failures is treated as "no secret configured".

---

## Example

```toml
# openproof.toml — safe to commit. Contains references, never credentials.

[server]
bind_address = "127.0.0.1"
port = 8443

[logging]
level = "info"
console = true

[operations]
metrics_enabled = true
metrics_bearer_token = "file:/run/openproof/secrets/metrics-bearer.token"
metrics_maximum_series = 512

[security]
token_signing_key = "env:OPENPROOF_TOKEN_SIGNING_KEY"
master_key_version = 1
credential_encryption_key = "env:OPENPROOF_CREDENTIAL_ENCRYPTION_KEY"
credential_encryption_key_version = 1
password_pepper = "file:/run/openproof/secrets/password-pepper.key"
recovery_code_pepper = "file:/run/openproof/secrets/recovery-code-pepper.key"
audit_chain_key = "file:/run/openproof/secrets/audit-chain.key"
oauth_client_secret_key = "file:/run/openproof/secrets/oauth-client-secret.key"

[gateway]
enabled = true
route_prefix = "/api"
upstream_host = "api.internal.example"
upstream_port = 443
upstream_tls = true
rate_limit_capacity = 1000
rate_limit_refill_per_second = 100
rate_limit_maximum_keys = 100000

[database]
connection_string = "env:OPENPROOF_DATABASE_URL"
pool_size = 8
migration_directory = "migrations"

[auth]
enabled = true
provider_id = "local"
organization_id = "tenant-id"
protected_route_prefix = "/api"

[[auth.route_policies]]
path_prefix = "/api"
methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
required_roles = ["member", "owner"]
role_match = "any"
minimum_assurance = "ial2"
```

```bash
export OPENPROOF_TOKEN_SIGNING_KEY="$(openssl rand -base64 32)"
export OPENPROOF_CREDENTIAL_ENCRYPTION_KEY="$(openssl rand -base64 24)"
export OPENPROOF_DATABASE_URL="postgresql://openproof@127.0.0.1/openproof"
opp server --config openproof.toml
```

---

## Startup behaviour and exit codes

`opp server` validates configuration before opening a socket and fails closed.
The built-in listener accepts only loopback addresses because it is plaintext;
TLS must terminate in a trusted local proxy. Outbound TLS verifies the peer,
hostname and SNI. SIGINT and SIGTERM stop the listener cleanly.

Validate the same configuration and resolve every referenced secret without
opening a listener or connecting to PostgreSQL/upstreams:

```bash
opp check-config --config /etc/openproof/openproof.toml
```

Success prints only `OpenProof configuration is valid.`; it never prints secret
values. Use this as a deployment pre-start check after the secret-store/KMS
mount is present.

`opp bootstrap-admin` does not open a listener. It requires `[auth].enabled`, a
database, a master key, a configuration file and all non-secret bootstrap
arguments. Repeating it returns exit code `2` without printing a new TOTP seed.

`opp rekey-totp` is the offline operator command for atomically rotating the
dedicated TOTP envelope key. Its complete call sequence and rollback rules are
in [the operations runbook](OPERATIONS.md#totp-credential-key-rotation). This
command is separate from `opp rotate-master-key`.

`opp rotate-master-key` retires a multi-purpose master after verifying that all
long-lived one-way/encrypted state uses independent keys. In a serializable,
locked transaction it deletes sessions, authentication/account challenges,
incomplete passkey-registration ceremonies, authorization codes, token families,
device grants and PAR objects derived from the old master, then writes their
exact counts plus a non-secret fingerprint/version journal. Passwords, TOTP,
registered passkey credentials, recovery codes, audit records and OAuth client
secrets are deliberately preserved. See [the exact
runbook](OPERATIONS.md#master-key-rotation).

Legacy version-1 deployments must first export the exact domain-separated
durable subkeys derived from their current master into an existing empty,
owner-only directory:

```bash
opp materialize-persistent-keys \
  --config /etc/openproof/openproof.toml \
  --output-directory /run/openproof/materialized-v1 \
  --acknowledge-secret-export
```

Configure the five generated values through `hexfile:` references while keeping
`master_key_version = 1`, verify a restart and credential flows, and only then
run the master rotation ceremony. The materializer refuses mixed/already-
dedicated configurations, unsafe directories and existing output files; it
never prints the master or generated key values. These values preserve legacy
credentials but remain derivable from the old master; materialization is not a
remedy for an already compromised legacy master. See the incident distinction
in the operations runbook.

| Exit code | Meaning |
|---|---|
| `0` | Started and stopped cleanly |
| `2` | Usage error (unknown option, missing argument) |
| `3` | Configuration could not be read, parsed or validated |
| `70` | Unhandled internal error |

Startup failures are reported on stderr with the error code, plus the
operator-only detail — stderr at startup is an operator channel, not a client
response:

```
opp: The configured port is outside the range 1-65535. [INVALID_ARGUMENT]
```

A successful start emits one structured JSON record per line:

```json
{"timestamp":"2026-08-05T00:47:47.082Z","level":"info","message":"openproof server starting","fields":{"version":"1.0.0","bind_address":"127.0.0.1","port":8443,"log_level":"info","registered_providers":0,"token_signing_key_configured":false}}
```

Note `token_signing_key_configured` records *whether* a key is present, never
the key. That is the general pattern for logging anything secret-adjacent.

Caller-supplied fields are nested under `fields` so that they can never shadow
an envelope key such as `level` or `timestamp`.

---

## OpenID Connect identity-platform mode

OpenID Connect is opt-in and requires the persistent authentication deployment.
The issuer must be HTTPS in production. Plain HTTP is accepted only for an exact
loopback host to support local development.

```toml
[oidc]
enabled = true
issuer = "https://identity.example.com"
key_id = "openproof-rs256-1"
signing_key = "file:/run/secrets/openproof-oidc-private.pem"
previous_signing_keys_directory = "/run/openproof/previous-oidc-keys"
```

`signing_key` is an RSA private key in PEM format. The server derives the public
JWK and publishes it through `/.well-known/jwks.json`; private key material is
never returned by an HTTP endpoint. The optional previous-key directory may
contain up to eight regular RSA public-key files named `<kid>.pem`. Those keys
are published after the active key so relying parties can validate tokens issued
before a rotation; they are never used to sign new tokens. Symlinks, duplicate
or active key IDs and RSA keys below 2048 bits fail startup.

Environment overrides:

- `OPENPROOF_OIDC_ENABLED`
- `OPENPROOF_OIDC_ISSUER`
- `OPENPROOF_OIDC_KEY_ID`
- `OPENPROOF_OIDC_SIGNING_KEY`
- `OPENPROOF_OIDC_PREVIOUS_KEYS_DIRECTORY`
- `OPENPROOF_MTLS_FORWARDING_KEY` — optional, at least 32 bytes; authenticates request-bound client-certificate forwarding from the trusted TLS ingress for RFC 8705 sender-constrained tokens.

The environment signing-key override contains PEM text and is a secret. Prefer a
file-backed secret in production so process environment inspection does not
become a key-disclosure path.

### External federated login

Redirect-based federation is enabled per provider by configuring its client ID.
Every enabled provider also requires `OPENPROOF_FEDERATION_CALLBACK_URI`, which
must be the exact HTTPS callback registered with the upstream provider (normally
`https://identity.example.com/auth/federated/callback`). The optional
`OPENPROOF_FEDERATION_CA_FILE` pins an additional CA bundle for discovery, token
and JWKS HTTPS requests.

- Google: `OPENPROOF_GOOGLE_CLIENT_ID`, `OPENPROOF_GOOGLE_CLIENT_SECRET`; optional
  `OPENPROOF_GOOGLE_ISSUER` (default `https://accounts.google.com`).
- Apple: `OPENPROOF_APPLE_CLIENT_ID`; optional `OPENPROOF_APPLE_ISSUER` (default
  `https://appleid.apple.com`). Configure either a pre-generated
  `OPENPROOF_APPLE_CLIENT_SECRET` JWT, or let OpenProof generate a fresh Apple
  client-secret JWT for every token exchange with `OPENPROOF_APPLE_TEAM_ID`,
  `OPENPROOF_APPLE_KEY_ID`, and `OPENPROOF_APPLE_PRIVATE_KEY_FILE` pointing to the
  Apple P-256 `.p8` private key. The private-key file must be a regular, non-symlink
  file no larger than 16 KiB. OpenProof requests `response_mode=form_post` for Apple because Apple requires
  form-post authorization responses whenever the `name` or `email` scopes are
  requested; the shared federation callback accepts URL-encoded POST responses.
  On the first authorization, OpenProof relays Apple's one-time `user` payload
  only to recover the sanitized first/last name for connection presentation. The
  canonical subject and verified email continue to come only from the validated
  signed ID Token; the raw `user` email is never trusted for identity linking.
- Microsoft: `OPENPROOF_MICROSOFT_CLIENT_ID`, `OPENPROOF_MICROSOFT_CLIENT_SECRET`,
  and a required tenant-specific `OPENPROOF_MICROSOFT_ISSUER`. Multi-tenant
  `common`, `organizations`, `consumers`, and issuer templates are rejected so an
  ID Token is never accepted under an ambiguous issuer policy. OpenProof requests
  `response_mode=form_post` for Microsoft web sign-in and accepts the callback on
  the shared URL-encoded POST federation endpoint.
- GitHub: `OPENPROOF_GITHUB_CLIENT_ID`, `OPENPROOF_GITHUB_CLIENT_SECRET`. The
  provider uses Authorization Code with PKCE, requires a structurally valid HTTPS
  callback URI, revalidates the authenticated user through the GitHub REST API
  after every sign-in, and accepts an email claim only when GitHub reports the
  primary address as verified.
- X (Twitter): `OPENPROOF_X_API_KEY`, `OPENPROOF_X_API_SECRET`. The provider
  uses the three-legged OAuth 1.0a request-token / authorization / access-token
  ceremony. The successful access-token response supplies the stable X `user_id`
  and `screen_name`, which OpenProof uses as the external subject and preferred
  username. OpenProof deliberately does not call `/2/users/me` or another profile
  lookup endpoint merely to establish identity.
- LinkedIn: `OPENPROOF_LINKEDIN_CLIENT_ID`, `OPENPROOF_LINKEDIN_CLIENT_SECRET`;
  optional `OPENPROOF_LINKEDIN_ISSUER` (default
  `https://www.linkedin.com/oauth`). Enable the **Sign in with LinkedIn using
  OpenID Connect** product for the application; OpenProof requests only
  `openid profile email`.
- Telegram: `OPENPROOF_TELEGRAM_CLIENT_ID`,
  `OPENPROOF_TELEGRAM_CLIENT_SECRET`; optional `OPENPROOF_TELEGRAM_ISSUER`
  (default `https://oauth.telegram.org`). Obtain both values and register the
  exact callback through BotFather. Telegram token exchange uses
  `client_secret_basic`; OpenProof applies the RFC 6749 form encoding to the
  client ID and secret before constructing the HTTP Basic credential. Keep the
  bot's ID-token algorithm at the OpenProof-supported default `RS256`. The
  default scopes are `openid profile`; phone and bot messaging permission are
  deliberately not requested.

OIDC discovery metadata and JWKS are fetched over certificate-verified TLS. When
the upstream metadata explicitly advertises token-authentication methods, response
modes, or PKCE methods, OpenProof rejects metadata that omits the configured client
authentication method, configured response mode, or required `S256`. Providers that
legitimately omit those optional discovery fields remain compatible. The browser
flow uses Authorization Code with PKCE, state and nonce. ID Tokens are
accepted only after signature, issuer, audience, expiry, issued-at and nonce
validation. For presentation metadata, a validated ID Token `name` claim takes
precedence; when it is absent or unusable, OpenProof composes a display name from
validated `given_name` and `family_name` claims. Presentation claims are normalized
to OpenProof profile limits (`display_name` 256 characters and `preferred_username`
128 characters), and picture claims are accepted only as structurally valid HTTPS
URLs. Apple's one-time callback name is used only as the final Apple-specific fallback;
malformed callback presentation metadata is ignored rather than failing authentication. A previously unseen verified
upstream subject may create a new canonical identity only for explicitly trusted
federation providers; email claims are never used to silently link an existing
account.

An authenticated user may explicitly attach any enabled redirect provider with
`GET /account/connections/start`. This uses the same registered federation
callback URI. The target OpenProof identity is captured from the authenticated
session at start and stored only in the server-side transaction; callback query
parameters cannot choose or replace it. Connection completion does not issue a
new session. Operators should expose `GET /account/connections` and disconnect
controls only over the authenticated account UI; the final sign-in method is
protected from removal.

### WebAuthn / passkeys

Passkeys are enabled by setting `OPENPROOF_WEBAUTHN_RP_ID` and the exact HTTPS
`OPENPROOF_WEBAUTHN_ORIGIN`. The RP ID must equal the origin host or be a domain-label
suffix of it; malformed origins and unrelated RP IDs are rejected at startup. An
explicit default HTTPS port (`:443`) is canonicalized away so server-side origin
comparison matches browser origin serialization. `OPENPROOF_WEBAUTHN_RP_NAME` is optional and
defaults to `OpenProof`. Registration is authenticated self-service under
`/account/passkeys`; assertion login is exposed under `/auth/passkey/*`.

The built-in relying party requires discoverable credentials, user verification,
privacy-preserving `none` attestation and ES256/P-256 credentials. Registration
validates the challenge, origin, RP-ID hash, authenticator flags and COSE public
key. Assertion login validates the same browser/RP bindings, verifies the
authenticator signature and performs an atomic signature-counter advance when
the authenticator supplies a non-zero counter. Passkeys are treated as a
phishing-resistant possession factor; biometric unlock is not promoted to a
server-side inherence claim.

### Wallet and Farcaster login
Relay-supplied display name, username and profile-picture metadata are presentation-only; malformed values are discarded before persistence.

Web3 browser bindings are `OPENPROOF_WEB3_DOMAIN` and the exact HTTPS
`OPENPROOF_WEB3_URI`; `OPENPROOF_WEB3_CA_FILE` optionally supplies an
additional CA bundle.

- Wallet/SIWE: enable with `OPENPROOF_ETHEREUM_WALLET_ENABLED=true`. The wallet
  supplies its active positive EVM chain ID for each ceremony; EOA signatures
  are recovered locally on secp256k1 and therefore do not require an RPC or a
  fixed chain. Smart-account verification (ERC-1271/ERC-6492) uses the optional
  server-side map `OPENPROOF_ETHEREUM_RPC_ENDPOINTS`, formatted as
  `1=https://...;8453=https://...;42161=https://...;5042=https://rpc.mainnet.arc.io;4663=https://rpc.mainnet.chain.robinhood.com`. Only the matching
  chain-specific endpoint is consulted. The legacy
  `OPENPROOF_ETHEREUM_RPC_ENDPOINT` plus `OPENPROOF_ETHEREUM_CHAIN_ID`
  pair remains supported as one smart-wallet RPC mapping. RPC endpoints must be
  structurally valid HTTPS URLs; invalid authorities and ports are rejected at
  startup. Query-only RPC URLs are sent with a canonical `/?...` request target,
  and non-default HTTPS ports are preserved in the HTTP `Host` header.
  `OPENPROOF_ETHEREUM_RPC_AUTHORIZATION` is applied to configured wallet RPC
  calls when required.
- Farcaster: `OPENPROOF_FARCASTER_RPC_ENDPOINT`,
  optional `OPENPROOF_FARCASTER_ID_REGISTRY` and
  `OPENPROOF_FARCASTER_KEY_REGISTRY` overrides, and optional
  `OPENPROOF_FARCASTER_RPC_AUTHORIZATION`. SIWF is fixed to Optimism mainnet
  chain ID `10`; the default registries are the canonical Farcaster IdRegistry
  (`0x00000000fc6c5f01fc30151999387bb99a9f489b`) and KeyRegistry
  (`0x00000000fc1237824fb747abde0ff18990e59b7e`). The signed FIP-11 proof binds
  statement `Farcaster Auth` and resource `farcaster://fid/<fid>`. OpenProof
  independently rechecks custody or an active type-2 auth address after
  signature verification. Setting `OPENPROOF_FARCASTER_CHAIN_ID` to a value
  other than `10` is rejected. The Optimism RPC endpoint is subject to the same
  strict HTTPS authority and port validation as wallet smart-account RPCs.

Web3 authentication is classified as a possession factor but is not promoted to
WebAuthn-style phishing resistance.

WalletConnect/Reown is an optional client-side transport, not an OpenProof server
credential or verification dependency. For the recommended hybrid browser setup,
Project ID/domain allowlisting, EIP-6963 discovery and the WalletConnect-to-SIWE flow,
see [WALLETCONNECT.md](WALLETCONNECT.md).

### LDAP and SAML federation

LDAP is enabled by `OPENPROOF_LDAP_URI` and requires
`OPENPROOF_LDAP_BASE_DN`. The URI must be one structurally valid `ldaps://host[:port]`
endpoint (URI lists, plaintext fallbacks, paths and malformed authorities are rejected),
and the base DN must parse as an LDAPv3 distinguished name. Certificate validation is
mandatory. Optional settings are `OPENPROOF_LDAP_CA_FILE`, service-bind
`OPENPROOF_LDAP_BIND_DN` / `OPENPROOF_LDAP_BIND_PASSWORD`, and attribute names:
`OPENPROOF_LDAP_USERNAME_ATTRIBUTE` (`uid`),
`OPENPROOF_LDAP_SUBJECT_ATTRIBUTE` (`entryUUID`),
`OPENPROOF_LDAP_DISPLAY_NAME_ATTRIBUTE` (`cn`) and
`OPENPROOF_LDAP_EMAIL_ATTRIBUTE` (`mail`). Authentication searches for exactly
one directory entry and then performs an LDAP bind as that user. LDAP and SAML display-name attributes are presentation-only, may contain spaces/UTF-8, and are normalized to the 256-character OpenProof profile limit.

SAML is enabled by `OPENPROOF_SAML_IDP_SSO_URL` and additionally requires
`OPENPROOF_SAML_SP_ENTITY_ID`, `OPENPROOF_SAML_IDP_ENTITY_ID`,
`OPENPROOF_SAML_IDP_CERTIFICATE_PEM`, and the exact
`OPENPROOF_FEDERATION_CALLBACK_URI` used as ACS. The IdP SSO and ACS endpoints
must be well-formed HTTPS URLs with a non-empty authority and valid optional port;
userinfo, fragments, backslashes, spaces/control characters, and ambiguous
authorities are rejected before any trust material is used. The adapter emits a
SAML 2.0 AuthnRequest and validates destination, `InResponseTo`, issuer, status,
audience, conditions, bearer subject confirmation and NameID. XML signatures are
pinned to the configured IdP certificate and constrained to the supported
RSA-SHA256 / SHA-256 / exclusive-canonicalization profile.

### SCIM provisioning

Set `OPENPROOF_SCIM_BEARER_TOKEN` to an operator-generated secret of at least 32
bytes to enable `/scim/v2/*`. Users provision canonical identities, profiles and
organization memberships; Groups and membership metadata are durable in
PostgreSQL. The service exposes Users/Groups CRUD and PATCH, equality filtering,
`ServiceProviderConfig`, `ResourceTypes` and `Schemas`. Bulk provisioning is not
advertised.

### Evidence verification and Trust

The authenticated `/evidence/*` surface supports one-time proof challenges,
verification, evidence listing and current trust assessment. Verifiers are
fail-closed and enabled only when their trust anchors are configured:

- Signed attestation JWT: `OPENPROOF_EVIDENCE_JWT_PUBLIC_KEY_PEM`,
  `OPENPROOF_EVIDENCE_JWT_ISSUER`, and `OPENPROOF_EVIDENCE_JWT_AUDIENCE`. The
  verifier requires RS256 and binds `sub` and `nonce` to the authenticated
  canonical identity and one-time challenge.
- X.509 proof: `OPENPROOF_EVIDENCE_X509_CA_FILE`; optional
  `OPENPROOF_EVIDENCE_X509_CRL_FILE`. The certificate chain must validate to the
  configured CA, a URI SAN must bind the OpenProof identity, and the subject must
  prove possession of the leaf private key by signing the challenge transcript.

### SCIM, evidence, and integration secrets

Environment-only integration values above are operational secrets/configuration
that are not projected into public discovery documents. Store authorization
tokens, provider client secrets and private trust material using the deployment's
secret manager rather than source-controlled shell files.

When `[oidc].enabled = true`, OpenProof reserves `/login`, `/oauth/*` and
`/.well-known/*`; gateway upstream routes cannot shadow these protocol endpoints.

A protected gateway route can additionally require an OAuth scope:

```toml
[[auth.route_policies]]
path_prefix = "/api/orders"
methods = ["GET", "POST"]
required_roles = ["member", "owner"]
role_match = "any"
minimum_assurance = "ial1"
required_scope = "orders"
```

The role/assurance checks remain authoritative for platform sessions. Delegated
OAuth access additionally carries a verified client ID and scopes from the token
service; caller-provided scope headers are removed at the gateway boundary.

See `examples/openproof.toml` for a complete deployment sample.
