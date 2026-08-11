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

The default binds to loopback rather than `0.0.0.0`: exposure should be a
deliberate act.

### `[logging]`

| Key | Type | Default | Environment override | Class |
|---|---|---|---|---|
| `level` | `trace` \| `debug` \| `info` \| `warn`(`warning`) \| `error` \| `critical`(`fatal`) | `info` | `OPENPROOF_LOGGING_LEVEL` | Private |
| `console` | boolean | `true` | `OPENPROOF_LOGGING_CONSOLE` | Private |

Level names parse case-insensitively. An unrecognized level is an error, not a
fallback to `info`.

Booleans accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`.

### `[security]`

| Key | Type | Default | Class |
|---|---|---|---|
| `token_signing_key` | secret reference | unset | Secret |

Required by `opp server`, with a minimum resolved length of 32 bytes. The process
derives independent session and trusted-context keys using HMAC domain labels;
the configured master is not used directly as either operational key.

### `[gateway]`

| Key | Type | Default | Class |
|---|---|---|---|
| `enabled` | boolean | `false` | Public |
| `route_prefix` | origin path prefix | `/` | Public |
| `upstream_host` | hostname or IP | unset | Private |
| `upstream_port` | integer 1–65535 | unset | Private |
| `upstream_tls` | boolean | `true` | Private |
| `upstream_ca_file` | path | system trust store | Private |

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
`env:` or `file:` reference. Enabling authentication requires a database. The
process opens a bounded pool and applies every checksummed migration before it
opens the listener.

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
either namespace. There is no
public registration or self-service password/TOTP enrollment endpoint. Member
administration is owner-only; policy administration is not implemented.

Each `[[auth.route_policies]]` table accepts exactly these fields:

| Key | Required | Meaning |
|---|---|---|
| `path_prefix` | yes | Canonical path prefix inside `protected_route_prefix` |
| `methods` | yes | Non-empty unique subset of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS` |
| `required_roles` | yes | One to 16 unique organization roles |
| `role_match` | no | `any` (default) or `all` |
| `minimum_assurance` | no | `ial1` (default), `ial2`, `ial3`, or `ial4` |

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
| `POST /auth/mfa/verify` | Verify password and optional TOTP, then issue a session | pre-auth cookies |
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
  --config examples/openproof.auth-gateway.toml \
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

Anything else — including a plain literal — is rejected with
`INVALID_ARGUMENT`. Rejecting literals is the point: a configuration file is
routinely committed, copied into an image, attached to a ticket and printed
during debugging, and a scheme that merely *discourages* inline secrets
eventually gets one anyway.

The rejection message deliberately does not echo the offending text. If an
operator did inline a credential, quoting it back would copy it straight into
the logs.

An `env:` reference to an unset variable fails with `FAILED_PRECONDITION`; a
`file:` reference to a missing file fails with `NOT_FOUND`. Neither is treated
as "no secret configured".

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

[security]
token_signing_key = "env:OPENPROOF_TOKEN_SIGNING_KEY"

[gateway]
enabled = true
route_prefix = "/api"
upstream_host = "api.internal.example"
upstream_port = 443
upstream_tls = true

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
export OPENPROOF_DATABASE_URL="postgresql://openproof@127.0.0.1/openproof"
opp server --config openproof.toml
```

---

## Startup behaviour and exit codes

`opp server` validates configuration before opening a socket and fails closed.
The built-in listener accepts only loopback addresses because it is plaintext;
TLS must terminate in a trusted local proxy. Outbound TLS verifies the peer,
hostname and SNI. SIGINT and SIGTERM stop the listener cleanly.

`opp bootstrap-admin` does not open a listener. It requires `[auth].enabled`, a
database, a master key, a configuration file and all non-secret bootstrap
arguments. Repeating it returns exit code `2` without printing a new TOTP seed.

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
{"timestamp":"2026-08-05T00:47:47.082Z","level":"info","message":"openproof server starting","fields":{"version":"0.1.0","bind_address":"127.0.0.1","port":8443,"log_level":"info","registered_providers":0,"token_signing_key_configured":false}}
```

Note `token_signing_key_configured` records *whether* a key is present, never
the key. That is the general pattern for logging anything secret-adjacent.

Caller-supplied fields are nested under `fields` so that they can never shadow
an envelope key such as `level` or `timestamp`.
