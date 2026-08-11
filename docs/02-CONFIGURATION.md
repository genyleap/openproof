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

Optional in Phase 1; required once tokens are issued in Phase 3.

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
```

```bash
export OPENPROOF_TOKEN_SIGNING_KEY="$(openssl rand -base64 32)"
opp --config openproof.toml
```

---

## Startup behaviour and exit codes

`opp` validates configuration before doing anything else and fails closed.

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
