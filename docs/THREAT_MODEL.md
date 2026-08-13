# OpenProof Threat Model

Status: living baseline for the 1.0 identity provider, OAuth/OIDC authorization
server, session/token service, gateway, PostgreSQL, evidence/trust foundation and
observability surface. Review it whenever a trust boundary or credential type
changes.

## Assets

- canonical identity, identity profile and organization membership;
- password verifiers, TOTP seeds and recovery-code digests;
- authentication transactions and platform session bearer tokens;
- application/client registrations, redirect policy and client-secret digests;
- authorization-code, access-token and refresh-token digests/families;
- OIDC operator signing private key and public JWKS;
- verified evidence, trust-policy inputs and derived assessments;
- policy decisions and the trusted context delivered upstream;
- master secret material, audit-chain integrity and security telemetry.

## Trust boundaries

1. Internet client → local TLS terminator → loopback Beast listener.
2. Browser/native relying party → OAuth/OIDC authorization server.
3. OAuth token service → relying product/API gateway.
4. Gateway → internal upstream, normally over verified TLS.
5. Provider response → trusted authentication broker.
6. Evidence verifier → verified evidence repository.
7. Process → PostgreSQL through the bounded connection pool.
8. Operator configuration/secret store → composition root.
9. Application events → audit, metric and trace sinks.

The client, every incoming header, redirect, provider assertion, evidence input
and database row is untrusted until validated at its boundary. Authentication,
proof, trust and authorization remain separate decisions.

## Threats and controls

| Threat | Primary controls | Residual risk / operator duty |
|---|---|---|
| Credential stuffing and account enumeration | Pepper+scrypt, dummy verification, normalized failures, IP+identity token buckets | Distributed low-rate attacks require fleet-wide aggregation and alerting |
| Session database theft | 256-bit opaque bearers; only keyed digests persist; absolute+idle expiry; rotation/revocation | A stolen live client-side bearer remains usable until expiry/revocation |
| Authentication replay/substitution | Hashed single-use nonce, binding digest, challenge id, deadline, atomic PostgreSQL consume | Correct binding material must come from the TLS-facing adapter |
| TOTP/recovery replay | Encrypted TOTP seed with atomic last-step update; atomic recovery `DELETE ... RETURNING` | TOTP is not phishing-resistant; add WebAuthn for stronger deployments |
| OAuth authorization-code interception | Mandatory PKCE S256, code/client/redirect binding, short code lifetime, atomic single use | Compromised endpoint/client device can still expose its own verifier/code |
| OAuth redirect confusion/open redirect | Registration validates URI authority; exact runtime redirect match; native HTTP allowed only on explicit loopback host+numeric port | Relying applications must not add an open redirect behind their registered callback |
| OAuth client impersonation | Confidential secrets are generated once, stored only as keyed digests and can rotate/revoke independently; public clients never receive a secret | Secret distribution/storage for confidential clients remains an operator/client duty |
| Refresh-token theft/replay | Opaque token, keyed digest storage, rotation on use, token-family replay revocation, client binding | Theft before legitimate use can still win the race; device-bound/token-bound extensions are future hardening |
| Access-token disclosure | Short default lifetime, opaque token, no durable plaintext, per-client scopes, revocation/introspection | Bearer semantics mean a stolen live token can be replayed until inactive |
| OIDC issuer/redirect authority confusion | Strict issuer validation; HTTPS except loopback development; no userinfo/query/fragment/control forms | Public DNS/TLS integrity remains external to the process |
| OIDC signing-key theft | Private PEM enters only through secret configuration; `SecretString`; JWKS exposes public key only; RS256 minimum key checks | Secret store, file permissions and key rotation procedure are operator duties |
| Browser credential confusion/CSRF | Session and bearer sources are unambiguous; login CSRF token; Secure/HttpOnly/SameSite cookies; protocol routes reserved | Front proxy must preserve host/origin/TLS invariants |
| Header spoofing | Strip all `x-openproof-*`; rebuild from trusted platform/delegated context; HMAC/freshness on upstream context | Upstream must verify the signature and protect the shared key |
| Request smuggling/parser abuse | Origin-form only; duplicate singleton and CL+TE rejection; bounded parser/body/header/deadline/connection limits | HTTP/2/3 termination behaviour belongs to the front proxy and must be tested there |
| SSRF through routing | Upstream host/port are closed-schema operator configuration, never request input | Configuration compromise can redirect traffic |
| Upstream MITM | TLS peer, hostname and SNI verification; optional private CA | Plain upstream mode should be limited to an equally trusted local channel |
| Authorization bypass | Closed exact method/path policies; RBAC, assurance and optional delegated OAuth scope; every non-Allow fails closed | Trust/risk is intentionally not an implicit authorization grant; deployment policy decides whether to consume it |
| Cross-tenant access | Organization required by identity/application/member operations and owner checks | Database superusers can bypass application isolation; separate DB roles are recommended |
| Database race/replay | Conditional UPDATE/DELETE, row locks, serializable admin mutations and transactional migrations | HA semantics depend on PostgreSQL consistency/failover configuration |
| Evidence poisoning | Provider-neutral verifier SPI; evidence is accepted only from a registered verifier and bound to canonical identity/provider; validation and revocation/expiry | Each concrete provider adapter needs its own provenance, replay and freshness review |
| Stale trust score | Trust is derived per request from currently active evidence and one clock snapshot; no permanent trust-score row | Policy weights and risk-source quality remain operator/application responsibilities |
| Log/metric injection and secret leakage | Secret types are non-formatable; JSON escaping; label validation/cardinality cap | Operator-added sinks must preserve the same contracts |
| Audit tampering | HMAC-linked sequence chain; sensitive admin/authorization mutations share transaction/outbox boundaries | Off-host checkpoints and external retention remain deployment work |
| Bootstrap privilege creation | Offline-only command, environment-only password, generated TOTP, fixed owner role, serializable transaction and one-time refusal | Operator shell and master-key access are trusted during bootstrap |
| Administrative privilege escalation | IAL2 boundary; active owner re-read in the mutation transaction; final active owner protection; target session revocation | An authorized owner can deliberately grant another owner role |
| Denial of service | Size/time/connection limits, scrypt resource ceilings, per-process rate limits, circuit breaker | Front proxy should add fleet-wide throttling and abuse controls |

## Deliberate constraints

- The built-in listener is HTTP/1.1 plaintext and `opp server` refuses
  non-loopback binds. TLS terminates in a trusted local proxy/sidecar.
- OpenProof is an **OIDC Provider / OAuth Authorization Server** in 1.0. Generic
  upstream OIDC login providers (Google/Microsoft/etc.) and WebAuthn/passkeys are
  separate provider-SPI integrations and are not represented as implemented.
- The concrete local authentication provider supports password and
  password+TOTP. Central identities are bootstrap/admin provisioned by default;
  public self-service signup is intentionally not opened without a deployment-
  specific anti-abuse and verification policy.
- OAuth 1.0 supports Authorization Code + PKCE and refresh tokens. It does not
  enable implicit, resource-owner-password or client-credentials grants.
- Application and client lifecycle management exists only behind an IAL2 active
  owner check. Confidential secrets are returned once after durable success.
- Evidence/Trust is provider-neutral. Concrete GitHub, Farcaster, ENS, wallet or
  enterprise verifiers require separate real API/protocol adapters; fake network
  adapters are not included.
- Trust assessment does not automatically grant access. A product/policy must
  explicitly decide how evidence/trust/risk affects authorization.
- PostgreSQL stores durable identities, sessions, credentials, applications,
  OAuth state/tokens, profiles and evidence. Raw bearer/authorization/client
  secrets are not stored durably.

## Verification gates

- Debug and RelWithDebInfo builds treat warnings as errors and enforce C++26
  contracts for internal invariants.
- `gcc-asan` enables AddressSanitizer and UndefinedBehaviorSanitizer.
- Boundary, concurrency, gateway and PostgreSQL integration tests are part of
  the C++ suite; database tests require an enabled test PostgreSQL instance.
- JavaScript SDK smoke tests and Kotlin compile checks are separately runnable.
- Target-toolchain release status is recorded in
  [RELEASE_VERIFICATION.md](RELEASE_VERIFICATION.md).
- Security invariants and their proving tests are indexed in
  [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md).
