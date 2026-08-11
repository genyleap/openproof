# OpenProof Threat Model

Status: living baseline for the implemented authentication, session, gateway,
PostgreSQL and observability surface. Review it whenever a trust boundary or
credential type changes.

## Assets

- canonical identity and organization membership;
- password verifiers, TOTP seeds and recovery-code digests;
- authentication transactions and session bearer tokens;
- policy decisions and the trusted context delivered upstream;
- master signing/pepper keys, audit-chain integrity and security telemetry.

## Trust boundaries

1. Internet client → local TLS terminator → loopback Beast listener.
2. Gateway → internal upstream, normally over verified TLS.
3. Provider response → trusted authentication broker.
4. Process → PostgreSQL through the bounded connection pool.
5. Operator configuration/secret store → composition root.
6. Application events → audit, metric and trace sinks.

The client, every incoming header, provider assertion and database row is
untrusted until validated at its boundary. A successful authentication is not
an authorization decision.

## Threats and controls

| Threat | Primary controls | Residual risk / operator duty |
|---|---|---|
| Credential stuffing and account enumeration | Pepper+scrypt, dummy verification for unknown local accounts, normalized failures, IP+identity token buckets | Distributed low-rate attacks require external aggregation and alerting |
| Session database theft | 256-bit opaque bearers; only keyed digests persist; absolute+idle expiry; rotation/revocation | A stolen live bearer at the client remains usable until expiry/revocation |
| Authentication replay/substitution | Hashed single-use nonce, binding digest, challenge id, inclusive deadline, atomic PostgreSQL consume | Correct binding material must come from the TLS-facing adapter |
| TOTP/recovery replay | Encrypted TOTP seed with atomic last-step update; atomic recovery `DELETE ... RETURNING` | TOTP is not phishing-resistant; prefer WebAuthn when implemented |
| Browser credential confusion/CSRF | Bearer and session cookie are mutually exclusive; `Secure`, `HttpOnly`, `SameSite=Strict`; pre-auth cookies are path-scoped, client-bound and short-lived | SameSite is defense in depth; the TLS terminator must preserve host/origin controls |
| Header spoofing | Strip all `x-openproof-*`; rebuild from trusted session; HMAC/freshness on upstream context | Upstream must verify the signature and protect the shared key |
| Request smuggling / parser abuse | Origin-form only; duplicate singleton and CL+TE rejection; Beast header/body limits; deadlines; connection ceiling | HTTP/2/3 termination behaviour belongs to the front proxy and must be tested there |
| SSRF through routing | Upstream host/port are closed-schema operator configuration, never request input | Configuration compromise can still redirect traffic |
| Upstream MITM | TLS peer, hostname and SNI verification; optional private CA | Plain upstream mode should be limited to an equally trusted local channel |
| Authorization bypass | Closed explicit method/path policies; immutable exact-match RBAC and minimum IAL; sealed policy input rebuilt from tenant-scoped PostgreSQL repositories; every non-Allow fails closed | Policy selection and administrative change review remain deployment duties; ABAC/trust/risk evaluation is not yet implemented |
| Cross-tenant access | Organization required by repository operations and membership ownership checks | Database superusers can bypass application isolation; separate DB roles are recommended |
| Database race/replay | Atomic conditional UPDATE/DELETE with RETURNING; transactional migrations and replacement | HA failover semantics depend on PostgreSQL deployment consistency |
| Log/metric injection and secret leakage | Secret types are non-formatable; JSON escaping; label validation/cardinality cap | Operator-added sinks must preserve the same contracts |
| Audit tampering | HMAC-linked sequence chain; bootstrap, member-lifecycle and rejected-authorization records commit with their security outbox events | General event persistence/export and off-host checkpoints remain deployment work |
| Bootstrap privilege creation | Offline-only command, environment-only password, generated TOTP, fixed owner role, serializable transaction, global advisory lock, refusal after first tenant | Operator shell and master-key access are fully trusted during the initial ceremony |
| Administrative privilege escalation | IAL2 session at HTTP boundary; active owner role re-read in the same serialized PostgreSQL transaction as every mutation; no roles trusted from the session; final active owner cannot lose authority; target sessions are revoked | An authorized owner may deliberately grant another owner role; administrative account protection and change review remain operator duties |
| Administrative credential disclosure | Initial and reset password/TOTP values are CSPRNG-generated server-side, excluded from audit/outbox, returned once only after commit with `no-store`; reset deletes recovery codes and revokes sessions | The TLS terminator, administrator client and recipient transfer channel can still expose the one-time response |
| Denial of service | Size/time/connection limits, scrypt resource ceilings, rate limits, circuit breaker | Per-process limiter state is not globally coordinated; front proxy should enforce fleet-wide limits |

## Deliberate constraints

- The built-in incoming listener is HTTP/1.1 plaintext and `opp server` refuses
  non-loopback binds. TLS is terminated by a trusted local proxy/sidecar.
- The runnable mode supports either public or protected routes to one configured
  upstream. Protected mode requires PostgreSQL, an active pre-provisioned
  organization and active membership. The first owner is enrolled by the
  one-time offline bootstrap command. Local-member creation, role replacement,
  suspension/reinstatement/removal and credential reset exist only behind an
  IAL2 session plus a transactional authoritative owner check; they are not
  public or self-service endpoints.
- Protected gateway access has no implicit active-member allow. Every reachable
  method/path pair must have an operator-configured role and assurance rule;
  rules are immutable until a validated process restart.
- Generic OIDC and WebAuthn providers are not implemented. The concrete local
  provider supports password and password+TOTP only.
- PostgreSQL provides durable sessions, authentication transactions, recovery
  codes, identities, external links, organizations, memberships, password
  verifiers and AES-256-GCM-encrypted TOTP seeds. Bootstrap and administrative
  member-lifecycle and rejected-authorization audit persistence is transactional;
  general audit persistence and fleet-wide rate limiting remain deployment work.

## Verification gates

- Debug and RelWithDebInfo builds treat warnings as errors and enforce C++26
  contracts for internal invariants.
- `gcc-asan` enables AddressSanitizer and UndefinedBehaviorSanitizer.
- Boundary corpus, concurrency/load, failure-injection, network integration and
  real PostgreSQL tests are part of the suite.
- Security invariants and their proving tests are indexed in
  [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md).
