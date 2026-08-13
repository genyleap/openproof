# OpenProof 1.1.0-rc1 release audit

Last qualification: 2026-08-14

This audit is grounded in the current source tree and separates implemented
capability from deployment-specific production approval.

## Implemented identity core

OpenProof implements centralized tenant-scoped identities, consumer signup and
verified email/phone lifecycle, local password/TOTP/recovery authentication,
passkeys, sessions, profiles, organizations/RBAC, application/client/resource
registries, service identities, OAuth 2.0/OIDC, federated/social/enterprise/Web3
providers, SCIM, evidence verification, trust assessment, PostgreSQL durability,
an enforcing gateway, admin UI/API and four client SDKs. The exact inventory and
external activation requirements are in `CAPABILITY_STATUS.md`.

## Qualification performed

The following gates passed on macOS ARM64 with GCC 16.1 on 2026-08-14:

- static release/source/CMake security gates;
- clean RelWithDebInfo build with warnings as errors;
- all **340/340** current CTest cases in Debug and RelWithDebInfo, with zero skips;
- all PostgreSQL integration cases against a dedicated disposable database;
- clean ASan + UBSan build and the same **340/340** tests with zero sanitizer errors;
- the deterministic 10,000-input malformed-boundary corpus exercised HTTP,
  credential, trace-context, redirect-URI and JOSE/JWK parsers under sanitizers;
- JavaScript SDK tests;
- Swift package build and native PKCE/issuer-boundary test;
- Kotlin SDK build through the checksummed Gradle 9.3.1 Wrapper. It uses the
  compiler embedded in the pinned distribution and does not depend on a
  host-global `kotlinc` or an unpinned Kotlin plugin download.

The reusable CI workflow runs the canonical `scripts/qualify-production.sh`
gate with two isolated PostgreSQL databases, all SDKs and the TLS identity E2E.

## Operational hardening in this tree

- `GET /health/live` and PostgreSQL-backed `GET /health/ready` are available for
  orchestration without exposing configuration or dependency errors.
- Health, JOSE key-overlap and trusted-proxy client-IP tests are included in the
  current **340-test** suite; Debug, Release and ASan/UBSan all pass.
- Safe backup and checksum creation is provided by
  `scripts/backup-postgres.sh`.
- Restore refuses a non-empty target and verifies the sidecar checksum before a
  single-transaction `pg_restore` (`scripts/restore-postgres.sh`).
- A local drill backed up the qualification database, restored 50 OpenProof
  tables and all 13 migration records into a new empty database, then verified
  that a second restore was refused without changing data. The disposable
  restore database was dropped after validation.
- Product flows and exact API calls are documented in `API_GUIDE.md`; the
  OpenAPI 3.1 contract now covers all 70 public paths and 92 operations across
  account, authentication, OAuth/OIDC, evidence, administration and SCIM. A
  dependency-free release gate rejects endpoint/operation-ID drift, and the
  complete document passes an independent OpenAPI semantic validator.
- The real-process E2E passed through a certificate-validating local TLS edge:
  authenticated signup delivery and verification, login/MFA/password reset,
  admin console/local-member/app/client/resource provisioning, Authorization Code + PKCE, independent
  Node verification of the RS256 ID Token, UserInfo, introspection, protected
  gateway audience/scope enforcement, refresh-family replay revocation, graceful
  restart persistence and old/new JWKS key overlap. A 600-request mixed
  concurrency smoke covers readiness, Discovery, JWKS, UserInfo, introspection
  and the protected gateway and reports throughput plus p50/p95/p99.
- The final canonical local mixed-read run completed 600 requests at concurrency
  24 with zero HTTP failures, about 778.8 requests/second, p50 30.4 ms,
  p95 36.9 ms and p99 40.9 ms. This is a local smoke measurement, not a target
  capacity claim.
- Trusted proxy mode canonicalizes exactly one proxy-overwritten client IP,
  rejects missing/malformed/chained values, strips the header before routing and
  cannot be enabled on a non-loopback listener. Hardened systemd/Nginx templates
  are included under `deploy/`.
- `opp check-config` validates the closed schema and resolves configured secret
  references without opening a listener or contacting dependencies. The Linux
  unit runs it in `ExecStartPre`, while the production TOML template consumes
  master/database/delivery/OIDC material through a read-only secret-store/KMS
  file mount instead of service-wide environment values.
- A representative-data drill backed up that E2E database and restored one
  organization, two identities, one application, one OAuth client, three session
  records and all 13 migrations. A second restore into the non-empty target was
  refused; the disposable restore database was then removed.

## Remaining promotion evidence

This candidate is not labeled production-approved until the target deployment
also passes:

1. repetition through the target deployment's real public TLS edge and selected
   browser/native OIDC clients;
2. product-shaped load/soak with target CPU, memory and PostgreSQL observability;
3. extended coverage-guided fuzzing and an independent focused security review;
4. a target secret-store/KMS rotation exercise and controlled master-key
   migration procedure.

These are concrete release gates, not evidence that the implemented account or
protocol surfaces are missing.

## Promotion command

Use a disposable PostgreSQL database only:

```bash
export OPENPROOF_TEST_POSTGRES='postgresql://.../openproof_qualification'
export OPENPROOF_TEST_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_IS_DESTRUCTIVE
export OPENPROOF_E2E_POSTGRES='postgresql://.../openproof_e2e_qualification'
export OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE
./scripts/qualify-production.sh
```

Never point either database at production, staging or shared development. The
integration fixture truncates tables, while E2E requires a second database with
zero user tables and intentionally retains its representative result for review.
