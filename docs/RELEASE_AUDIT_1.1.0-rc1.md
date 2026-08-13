# OpenProof 1.1.0-rc1 release audit

Date: 2026-08-11

This audit is grounded in the packaged source tree. It deliberately separates
implemented capability from target-environment qualification.

## Implemented IAM core

OpenProof currently implements canonical tenant-scoped identity, local password
and TOTP authentication, session lifecycle, recovery codes, organization and
membership administration, application registration, OAuth client management,
Authorization Code + mandatory S256 PKCE, opaque access/refresh tokens,
refresh-token rotation and family replay revocation, OAuth introspection and
revocation, OpenID Connect Discovery/JWKS/RS256 ID Token/UserInfo, PostgreSQL
persistence, API-gateway policy/routing primitives, administration APIs and four
SDK integration surfaces.

## Security hardening added for this candidate

- Native loopback redirect matching accepts registered IPv4/IPv6 loopback IP
  literals with a variable ephemeral port while preserving host/path/query.
- Authorization codes are consumed only after client, redirect and PKCE binding
  match atomically; a mismatched verifier does not burn a valid code.
- Confidential client-secret digests are compared in constant time.
- Refresh-token family expiry is absolute and non-sliding.
- `offline_access` is rejected and not advertised until explicit consent exists.
- Ambient browser credentials use `__Host-` cookie names.
- OAuth authorization responses carry `iss`; C++, JavaScript, Swift and Kotlin
  SDK surfaces validate the returned issuer.
- The release import/CMake consistency gate covers both `.cpp` and `.cppm`.
- PostgreSQL integration coverage includes Application/Client/Profile storage,
  bound single-use authorization-code consumption, access/refresh persistence,
  rotation, absolute refresh expiry and replay-triggered family revocation.

## Deliberately not claimed as complete

OpenProof 1.1.0-rc1 does not yet provide a complete public-consumer CIAM
experience. Public registration, verified email/phone lifecycle, self-service
forgot-password, self-service profile editing/deletion/export, WebAuthn/passkeys,
social providers, consent records/screens and a human admin console remain to be
implemented when required by a product.

The protocol surface also does not yet include `client_credentials`, Device
Authorization, Token Exchange, PAR/JAR/JARM, DPoP/mTLS, Dynamic Client
Registration or OIDC RP-Initiated Logout. A first-class resource-server/audience
registry is still required before unrelated APIs with overlapping scopes share
one token ecosystem.

Operationally, the current tree uses one configured OIDC RSA signing key, does
not provide online master-secret rotation, and does not implement a trusted
reverse-proxy client-IP propagation contract. Backup/restore automation,
disaster recovery, multi-region operation and public-load qualification are
operator/release work, not proven capabilities of this candidate.

## Verification performed while packaging this candidate

- Static release verification: PASS.
- C++ test declarations found: 327.
- JavaScript SDK tests: PASS on Node 22.16.0.
- Kotlin SDK compilation: PASS with `kotlinc`.
- Swift source parse: PASS. Full Swift package compilation is not claimed in the
  Linux packaging environment because Apple CryptoKit is unavailable there.
- Shell syntax for `scripts/qualify-production.sh`: PASS.
- Classic project headers (`.h`/`.hpp`): zero.
- Production TODO/FIXME/HACK/XXX scan: zero in source/SDK/example code.

The owner previously demonstrated a clean GCC 16.1/macOS ARM64 build/link of the
1.0.13 baseline. Because 1.1.0-rc1 changes security-sensitive code, this
candidate requires its own clean GCC 16.1 build, full CTest run and zero-skip
PostgreSQL qualification. Those target-environment results are intentionally not
inferred from the 1.0.13 result.

## Promotion command

Use a disposable PostgreSQL database only:

```bash
export OPENPROOF_TEST_POSTGRES='postgresql://.../openproof_qualification'
export OPENPROOF_TEST_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_IS_DESTRUCTIVE
./scripts/qualify-production.sh
```

Never point this qualification harness at production, staging, or a shared
development database; the PostgreSQL integration fixture truncates OpenProof
tables.
