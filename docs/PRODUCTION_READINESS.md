# Production readiness — 1.1.0-rc1

OpenProof 1.1.0-rc1 is an **integration-ready production qualification
candidate**, not a production-approved public release.

The current 1.1.0-rc1 tree completed clean GCC 16.1 Release and ASan/UBSan
builds on macOS ARM64 on 2026-08-14. Debug, Release and ASan/UBSan passed all
340 current tests, including PostgreSQL integration against a dedicated
disposable database, with zero skips. JavaScript tests, the checksummed Kotlin
Gradle build and Swift package tests also passed. See
`RELEASE_AUDIT_1.1.0-rc1.md` for the exact qualification record.

## Promotion gates

Production promotion requires all of the following on the target deployment
class:

1. Clean GCC 16.1 configure and full Release build with warnings as errors.
2. Complete CTest pass with `OPENPROOF_TEST_POSTGRES` configured so PostgreSQL
   tests do not skip.
3. AddressSanitizer + UndefinedBehaviorSanitizer build and full test pass.
4. The repository TLS E2E must pass, then the same Authorization Code + PKCE
   flow must be repeated through the target reverse proxy with selected browser
   and native clients. The repository E2E covers `state`, `nonce`, response `iss`,
   refresh rotation/replay, logout and restart persistence.
5. Discovery/JWKS/ID-token/UserInfo verification must pass both the independent
   Node crypto verifier shipped in the E2E and the product's selected OIDC RP.
6. PostgreSQL concurrency exercises for authorization-code consumption, refresh
   rotation and session/recovery one-time state.
7. The shipped representative-data backup/restore drill must pass, followed by
   a rehearsal with target storage, retention and secret-store versions.
8. Load/soak testing of authorization, token, introspection, UserInfo and gateway
   paths with resource limits observed.
9. Coverage-guided fuzzing beyond the shipped deterministic malformed-input
   corpus, plus independent security review of HTTP parsing, redirect URI,
   JOSE/JWK and persistence-decoding boundaries.
10. Resolution of any product-specific launch gate not exercised by the generic suite.

## Security deltas in 1.1.0-rc1

- Native loopback redirect matching follows an IP-literal + variable ephemeral
  port model while preserving registered path/query binding.
- Authorization-code client/redirect/PKCE checks happen inside the atomic
  consume operation so an invalid verifier cannot burn a valid code.
- Confidential client secret digests are compared through the security layer's
  constant-time comparison.
- Refresh-token family expiration is absolute; rotation does not extend it.
- `offline_access` is available only through the explicit consent boundary and
  is advertised when OIDC is enabled.
- Browser ambient credentials use `__Host-` cookie names.
- Authorization responses carry `iss`, and all shipped SDK surfaces validate it.
- Release verification checks project-module imports in both `.cpp` and `.cppm`
  files against the CMake target dependency graph.
- PostgreSQL promotion coverage includes the identity-platform repositories and
  one-time OAuth/token state; those tests remain a launch gate until run zero-skip
  against a disposable PostgreSQL database on the qualified target toolchain.
- Deployment preflight uses `opp check-config` before the listener starts, and
  the Linux template reads core secret material from a read-only
  secret-store/KMS mount. Target promotion still requires exercising the actual
  provider and recording the selected secret versions with the restore drill.

## Toolchain note

GCC 16.1/Darwin is the qualified modules toolchain for this project. Production
builds explicitly disable the experimental Contracts front-end and Reflection;
internal invariants use `foundation::requireInvariant`. Clean CMI/BMI state is
mandatory for release qualification.
