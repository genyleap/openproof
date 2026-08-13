# Production readiness — 1.1.0-rc1

OpenProof 1.1.0-rc1 is an **integration-ready production qualification
candidate**, not a production-approved public release.

The project has a real executable and the 1.0.13 baseline was cleanly compiled
and linked by the project owner on the qualified GCC 16.1.0 / Ninja / macOS
ARM64 toolchain. The 1.1.0-rc1 tree changes security-sensitive OAuth/client/token
and cookie behavior and therefore requires its own clean qualification; it does
not inherit the 1.0.13 build result.

## Promotion gates

Production promotion requires all of the following on the target deployment
class:

1. Clean GCC 16.1 configure and full Release build with warnings as errors.
2. Complete CTest pass with `OPENPROOF_TEST_POSTGRES` configured so PostgreSQL
   tests do not skip.
3. AddressSanitizer + UndefinedBehaviorSanitizer build and full test pass.
4. Browser/native Authorization Code + PKCE end-to-end test through the actual
   reverse proxy/TLS boundary, including `state`, `nonce`, authorization-response
   `iss`, code replay, refresh rotation/replay, logout and restart persistence.
5. Independent OIDC relying-party interoperability test for Discovery/JWKS/
   ID-token validation/UserInfo.
6. PostgreSQL concurrency exercises for authorization-code consumption, refresh
   rotation and session/recovery one-time state.
7. Database migration on non-empty data, backup/restore drill and documented
   rollback/recovery procedure.
8. Load/soak testing of authorization, token, introspection, UserInfo and gateway
   paths with resource limits observed.
9. Security review/fuzzing of HTTP parameter parsing, redirect URI handling,
   JOSE/JWK boundaries and persistence decoding.
10. Resolution of the P0 launch gaps in `docs/CAPABILITY_STATUS.md` that are
    required by the specific product (consumer registration, recovery, provider
    set, audience model, key/proxy operations).

## Security deltas in 1.1.0-rc1

- Native loopback redirect matching follows an IP-literal + variable ephemeral
  port model while preserving registered path/query binding.
- Authorization-code client/redirect/PKCE checks happen inside the atomic
  consume operation so an invalid verifier cannot burn a valid code.
- Confidential client secret digests are compared through the security layer's
  constant-time comparison.
- Refresh-token family expiration is absolute; rotation does not extend it.
- `offline_access` is rejected until consent support exists and is not advertised.
- Browser ambient credentials use `__Host-` cookie names.
- Authorization responses carry `iss`, and all shipped SDK surfaces validate it.
- Release verification checks project-module imports in both `.cpp` and `.cppm`
  files against the CMake target dependency graph.
- PostgreSQL promotion coverage includes the identity-platform repositories and
  one-time OAuth/token state; those tests remain a launch gate until run zero-skip
  against a disposable PostgreSQL database on the qualified target toolchain.

## Toolchain note

GCC 16.1/Darwin is the qualified modules toolchain for this project. Production
builds explicitly disable the experimental Contracts front-end and Reflection;
internal invariants use `foundation::requireInvariant`. Clean CMI/BMI state is
mandatory for release qualification.
