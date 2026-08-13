# Changelog

## 1.1.0-rc1 - 2026-08-11

### Identity-platform completion pass — 2026-08-13

- Completed public signup, durable email/phone verification, forgot/reset password and authenticated profile self-service with verified email/phone change ceremonies.
- Added discoverable WebAuthn/passkey registration and authentication using ES256/P-256, RP/origin/challenge/UP/UV checks, durable credentials and atomic sign-counter advancement.
- Added Google, Apple and tenant-specific Microsoft OIDC login, GitHub OAuth login with PKCE and immutable account subjects, plus SIWE wallet and Farcaster FID/custody verification including ERC-1271 contract-wallet support.
- Added durable OAuth consent, resource/audience registration and enforcement, service identities, `client_credentials`, Device Authorization Grant, down-scoped Token Exchange, PAR, registered-key JAR and signed JARM.
- Added persisted DPoP/mTLS sender constraints with replay protection, refresh/exchange binding preservation and per-request enforcement in the gateway and UserInfo.
- Added owner/IAL2-protected administration UI/API for members, applications, OAuth clients, resources, service identities, secret rotation and JAR signing-key management.
- Added enterprise SAML 2.0 login with pinned-certificate XMLDSIG validation, LDAPS search-then-bind authentication and SCIM 2.0 Users/Groups provisioning. SCIM now advertises ETag support consistently, emits version tags and enforces `If-Match` preconditions on mutating resource operations.
- Added durable trust/evidence challenge handling, pinned RS256 attestation-JWT verification and X.509 chain/SAN/proof-of-possession verification feeding the trust engine.
- Added PostgreSQL migrations and production composition for the new account, consent, resource, service-identity, OAuth extension, passkey, enterprise/SCIM and evidence state. External trust integrations remain fail-closed until explicitly configured.
- Removed the obsolete `OpenProofCxx26Runtime.cmake` probe and hardened release-source gates for direct module dependencies, consent-backed `offline_access`, dead runtime dependencies and unfinished production markers.
- Added a complete 70-path/92-operation OpenAPI 3.1 contract, dependency-free
  endpoint-coverage gate and product integration examples for account,
  authentication, OAuth/OIDC, evidence, administration and SCIM calls.
- Added `opp check-config` for listener-free deployment preflight, wired it into
  the hardened systemd template, and changed the production example to consume
  core secrets from a read-only secret-store/KMS file mount.
- Fixed the built-in admin console's local-member form so it sends the required
  `identity_id`; the real-process E2E now provisions and verifies a local member.
- The browser SDK now verifies RS256 ID Tokens and the OIDC issuer/audience/time/
  nonce boundary before returning claims. JavaScript, Swift and Kotlin reject
  credential-bearing, query-bearing and loopback-lookalike issuer URLs; native
  SDK checks are part of the canonical SDK gate.
- The source/static release gate passes with 340 declared C++ tests. Qualified production promotion still requires the repository-mandated GCC 16.1 + Ninja build and full CTest/integration qualification.

### Production qualification and capability audit

- Audited the downloadable 1.0.13 source as the authoritative baseline; capability status now distinguishes implemented, foundation and missing behavior in `docs/CAPABILITY_STATUS.md`.
- Native OAuth redirect validation now supports RFC 8252-style loopback IP literals with variable ephemeral ports while rejecting `localhost` and non-loopback HTTP registrations.
- Authorization-code redemption now verifies client, redirect URI and PKCE challenge inside the repository's atomic consume operation; a wrong verifier no longer consumes a valid code.
- Confidential OAuth client-secret digest comparison now uses the security layer's constant-time comparison primitive.
- Refresh-token rotation preserves the original family expiration instead of extending lifetime on every refresh; replay/expiry remains family-revoking.
- Browser session, pre-authentication binding and login-CSRF cookies use `__Host-` names with Secure/HttpOnly attributes and `Path=/`.
- `offline_access` is no longer advertised and is rejected until an explicit consent subsystem exists.
- OAuth authorization responses include issuer `iss`; C++, JavaScript, Swift and Kotlin SDK callback helpers validate the returned issuer.
- Strengthened release verification to scan both module interfaces and implementation units for missing CMake module dependencies. This found and fixed missing explicit `openproof_identity_core` edges in application/authentication HTTP targets.
- Added regression coverage for wrong-PKCE non-consumption, native loopback port variation, absolute refresh-family expiry, Host-only cookie attributes and SDK issuer mismatch.
- Rewrote production-readiness documentation around actual promotion gates and explicitly documented remaining CIAM, provider, audience, key-rotation, proxy and operational gaps.

## 1.0.13 - 2026-08-11

### Remove fragile C++26 text-encoding runtime dependency

- Removed the production call to `std::text_encoding::environment()` and the `openproof_cxx26_runtime`/`libstdc++exp` qualification target.
- OpenProof now declares UTF-8 as an application-level protocol, JSON and logging policy instead of deriving wire behavior from the host locale.
- Startup observability records `LC_ALL`, `LC_CTYPE` or `LANG` as diagnostic metadata and reports whether the locale string declares UTF-8; locale never changes protocol encoding.
- Removed `cmake/OpenProofCxx26Runtime.cmake` and the corresponding `opp` link dependency, eliminating the Homebrew GCC 16.1/Darwin runtime packaging mismatch that blocked configuration.
- Added release gates that reject reintroduction of `std::text_encoding`, `openproof_cxx26_runtime` or `libstdc++exp` into production source/build files.

## 1.0.12 - 2026-08-11

### GCC 16.1 C++26 runtime-link qualification

- Fixed the final `opp` link failure for `std::text_encoding::environment()` on GCC 16.1/libstdc++ by explicitly qualifying the C++26 runtime implementation at CMake configure time.
- Added `openproof_cxx26_runtime`, an interface target that first probes whether `std::text_encoding` links from the primary standard library and, for GCC 16.1, falls back to the compiler-matched `libstdc++exp` archive when required.
- The runtime probe compiles **and links** a program that calls both `std::text_encoding::environment()` and `literal()`; a header-only feature macro is no longer accepted as proof that the runtime ABI is usable.
- `opp` now links the qualified C++26 runtime target, so GCC selects the matching archive from its own library search path instead of embedding a Homebrew- or machine-specific path.
- Startup text-encoding diagnostics are enabled only when the configure-time runtime probe succeeded.
- Release verification now rejects a text-encoding call that is not backed by the C++26 runtime qualification target.

## 1.0.12 - 2026-08-11

### Fixed
- OIDC ID-token `acr`/`amr` derivation now uses the long-standing `RedeemedAuthorization::assurance()` and `strength()` API instead of convenience accessors introduced only in 1.0.10. This is robust against stale GCC module CMIs and keeps the OAuth/OIDC boundary smaller.
- Added the explicit `openproof_identity_provider` CMake dependency required by the OIDC implementation unit's direct `openproof.identity.provider` import.
- Removed the transient `RedeemedAuthorization` convenience methods (`assuranceName`, factor booleans) and updated platform tests to validate the same semantics through the canonical provider API.
- Release verification now requires the OIDC provider import and its matching CMake edge and rejects reintroduction of those convenience accessors.

## 1.0.10 - 2026-08-11

### GCC 16.1 build-graph and warning qualification

- Removed the OIDC implementation-unit dependency on `openproof.identity.provider`; OIDC now consumes a normalized authentication context exposed by `oauth::RedeemedAuthorization`.
- Added stable OAuth accessors for assurance wire name, factor categories and phishing-resistant authentication so OIDC no longer needs provider-module symbols.
- Removed the now-unnecessary direct `openproof_identity_provider` dependency from the OIDC CMake target.
- Fixed PostgreSQL `-Wshadow` and `-Wmisleading-indentation` failures and statement-separated the newly added identity-platform persistence adapter to prevent hidden warning chains under `-Werror`.
- Added release gates for implementation-import/CMake dependency consistency, OIDC/provider boundary regression, and compressed PostgreSQL control-flow regressions.
- Extended the platform test to verify the normalized assurance/factor context used for OIDC `acr`/`amr`.

## 1.0.9 - 2026-08-11

### GCC 16 direct-dependency and warning-clean build fix

- Added the implementation-private `openproof.identity.provider` import to the OIDC service implementation; the service uses authentication strength/factor helpers when producing OIDC `acr` and `amr` claims and must not rely on a transitive module dependency.
- Removed the unused `emptyResponse` helper from the application-management HTTP implementation so the project remains clean under the qualified `-Werror -Wunused` profile.
- Added release regressions that require the OIDC provider import and reject reintroduction of the dead application HTTP helper.
- Retained the v1.0.8 production-stability profile: opaque heavy module models and `-fno-contracts` remain unchanged.

## 1.0.8 - GCC 16 production-stability profile

- Disabled GCC's experimental C++26 Contracts front-end by default for production builds (`-fno-contracts`); internal fail-closed invariants now use `foundation::requireInvariant`.
- Added `OPENPROOF_ENABLE_EXPERIMENTAL_CONTRACTS=ON` as an explicit unqualified compiler-research profile only.
- Reworked `Client`, OAuth authorization records, token records, Evidence and TrustAssessment to opaque shared state so non-trivial imported layouts are not serialized through GCC module CMIs.
- Preserved value semantics with copy-on-write for mutable `Client`, access/refresh token records and Evidence.
- Kept Client/OAuth/Token digest wrappers trivial and interface-defined.
- Replaced the old special-member workaround release gate with module-boundary, owner-header, repository-PImpl, no-contract-syntax and opaque-model gates.
- Release verification always deletes the build directory before configure to prevent stale GCC CMI/BMI reuse.
- Added regression coverage proving copied opaque values detach before mutation.


## 1.0.7 - 2026-08-11

### GCC 16.1 trivial-digest module-boundary workaround

- Replaced custom Rule-of-Five implementations for `ClientSecretDigest`, `CodeDigest`, and `TokenDigest` with trivially-copyable value wrappers whose complete operations live in their owning module interfaces.
- Removed the three model partitions' direct dependency on `openproof.security`; their public byte representation is now spelled directly as `std::array<std::byte, 32>`, which remains type-identical to `security::Sha256Digest` while avoiding cross-module alias streaming.
- Removed out-of-line digest constructors, copy/move operations, destructors, accessors, and comparisons from implementation units so GCC 16.1 no longer needs to access digest private storage while compiling `model.cpp`.
- Added compile-time regression assertions requiring all three digest wrappers to remain trivially copyable and trivially destructible.
- Retained the repository PImpl boundary and explicit special-member hardening for the larger non-trivial exported records.

## 1.0.6 - 2026-08-11

- Replaced `= default` special-member definitions on exported OpenProof value types with explicit member-wise copy/move/destruction for the qualified GCC 16.1 modules toolchain.
- Fixed `ClientSecretDigest` copy/move/assignment becoming spuriously deleted when used through `std::optional` in `Client`.
- Localized digest storage in Client/OAuth/Token modules to `std::array<std::byte, 32>` instead of storing the imported `security::Sha256Digest` alias; the public API remains typed as `Sha256Digest`. A reduced GCC modules reproduction demonstrated that this alias boundary itself can ICE even with manual special members.
- Applied the same hardening proactively to Application, Client, OAuth, Token, Profile, Evidence, Trust, OIDC policy/value types, and the C++ SDK.
- Moved move-only exported SecretString wrappers to explicit out-of-line move operations instead of importer-side `= default` synthesis.
- Added a static release gate that rejects defaulted special-member definitions for the hardened exported module value types.

## 1.0.5 - 2026-08-11

### GCC 16.1 module-boundary hardening

- Hides all new in-memory repository STL storage behind PImpl so exported repository CMIs no longer instantiate `std::map`/`std::mutex` over OpenProof module value types.
- Changes in-memory storage to pointer-backed records, avoiding importer-side copy-assignment/destructor synthesis for `Client`, OAuth authorization-code records, token records, evidence, profiles, and applications.
- Gives exported durable/value records explicit out-of-line copy/move/destructor definitions across the application, client, OAuth, token, evidence, profile, and trust modules.
- Adds an importer regression test that instantiates and destroys standard containers using `CodeDigest`, `AuthorizationCode`, `AccessTokenRecord`, and `RefreshTokenRecord`.
- Makes `scripts/verify-release.sh` start from a clean build tree so stale GCC CMI/BMI artifacts cannot mask or resurrect fixed module bugs.
- Adds release gates for repository PImpl boundaries and explicit module special members.

## 1.0.4 - 2026-08-11

### GCC 16.1 module ICE workaround

- Moved `client::Client` copy/move special-member generation out of importing translation units by declaring the Rule-of-Five surface in `model.cppm` and defining it out-of-line in `model.cpp`.
- Avoids a GCC 16.1 internal compiler error observed while compiling `InMemoryClientRepository::save`, where the compiler crashed synthesizing implicit `constexpr Client::operator=(const Client&)` for an exported module type.
- Added a cross-module regression test that copy-constructs, copy-assigns, move-constructs and move-assigns `Client`.
- Added a release gate that prevents accidental removal of the explicit special-member workaround while GCC 16.1 remains the qualified toolchain.


## 1.0.3 - 2026-08-11

### Fixed

- Added direct `<algorithm>` ownership includes to the Identity Profile, OAuth service, OIDC service, and Evidence model implementation units that use C++ ranges algorithms.
- Added a release regression gate that rejects `std::ranges` algorithms without the owning `<algorithm>` header, preventing GCC 16 module reachability failures from recurring.
- Added a direct `<chrono>` include to the OAuth authorization service because it performs `Instant + Duration` arithmetic; this avoids another GCC 16 module reachability failure hidden behind the earlier build stop.

## 1.0.2 - 2026-08-11

### Fixed

- Removed `[[nodiscard]]` from non-defining `friend` operator declarations in `ClientSecretDigest` and `CodeDigest`; GCC 16.1 correctly warns that such an attribute appertains to the friend declaration and is ignored, which failed the project under `-Werror=attributes`.
- Added a release regression gate that rejects `[[nodiscard]] friend` declarations which end in `;`, while preserving attributes on inline/defaulted friend definitions.

## 1.0.1 - 2026-08-11

### Fixed

- Added implementation-unit standard-library imports required by GCC 16.1 module visibility rules (`<mutex>`, `<chrono>`, and directly used utility headers).
- Fixed `std::scoped_lock` / `std::lock_guard` compilation failures in the new application, client, OAuth, token, evidence, and profile repositories.
- Fixed `foundation::Instant` comparison lookup failures in GCC 16.1 by making `<chrono>` reachable in every implementation unit that performs time-point comparisons.
- Expanded the release static gate to detect synchronization primitives used without `<mutex>` and `Instant` comparisons used without `<chrono>`.

## 1.0.0 - 2026-08-11

### Identity platform

- Added a durable Application Registry. Applications are organization-owned,
  environment-scoped products and have an independent lifecycle.
- Added OAuth client management with separate web, browser, native and service
  client kinds, exact redirect URI validation, scope policy, client lifecycle,
  confidential-client secret hashing and one-time secret return on creation or
  rotation.
- Added identity profiles for OIDC UserInfo claims without expanding the
  canonical identity aggregate.

### OAuth and OpenID Connect

- Added an OAuth 2.0 Authorization Server using the Authorization Code flow with
  mandatory PKCE S256 for all interactive clients.
- Added opaque single-use authorization codes, exact redirect binding, state and
  OIDC nonce propagation.
- Added short-lived opaque access tokens and rotating opaque refresh tokens.
- Added refresh-token family replay detection and family revocation.
- Added token introspection and revocation endpoints.
- Added OpenID Connect discovery, UserInfo and JWKS endpoints.
- Added RS256 ID Token signing using OpenSSL with an operator-provided RSA key.
- Added canonical OpenProof Identity IDs as OIDC `sub` values.
- Removed any need for implicit or resource-owner-password grants.

### Gateway

- Added delegated OAuth bearer authentication alongside platform sessions.
- Added route-level required OAuth scopes.
- Added signed upstream client ID and scope context while stripping untrusted
  client-supplied identity headers.
- Reserved OpenProof identity and protocol routes so an upstream cannot shadow
  them.

### Persistence and administration

- Added PostgreSQL persistence for applications, OAuth clients, redirect URIs,
  scopes, identity profiles, authorization codes, access tokens, refresh-token
  families and evidence.
- Authorization-code and refresh-token consumption use transactional locking so
  concurrent nodes cannot redeem a single-use credential twice.
- Added owner/IAL2-protected Application and OAuth Client management HTTP APIs.

### Trust and evidence

- Added provider-neutral Evidence, EvidenceVerifier and EvidenceService APIs.
- Added durable evidence storage and revocation.
- Added a derived TrustEngine with weighted active evidence and normalized risk
  signals. Trust assessments are recomputed rather than stored as durable truth.

### SDKs and integration

- Added modern C++ module SDK (`openproof.sdk`).
- Added browser/JavaScript PKCE SDK.
- Added Apple Swift SDK for iOS 17+ and macOS 14+.
- Added Kotlin SDK suitable for Android/JVM applications.
- Added a Tegra-style reference consumer showing how a product delegates sign-in
  to OpenProof instead of owning passwords or sessions.

### Security hardening

- Redirect URIs use exact matching and reject authority-confusion/userinfo forms.
- Native loopback redirects require an explicit numeric port and an exact
  loopback host.
- OIDC issuer validation rejects userinfo, query, fragment, control characters
  and non-loopback plaintext issuers.
- Raw authorization codes, access tokens, refresh tokens and confidential-client
  secrets are never stored durably; keyed digests are persisted instead.
- Added trust/risk boundary validation and deterministic evidence expiry handling.
