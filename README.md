# OpenProof Protocol

**An Open Protocol for Identity, Proof, Trust & Secure Access**

OpenProof is a self-hostable, extensible protocol for verifying identity,
collecting and evaluating proofs and evidence, assessing trust and risk, and
enforcing secure access policies across Web2, Web3, enterprise, social, physical
and machine identities.

It is vendor-neutral. Nothing in the protocol core names a particular company,
cloud, database, blockchain, social network or identity provider — those exist
only as providers behind extension interfaces.

> ### Status: authentication and gateway milestone implemented and verified.
>
> Implemented and tested: the foundation, the identity core (canonical identity,
> explicit linking, explicit merge, organization-scoped repositories), the
> authentication SPI and local password+TOTP provider, opaque server-side sessions,
> recovery codes, multi-tenancy, trusted authentication/authorization handoff,
> bounded HTTP reverse proxy, signed upstream identity context, rate limiting,
> discovery, weighted load balancing, circuit breaking, PostgreSQL migrations and
> durable single-use stores, audit chaining, metrics and tracing.
>
> `opp server` now has an opt-in operational authentication mode: HTTP login/MFA,
> session rotation/revocation, recovery-code issuance, PostgreSQL-backed identities,
> memberships, local password/TOTP credentials and protected-route enforcement.
> Credential enrollment and tenant/policy administration deliberately remain an
> operator/admin boundary; there is no public sign-up endpoint. Proof/evidence,
> trust/risk, generic OIDC/WebAuthn and the administrative API are future phases.
>
> See [docs/00-AUDIT.md](docs/00-AUDIT.md) §14 for the phase plan and exactly
> what is and is not built. Nothing here is stubbed to look finished.

---

## What it separates

The central design claim is that these are different questions, and collapsing
them into one score or one boolean is how identity systems go wrong:

```
Identity        who or what is this subject?
Authentication  how did the subject authenticate?
Proof           what can the subject prove?
Evidence        what externally verifiable information supports that proof?
Trust           how useful is that evidence, for this specific purpose?
Risk            what signals indicate abuse, fraud, Sybil behaviour, compromise?
Policy          what does the relying application require?
Authorization   given all of the above, is this operation permitted?
```

Each is a separate module boundary, not a comment.

## Self-hosted first

A deployment operator runs the whole system on their own infrastructure and owns
the identity data, credentials, sessions, proofs, evidence, policies and audit
logs. The protocol does not require its maintainers to hold anyone's data.

---

## Requirements

| Component | Minimum | Verified on |
|---|---|---|
| Compiler | **GCC ≥ 16 (required)** | GCC 16.1.0 |
| CMake | ≥ 3.30 | 4.4.1 |
| Generator | Ninja | 1.13.2 |
| OpenSSL | ≥ 3.0 | 3.6.3 |
| tomlplusplus | 3.x | 3.4.0 |
| GoogleTest | 1.x | 1.17.0 (built from source) |
| Boost | ≥ 1.88 | 1.90.0 |
| PostgreSQL client | ≥ 15 | 18.4 |

GCC 16 is required, not preferred: OpenProof uses C++26 contracts (P2900)
through standard syntax, and no other released compiler implements them. Clang
is rejected at configure time with a diagnostic naming the gap. The measured
feature matrix, including two GCC defects worked around, is in
[docs/03-CXX26.md](docs/03-CXX26.md).

```bash
brew install gcc cmake ninja openssl@3 tomlplusplus boost postgresql@18
```

## Build

```bash
cmake --preset gcc-debug
```

```bash
cmake --build --preset gcc-debug
```

```bash
ctest --preset gcc-debug
```

Presets: `gcc-debug`, `gcc-release`, and `gcc-observe` (contracts report instead
of terminating — for staged rollout, not production), plus `gcc-asan` for
AddressSanitizer and UndefinedBehaviorSanitizer.

### CLion

Choose a CMake profile backed by the **`gcc-debug` preset**. That is the whole
setup.

Configuring a toolchain by hand instead requires two *different* drivers:

| Field | Value |
|---|---|
| C compiler | `gcc-16` |
| C++ compiler | `g++-16` |

A C compiler is needed even though OpenProof contains no C: GoogleTest's own
`project()` call names no languages, so CMake enables C for it. Pointing the C
field at `g++-16` is detected at configure time with the correct driver named.

## Run

```bash
./cmake-build-gcc-debug/apps/opp/opp --help
```

```bash
./cmake-build-gcc-debug/apps/opp/opp --print-default-config
```

```bash
OPENPROOF_TOKEN_SIGNING_KEY="$(openssl rand -base64 32)" \
  ./cmake-build-gcc-debug/apps/opp/opp server --config openproof.toml
```

For the persistent protected gateway, provision an active organization and an
explicitly linked local account, then use
[`examples/openproof.auth-gateway.toml`](examples/openproof.auth-gateway.toml).
The process applies checksummed migrations at startup. Authentication endpoints
are documented in [docs/02-CONFIGURATION.md](docs/02-CONFIGURATION.md).

The built-in incoming listener is intentionally plaintext and refuses any
non-loopback bind. Terminate TLS in a trusted local reverse proxy/sidecar. TLS to
the upstream is verified by default, including SNI and hostname verification.

Configuration reference: [docs/02-CONFIGURATION.md](docs/02-CONFIGURATION.md).

---

## Repository layout

```
CMakeLists.txt              project openproof
CMakePresets.json           gcc-debug / gcc-release / gcc-observe
cmake/
  OpenProofToolchainGuard.cmake   hard-fails on an unsupported toolchain
  OpenProofModule.cmake           openproof_add_module() — FILE_SET CXX_MODULES
  OpenProofCompileOptions.cmake   warnings-as-errors, hardening, contracts
  toolchains/gcc.cmake            GCC discovery without machine-specific paths
src/
  foundation/          openproof.foundation         errors, Result, ids, time, secrets, encodings
  security/            openproof.security           CSPRNG, SHA-256, constant-time compare, AEAD
  observability/       openproof.observability      structured JSON logging
  config/              openproof.config             typed configuration, secret references
  identity/core/       openproof.identity.core      Identity, linking, merge, repositories
  identity/provider/   openproof.identity.provider  authentication SPI, transactions, assurance
  authentication/      openproof.authentication     broker plus bounded HTTP auth plane
  session/             openproof.session            opaque sessions, rotation and revocation
  credentials/         openproof.credentials        scrypt passwords, TOTP and recovery codes
  providers/local/     openproof.provider.local      password and password+TOTP provider
  gateway/             openproof.gateway[.http]      routing, enforcement and reverse proxy
  storage/postgres/    openproof.storage.postgres    pool, migration and durable atomic stores
  audit/               openproof.audit               HMAC-chained audit/security events
  telemetry/           openproof.telemetry           bounded metrics and W3C trace context
  policy/              openproof.policy             authorization decision model
  organization/        openproof.organization       tenants, memberships, role assignment
apps/opp/              single binary; `opp server` will run the daemon
tests/                 291 discovered tests
docs/
  00-AUDIT.md              Phase 0 audit, conflicts, phase plan
  01-ARCHITECTURE.md       layering, provider SPI, security properties
  02-CONFIGURATION.md      configuration reference
  03-CXX26.md              measured C++26 feature baseline
  SECURITY_INVARIANTS.md   invariants with enforcement, proof and failure mode
  THREAT_MODEL.md          assets, trust boundaries, threats and residual risks
```

## Security invariants

Forty-nine invariants are recorded in
[docs/SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md), each naming what must
be true, the mechanism that enforces it, the test that proves it, and what
happens on failure. Invariants that are true but not yet *mechanically* enforced
are listed separately rather than presented as if they were.

Several are enforced by the type system, so violating them fails the build:

- A credential cannot be logged, formatted, streamed, copied or compared —
  `Secret<T>` has no formatter, no stream insertion, no conversion and no `==`.
- An external identifier cannot become a canonical identity key — distinct
  `StrongId` tags with no conversion between them.
- Cross-tenant access cannot be *expressed*: the organization is a parameter of
  every repository operation, and a foreign key reads as absent.

## Engineering contract

Built against [ai-for-modern-cpp](https://github.com/thecompez/ai-for-modern-cpp),
revision `326cd850c2cb5e39264b7d2ccf2c29fba6627380`.

C++26 with project-owned modules, `.cppm` interfaces with `.cpp` implementations,
no `.h`/`.hpp` anywhere in project code, no `import std;`, target-based CMake with
module file sets, warnings-as-errors, `std::expected` for recoverable failures,
RAII throughout, documented thread safety, English Doxygen on every exported
declaration.

Where the contract and a measured toolchain fact disagree, the measurement wins
and the deviation is recorded in [docs/03-CXX26.md](docs/03-CXX26.md).
