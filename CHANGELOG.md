# Changelog

Notable user-facing changes to OpenProof are recorded here.

## 1.1.0-rc4 — 2026-09-22

### Setup reliability

- Fixed a Bash nounset failure while persisting generated database credentials
  during local PostgreSQL setup.
- Audited installer-local variable declarations for dependent initialization.
- Added a release blocklist hook so a known-bad release can be skipped by the
  bootstrap resolver even if GitHub has already published its artifacts.

## 1.1.0-rc3 — 2026-09-22

### Installer and operations UX

- Added a polished color-aware terminal experience for installation and setup.
- Added explicit self-hosted operation, data responsibility, privacy, terms, and
  documentation notices to the installer and configuration wizard.
- Fixed interactive setup when the bootstrap installer is piped through sudo.
- Expanded the `openproof` management CLI with info, service lifecycle, logs,
  update/upgrade, diagnostics, backup/restore, and safer uninstall workflows.
- Kept production installation prebuilt-only with verified AMD64/ARM64 bundles.

## 1.1.0-rc2 — 2026-09-22

### Installation and release delivery

- Replaced target-host source-build fallback with verified prebuilt Linux bundles.
- Added self-contained AMD64 and ARM64 runtime bundles with required non-glibc
  shared libraries and a bundled OpenSSL CLI.
- The bootstrap installer no longer installs compilers, build toolchains, or
  OpenProof runtime library packages on the target host.
- Missing release artifacts now fail explicitly instead of compiling OpenProof
  or GCC on the user's machine.

## 1.1.0-rc1 — 2026-09-21

### Identity and authentication

- Added public account enrollment, verified email/phone ownership, profile
  self-service, password recovery and passkeys.
- Added self-service connected accounts with explicit linking and protection
  against cross-account transfer.
- Added Google, GitHub, Microsoft, Apple, LinkedIn, Telegram and X federation.
- Added Ethereum SIWE and Farcaster SIWF authentication.
- Added SAML, LDAPS and SCIM enterprise integration.

### OAuth, OIDC and access

- Added Authorization Code + PKCE, client credentials, Device Flow, Token
  Exchange, PAR, JAR/JARM, introspection and revocation.
- Added OIDC discovery, JWKS, UserInfo and signed ID tokens.
- Added application/client registration, resource/audience policy, consent and
  service identities.
- Added sender-constrained token support for DPoP and mTLS.
- Added route-level scope, audience, role and assurance enforcement.

### Platform and security

- Added PostgreSQL-backed durable state and checksummed migrations.
- Added versioned credential encryption, key-rotation workflows and hardened
  secret references.
- Added authenticated metrics, health endpoints, backup/restore tooling and
  production qualification scripts.
- Added release packaging and a guided Debian/Ubuntu installer with verified
  release downloads and source-build fallback.
- Expanded the C++, JavaScript, Swift and Kotlin SDK foundations.
- Added the OpenAPI 3.1 contract and interactive Developer Portal.

## 1.0.0 — 2026-08-11

- Established the canonical identity, provider, session, policy, gateway,
  security and PostgreSQL module boundaries.
- Added the initial OAuth/OIDC authorization server and application/client
  registry.
- Added provider-neutral evidence and trust primitives.
- Added the first SDK surfaces and reference application integration.
