# Changelog

Notable user-facing changes to OpenProof are recorded here.

## 1.1.0-rc1 — 2026-09-22

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
- Added versioned credential encryption, dedicated persistent keys, key-rotation
  workflows and hardened binary-safe secret references.
- Added authenticated metrics, health endpoints, backup/restore tooling and
  production qualification scripts.
- Added the OpenAPI 3.1 contract and interactive Developer Portal.
- Expanded the C++, JavaScript, Swift and Kotlin SDK foundations.

### Installation and operations

- Added verified prebuilt AMD64 and ARM64 runtime bundles; the production
  installer never compiles OpenProof or installs compiler/build dependencies on
  the target host.
- Added a color-aware guided installer and setup wizard with explicit self-hosted
  operation, data-responsibility, privacy and terms notices.
- Added PostgreSQL, optional local email delivery, provider, Nginx and TLS setup.
- Added the `openproof` management CLI for info, status, diagnostics, logs,
  service lifecycle, configuration, update/upgrade, backup/restore and uninstall.
- Made setup resilient when invoked through `curl | sudo sh`.
- Interactive validation now stays on the current field instead of restarting the
  wizard: invalid input gets red feedback, accepted input gets green feedback,
  each field gets three attempts, then the operator can retry that same field or
  exit setup while preserving completed system changes.
- Collects and validates SMTP relay settings before installing optional mail
  runtime packages, and keeps successful package provisioning output concise.
- Generated persistent security material is stored as hexadecimal and referenced
  with `hexfile:` so OpenProof receives the exact binary key lengths expected by
  the runtime.

## 1.0.0 — 2026-08-11

- Established the canonical identity, provider, session, policy, gateway,
  security and PostgreSQL module boundaries.
- Added the initial OAuth/OIDC authorization server and application/client
  registry.
- Added provider-neutral evidence and trust primitives.
- Added the first SDK surfaces and reference application integration.
