# Changelog

Notable user-facing changes to OpenProof are recorded here.

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
