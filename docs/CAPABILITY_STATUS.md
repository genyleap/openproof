# OpenProof capability status — completed identity-platform surface

This document inventories the capabilities present in the current source tree.
A capability is marked **Implemented** only when the repository contains the
usable domain/service implementation plus the persistence, protocol/HTTP surface
and production composition needed by that capability. Features that depend on an
external IdP, directory, blockchain RPC, delivery service, CA or proof issuer are
fail-closed until that operator configuration is supplied.

## Requested identity-platform capabilities

| # | Capability | Status | Current implementation |
|---:|---|---|---|
| 1 | Public signup | **Implemented** | Public enrollment creates a pending canonical identity and local credential; login remains unavailable until the email-verification ceremony completes. |
| 2 | Email verification | **Implemented** | One-time HMAC-digested verification challenges, resend/expiry handling, verified email claim, and verified email-change ceremony. |
| 3 | Phone/SMS verification | **Implemented** | One-time phone verification ceremony with durable verified-phone claim and authenticated HTTPS verification-delivery adapter. |
| 4 | Forgot-password self-service | **Implemented** | One-time password-reset challenge, authenticated delivery, expiry/replay handling and credential replacement. |
| 5 | User-profile self-service | **Implemented** | Authenticated profile read/update plus separately verified email/phone ownership changes. |
| 6 | Passkeys / WebAuthn | **Implemented** | Discoverable ES256/P-256 credentials, RP/origin/challenge/UP/UV validation, durable credential storage, assertion verification and atomic sign-counter advancement. |
| 7 | Google / Apple login | **Implemented** | OIDC Authorization Code + PKCE, state/nonce, discovery/JWKS rotation and ID Token validation; Apple form-post callback is supported. |
| 8 | Consent subsystem | **Implemented** | Durable remembered grants, consent UI with CSRF protection, approve/deny and revocation semantics. |
| 9 | Resource / Audience Registry | **Implemented** | Tenant resource registry, resource scopes, audience propagation into token families and gateway audience enforcement. |
| 10 | `client_credentials` | **Implemented** | Service-client authentication and access-token-only machine grant with registered scope/audience constraints. |
| 11 | Service identities | **Implemented** | Canonical `Service` identities bound to service OAuth clients with durable lifecycle and management API. |
| 12 | GitHub / Microsoft / Farcaster / Wallet providers | **Implemented** | GitHub OAuth+PKCE and immutable account subject; tenant-specific Microsoft OIDC; SIWE EOA/ERC-1271 wallet proof; Farcaster FID/custody verification against the configured on-chain IdRegistry. |
| 13 | Admin Console | **Implemented** | Owner + IAL2-protected web/API management for members, applications, clients, resources, service identities, client secret rotation and JAR signing keys. |
| 14 | SAML / LDAP / SCIM | **Implemented** | Pinned-certificate SAML 2.0 login with constrained XMLDSIG verification; LDAPS search-then-bind; bearer-protected SCIM 2.0 Users/Groups provisioning over canonical identities/memberships. |
| 15 | DPoP / mTLS | **Implemented** | Sender binding persisted in token families, DPoP replay/`htu`/`htm`/`iat`/`jti`/`ath` verification, authenticated mTLS certificate forwarding, refresh/exchange binding preservation and gateway/UserInfo enforcement. |
| 16 | Device Flow | **Implemented** | Durable Device Authorization Grant with approval/denial, atomic polling, `authorization_pending`, `slow_down`, expiry and single consumption. |
| 17 | Token Exchange | **Implemented** | Down-scope/down-audience token exchange that cannot mint authority absent from the subject token and client grants. |
| 18 | PAR / JAR / JARM | **Implemented** | One-time pushed authorization requests, pinned registered JAR signing keys with replay protection, and signed JARM success/error responses. |
| 19 | Real Trust / Evidence verifiers | **Implemented** | Durable one-time proof challenges plus pinned RS256 attestation-JWT verification and X.509 chain/SAN/proof-of-possession verification feeding the evidence repository and trust engine. |

## Other implemented platform surface

- Canonical tenant-scoped identities, explicit external-identity linking and lifecycle.
- Password + TOTP local authentication, recovery codes and session rotation/revocation.
- Organization membership and role administration.
- Application and OAuth-client registries with exact redirect and lifecycle rules.
- Authorization Code + mandatory S256 PKCE, opaque access/refresh tokens, refresh
  rotation/replay-family revocation, introspection and revocation.
- OIDC discovery, JWKS, RS256 ID Token and UserInfo.
- PostgreSQL persistence with checksummed forward-only migrations.
- API gateway role/IAL/scope/audience enforcement, rate limiting, circuit breaker
  and trusted upstream identity context.
- C++/JavaScript/Swift/Kotlin SDK foundations.

## External dependencies that must be configured to activate integrations

Capabilities are present in source but deliberately stay disabled when their
external trust dependency is absent:

- Email/SMS verification requires the authenticated HTTPS delivery webhook in
  `[account]` configuration.
- Google, Apple, Microsoft and GitHub require registered upstream OAuth/OIDC
  client credentials and the exact federation callback URI.
- Wallet/Farcaster require HTTPS EVM RPC endpoints; Farcaster additionally
  requires the configured IdRegistry contract address.
- LDAP requires LDAPS and directory configuration; SAML requires the IdP entity,
  SSO URL and pinned IdP signing certificate.
- SCIM requires an operator-generated bearer token of at least 32 bytes.
- Signed evidence JWT requires a pinned RSA public key, issuer and audience.
- X.509 evidence requires an operator CA trust store and may additionally use a
  CRL file.
- mTLS sender constraints require an authenticated trusted-ingress forwarding
  key when TLS terminates outside the OpenProof loopback listener.

## Deliberately separate or still deployment-level work

The completed list above does not imply that every possible IAM feature belongs
inside OpenProof. Dynamic Client Registration, pairwise OIDC subjects, RP-initiated
logout, automated master-key rekeying, multi-region replication, scheduled
backup/restore orchestration beyond the included safe scripts, external SIEM
integration, and a trusted public TLS edge remain
separate protocol/deployment capabilities unless a relying deployment adds them.
Self-service privacy workflows such as account export/deletion are also distinct
from the 19 completed identity-platform capabilities above.

## Production qualification

The repository continues to require its qualified **GCC 16.1 + Ninja** C++26
modules toolchain. Promotion to production still requires the release gates in
`scripts/qualify-production.sh`: a clean qualified build, complete CTest run,
PostgreSQL integration tests without skips, sanitizers/fuzzing where configured,
the repository TLS identity E2E, load/soak qualification and deployment
key/backup exercises.
