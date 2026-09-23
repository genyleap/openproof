# Changelog

Notable user-facing changes to OpenProof are recorded here.

## 1.1.0-rc3 — 2026-09-24

### Identity presentation and federation

- Federated identities that provide a preferred username but no display name now
  use that username as the initial canonical display name, avoiding empty-name
  profiles for providers that expose only a handle.
- Telegram OIDC keeps the standard `name`, `preferred_username` and `picture`
  claims authoritative while accepting Telegram-specific first/last-name and
  username aliases only as text-presentation fallbacks.
- Removed the legacy Telegram `photo_url` image fallback because those URLs can
  become stale or return 404 after linking. A Telegram presentation refresh now
  clears a stale stored picture when the provider no longer supplies a valid
  standard OIDC picture claim, without discarding the saved display name or
  username.

### Release metadata and documentation

- Synchronized the public release version across `VERSION`, OpenAPI, SDK
  metadata, the handbook, installation examples and release documentation.
- Release instructions and production qualification now derive the active
  release version from `VERSION` instead of embedding an RC number that can
  silently become stale.

## 1.1.0-rc2 — 2026-09-23

### Fixed

- Fixed duplicate canonical identities when a user first authenticated through a
  trusted federated provider and later enrolled local email/password with the
  same verified email. OpenProof now converges that enrollment onto the single
  active canonical identity instead of creating a second account.
- Verified-email convergence now fails closed when the same verified email is
  associated with multiple active identities, or with a suspended/non-authenticating
  identity, rather than guessing which identity should own the new sign-in method.
- Completing signup email verification now establishes an IAL1 browser session,
  so a user does not need to perform a second sign-in immediately after proving
  control of the email address. The OpenAPI response now exposes `session_id`
  and `assurance` consistently with that behavior.

### Documentation and developer tooling

- Added the end-to-end Deployment & Developer Handbook covering installation,
  production setup, OAuth/OIDC integration, Node.js, PHP, C++ and generic HTTP.
- Added machine-readable LLM documentation entry points plus the public,
  read-only OpenProof documentation MCP server and its reproducible source.

## 1.1.0-rc1 — 2026-09-22

### Identity and authentication

- Added public account enrollment, verified email/phone ownership, profile
  self-service, password recovery and passkeys.
- Added self-service connected accounts with explicit linking and protection
  against cross-account transfer.
- Added Google, GitHub, Microsoft, Apple, LinkedIn, Telegram and X federation.
- Added Ethereum SIWE and Farcaster SIWF authentication.
- Added SAML, LDAPS and SCIM enterprise integration.
- Verified-email convergence now reuses one active canonical identity across
  federated and local-email enrollment instead of creating a duplicate identity;
  ambiguous or suspended matches fail closed, and successful signup-email
  verification establishes an IAL1 browser session.

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
- Generates a runnable gateway configuration and collects the protected
  application upstream host, port and TLS mode instead of leaving the production
  gateway disabled.
- Fixes comma-separated provider processing so the final selected provider is
  validated and configured rather than being silently dropped.
- Provider, main and delivery configuration remain editable after installation;
  management edits are backed up and rolled back automatically when they prevent
  the affected service from becoming healthy.
- Setup reruns now reconcile the initialized organization and owner directly
  from PostgreSQL bootstrap state before regenerating configuration, so changing
  an Organization ID during recovery cannot disconnect the service configuration
  from the authoritative database tenant. Existing owner credentials are not
  requested or recreated during resume.
- Placeholder provider credentials such as `0`, `test`, `dummy` or
  `example` are treated as deferred configuration and leave that provider
  disabled instead of allowing a later runtime-startup failure.
- Failed readiness stops the service to avoid an uncontrolled systemd restart
  loop, and a resumed setup proactively pauses an incomplete OpenProof service
  before changing configuration.
- Local readiness probes now send the loopback `X-Forwarded-For` value required
  by deployments with trusted-proxy client-IP handling enabled; setup, status,
  doctor and configuration rollback no longer misclassify a healthy listener as
  unavailable.
- Reserved/test identity domains such as `*.example.com`, `*.test`,
  `*.invalid` and localhost no longer default into a doomed public Let's
  Encrypt flow; interactive setup defaults them to external/deferred TLS.
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
