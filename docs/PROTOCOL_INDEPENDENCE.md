# Protocol independence and customer isolation

OpenProof is an independently deployable identity and OAuth/OIDC platform.
**No specific publisher, organization, product, OAuth client, application
redirect URI, or Farcaster application is privileged by the core runtime.**

## Core and integration boundaries

- Core source in `src/` and the `apps/opp` composition root implement
  reusable identity, OAuth, OIDC, session, consent, account security and
  administration services. All built-in UI speaks in terms of the requesting
  **application** and the OpenProof **identity**, not a named customer's brand.
- Issuer URL, tenant identity, OAuth clients, application names, redirect URIs,
  authentication providers, and delivery mechanisms are deployment/application
  configuration or managed through the standard administration interfaces.
- Optional providers such as Farcaster/Wallet authentication are provider
  adapters, not implied ownership of an identity or automatic integration
  with any Farcaster client application. They require explicit configuration.
- Genyleap-hosted installer/doc/release URLs are publisher distribution
  channels. They do not supply a required runtime identity backend, database
  or privileged client. Self-hosted OpenProof must not depend on them for
  normal authentication, OAuth flows or authorization.

## Historical client migration compatibility

Some older releases incorrectly bundled customer-specific OAuth registrations
as migration files 0020–0022. Their exact original SQL is **not** part of the
general schema upgrade sequence. They are retained unchanged in
`migrations/legacy/` for verification of checksums already recorded in
`openproof.schema_migrations` by prior installations.

- **Fresh installations:** only root-level schema SQL executes. No tenant
  or OAuth client is silently seeded, even when an organization happens to
  use a historically named identifier.
- **Existing installations:** applied legacy SQL hashes remain verifiable
  against the immutable archived originals. This release does not delete,
  disable or rewrite previously provisioned OAuth clients or tenant data.
- **In-place upgrades with old root-level files:** exact byte-for-byte matches
  to archived SQL are recognized as historical and never executed again.
  A mismatch is a hard failure; do not auto-correct customer data.
- **Manual client provisioning:** operators create clients under their own
  tenant using the standard application and OAuth-client registration APIs.
  Any product-specific deployment recipe belongs in the product's own
  operations repository, never in reusable OpenProof schema migrations.

Deploy the whole migration directory, **including** the checksum-only legacy
archive. Installing a new binary over an incomplete old migration directory
is not a supported upgrade. Verify the migration inventory and backup the
database before a controlled in-place upgrade.

## Enforcement

`python3 scripts/check-protocol-neutrality.py` runs in both CI and the
release validation job. It rejects publisher-specific runtime strings,
customer-specific executable root migrations, historical SQL tampering,
and loss of the checksum-only legacy archive. This guard is intentionally
strict: adding new client-specific source or migration contents requires
moving the integration into the appropriate external project.

See also `docs/ARCHITECTURE.md`, `docs/OPERATIONS.md`, and
`scripts/verify-migration-artifacts.py`.
