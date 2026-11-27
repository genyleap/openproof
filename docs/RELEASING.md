# Release process

OpenProof releases are built and published by GitHub Actions. Release assets are
created from a tag only after the tag matches the repository \`VERSION\` file.

## 1. Prepare the release

Update:

- \`VERSION\`;
- \`CHANGELOG.md\`;
- public documentation when behavior or configuration changed.

Then merge the release commit to \`main\` and wait for **CI** to pass.

CI validates:

- shell scripts;
- the OpenAPI contract;
- Developer Portal behavior;
- the JavaScript SDK;
- the GCC 16 / C++26 release build;
- the CTest suite;
- Debian package generation;
- standalone runtime bundle generation.

## Stable schema consolidation (mandatory before coroutine migration release)

During development, numbered SQL migrations are incremental review and test
units. They are not the intended permanent fresh-install layout of the
completed OpenProof protocol.

Before the first stable release of the completed migration:

- Freeze the accepted schema and consolidate the development-only changes into
  one versioned, tenant-neutral fresh-install baseline. Do not ship the
  development sequence as the normal fresh-install execution path.
- Inventory all schema versions and exact SQL checksums already distributed
  in public release artifacts, including release candidates. Keep a separate
  supported upgrade path and immutable checksum manifest/archive for those
  versions. Never execute historical customer-specific SQL on a fresh database.
- Teach the migrator to distinguish empty installations, known upgrade
  histories, partial installations and unknown/drifted schemas under a common
  migration lock. Fail closed on ambiguous history or mismatched checksums;
  never infer that a database is current from a version number alone.
- Verify schema equivalence on disposable PostgreSQL databases (tables,
  columns, defaults, constraints, foreign keys, indexes, functions and
  privileges), and run the full authentication/session/tenant/OAuth/credential
  and coroutine acceptance suites against both clean baseline and supported
  upgrade paths. Test concurrent bootstrap, rollback on failure, repeat
  execution, preservation of existing data and tampered histories.
- Verify packaged AMD64/ARM64 installs and upgrades, and explicitly document
  the supported upgrade matrix and backup/restore procedure. The stable
  release is not approved until this evidence is recorded.

Do not rewrite applied migration files or delete migration ledger rows merely
to make the source tree smaller. Published compatibility material is distinct
from the new baseline and may be distributed as a separate upgrade bundle
only once the migrator and packaging support that arrangement.

After the stable baseline is released, its contents are immutable. Subsequent
schema evolution uses reviewed versioned upgrade steps; a later baseline
consolidation must preserve the same compatibility guarantees.

**Current development state:** the opt-in consolidated baseline and atomic
ledger-aware migrator have been implemented and validated separately on
disposable PostgreSQL. Their combined integration with generation-safe
verification and package parity must pass CI before development acceptance.
The release remains NOT_APPROVED; numbered compatibility SQL stays intact.

## Published schema inventory

`docs/schema-release-inventory.json` pins the release-tag objects, peeled
commits, exact SQL paths and SHA-256 checksums for v1.1.0-rc1 through rc7.
It is reproducible using `python3 scripts/inventory-release-schema.py --check`
from a complete Git checkout. The CI static job verifies those pinned tags.

The inventory includes historical customer-specific migrations solely as
compatibility evidence, not as authorization to execute them. It records
source-tag contents, not the independently downloaded release artifacts.
Before consolidating the fresh-install schema, verify actual supported
release packages against their tagged inventories using the artifact verifier;
preserve old ledger checksums and isolate the upgrade path. New published
tags must be explicitly added to the inventory. Do not silently regenerate
the recorded history to accommodate moved tags.

### Verify published package migration parity

Download the named release assets and its SHA256SUMS from the official
release. The checker verifies complete package digests against the published
SHA256SUMS before comparing SQL against the independently pinned tag, without
checking out or executing historical SQL:

    python3 scripts/verify-migration-artifacts.py --release-tag v1.1.0-rc7 \
      --sha256sums SHA256SUMS \
      --deb openproof_1.1.0-rc7_amd64.deb \
      --bundle openproof_1.1.0-rc7_linux_amd64.tar.gz

Repeat for each supported tag and architecture. The checker verifies exact
relative paths and checksums, including historical root versus legacy
locations. Unknown tags and ambiguous checksums fail closed. This is a
migration parity check, not binary provenance or runtime acceptance.
The current-source packaging checks continue to use `--source`.

### Atomic schema upgrades

The PostgreSQL migrator checks the complete recorded ledger, including archived
tenant-specific records, before applying pending SQL. An unknown or modified
record fails closed; downgrading an upgraded database is not supported.
The entire batch and ledger bootstrap share one READ COMMITTED transaction
and the migration advisory lock. Pending migration SQL must be trusted,
transaction-compatible release SQL without explicit transaction control.
Take a verified backup and stop application traffic during schema upgrades;
this is not an online migration or a substitute for upgrade testing.

### Development baseline round-trip

Run `python3 scripts/verify-schema-baseline.py` on a PostgreSQL 16-capable
test runner. The script creates a private temporary cluster with no TCP
listener and no external connection string, applies only root-level neutral
schema migrations, generates a single SQL candidate, and reconstructs a
second empty database. It compares full schema dumps (including grants,
constraints and indexes, excluding database-owner differences) and fresh
data/sequence dumps. Historical customer SQL is excluded. The dedicated CI
job runs this round-trip independently of the C++ build.

Use `--emit` to obtain the candidate SQL after a successful comparison.
Use `--output-dir <new-directory>` to generate the SQL and exact ordered
checksum manifest. A candidate may be placed under a test copy of the
migration directory as `baseline/schema.sql` and `baseline/checksums.txt`.
The migrator verifies all bytes, restores it only when the OpenProof schema
namespace did not exist before bootstrap, and writes the original numbered
migration ledger in the same transaction. On a recorded installation it
continues using numbered migrations and never restores the snapshot.
The runtime candidate is not generated by the release packaging scripts.

For development packages only, set OPENPROOF_SCHEMA_BASELINE_DIRECTORY to
the round-tripped candidate directory produced by the verifier. Both DEB
and Linux bundle builders validate the exact schema and ordered manifest
against the numbered source files, then verify both baseline artifacts
inside the completed package. Without the opt-in variable, the ordinary
package format remains unchanged. The CI builds both formats separately.
This does not authorize a public release or removal of numbered upgrades:
that requires a frozen final schema, verified upgrade policy and complete
coroutine acceptance.

The CI runtime upgrade verifier reconstructs each pinned historical release
schema in a private PostgreSQL cluster, inserts neutral profile, membership
and session fixtures, preserves historical ledger checksums and timestamps,
then invokes the actual C++ migrator twice. It compares the resulting schema
with the fresh-install schema and verifies profile backfill, verified contact
claims, membership and session state. Historical customer SQL is never
executed; historical root seed ledger records are simulated, so this does
not certify arbitrary customer-specific data transformations.
The candidate is not yet the production installation baseline: the final
schema must be frozen, upgrade history and existing-data transformations
must be tested, and the migrator, installation packaging and release gate
must be updated together.

## 2. Tag

For a release candidate:

\`\`\`bash
version="$(tr -d '[:space:]' < VERSION)"
git tag -a "v${version}" -m "OpenProof ${version}"
git push origin "v${version}"
\`\`\`

For a stable release:

\`\`\`bash
git tag -a v1.1.0 -m "OpenProof 1.1.0"
git push origin v1.1.0
\`\`\`

The Release workflow refuses a tag whose name does not equal \`v$(cat VERSION)\`.

## 3. GitHub Release artifacts

The tag workflow builds on native AMD64 and ARM64 GitHub runners and publishes:

\`\`\`text
openproof_<version>_amd64.deb
openproof_<version>_arm64.deb
openproof_<version>_linux_amd64.tar.gz
openproof_<version>_linux_arm64.tar.gz
SHA256SUMS
\`\`\`

Tags containing \`-rc\`, \`-beta\` or \`-alpha\` are published as GitHub
prereleases. Other matching tags are normal releases.

The public bootstrap endpoint at
\`https://genyleap.com/install/openproof\` resolves releases from GitHub and
verifies the selected prebuilt runtime bundle against \`SHA256SUMS\` before installation.

## 4. Verify after publishing

On a clean supported VM:

\`\`\`bash
curl -fsSL https://genyleap.com/install/openproof | sudo sh
sudo openproof doctor
\`\`\`

For a prerelease:

\`\`\`bash
curl -fsSL https://genyleap.com/install/openproof | \
  sudo sh -s -- --channel rc
\`\`\`

Do not promote a release until the full setup wizard, public readiness endpoint
and OIDC discovery pass on a clean host.
