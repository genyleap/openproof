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
