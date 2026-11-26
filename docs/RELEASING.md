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

**Current development state:** the existing migrator still executes the
root-level numbered SQL sequence and validates the legacy archive. The
consolidated baseline and upgraded migrator are a pending release requirement,
not a capability of this branch. Keep current migration artifacts intact
until the new installation and upgrade paths are verified.

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
