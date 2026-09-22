# Installing OpenProof

The recommended production installation path is the Genyleap bootstrap installer:

\`\`\`bash
curl -fsSL https://genyleap.com/install/openproof | sudo sh
\`\`\`

The bootstrap script detects the supported Debian/Ubuntu release and CPU
architecture, downloads the matching prebuilt OpenProof runtime bundle, and
verifies it against the published SHA-256 manifest. The installer never compiles
OpenProof on the target host and never installs a compiler, CMake, Boost, or other
build dependencies. If a matching prebuilt bundle is unavailable, installation
fails explicitly instead of falling back to a source build.

## Supported systems

The packaged installer currently targets:

- Ubuntu 24.04 or newer;
- Debian 13 or newer;
- AMD64 and ARM64;
- systemd-based hosts.

Source builds remain available as a separate, explicit developer workflow and
are never selected automatically by the production bootstrap installer.

## Self-hosted operation and data responsibility

OpenProof is software you operate on infrastructure you control; installing it
does not create a managed Genyleap identity service. Normal OpenProof runtime does
not require a Genyleap-hosted backend for the identity database, credentials,
sessions, or cryptographic keys.

The operator remains responsible for server administration, access control,
backups, upgrades, legal/regulatory obligations, and any third-party identity,
mail, RPC, TLS, database, or delivery services it chooses to configure.

The installer and upgrade command may contact Genyleap and GitHub to resolve and
download verified OpenProof release artifacts.

- Product: https://genyleap.com/products/openproof
- Privacy: https://genyleap.com/privacy
- Terms: https://genyleap.com/terms-of-use

## What the setup wizard configures

The setup wizard can provision the entire single-host deployment:

1. identity domain and organization;
2. local or external PostgreSQL;
3. cryptographic keys and protected secret files;
4. initial owner account and one-time TOTP enrollment;
5. verification email through authenticated SMTP, local Postfix, or an existing
   HTTPS delivery webhook;
6. Google, GitHub, Microsoft, Apple, LinkedIn, Telegram, X, Ethereum and
   Farcaster credentials when selected;
7. WebAuthn relying-party origin;
8. the protected application upstream used by the OpenProof gateway;
9. Nginx and Let's Encrypt, an existing certificate, or an external TLS ingress;
10. systemd services and final readiness checks.

Interactive validation is local to the current field. Invalid values are shown
with red feedback and accepted values with green feedback. A field is retried up
to three times; after three unsuccessful attempts the operator can retry that
same field from a fresh three-attempt cycle or exit setup. Exiting preserves the
bundle and system changes already completed, but does not mark the host as fully
configured.

Provider credentials are requested only for providers selected during setup. A
blank provider selection means "configure later". Provider credentials are not
immutable: after installation use `sudo openproof config providers` to add,
replace, or remove them. OpenProof backs up the previous provider file and rolls
back the edit if the service cannot become ready after the change. Placeholder
credentials may satisfy local non-empty validation but do not prove that the
external provider will accept them.

The shared federation callback is derived from the configured identity domain:

\`\`\`text
https://identity.example.com/auth/federated/callback
\`\`\`

## Bundle-only installation

To install or update the verified prebuilt bundle without running the setup wizard:

\`\`\`bash
curl -fsSL https://genyleap.com/install/openproof | sudo sh -s -- --no-setup
sudo openproof setup
\`\`\`

Install an exact version:

\`\`\`bash
curl -fsSL https://genyleap.com/install/openproof | \
  sudo sh -s -- --version 1.1.0
\`\`\`

Select the newest release candidate explicitly:

\`\`\`bash
curl -fsSL https://genyleap.com/install/openproof | \
  sudo sh -s -- --channel rc
\`\`\`

The default \`auto\` channel chooses the newest stable release, and falls back to
the newest published release when no stable release exists yet.

## Non-interactive installation

Automation systems can pre-supply setup values through environment variables and
then run:

\`\`\`bash
curl -fsSL https://genyleap.com/install/openproof | \
  sudo -E sh -s -- --non-interactive
\`\`\`

Important variables include:

\`\`\`text
OPENPROOF_DOMAIN
OPENPROOF_ORGANIZATION_NAME
OPENPROOF_ORGANIZATION_ID
OPENPROOF_OWNER_SUBJECT
OPENPROOF_ADMIN_PASSWORD
OPENPROOF_DATABASE_MODE
OPENPROOF_DATABASE_URL
OPENPROOF_EMAIL_MODE
OPENPROOF_TLS_MODE
OPENPROOF_TLS_EMAIL
OPENPROOF_PROVIDERS
\`\`\`

Provider-specific credentials use the same names documented in
[PROVIDER_SETUP.md](PROVIDER_SETUP.md).

The optional gateway upstream can be supplied non-interactively with
`OPENPROOF_GATEWAY_UPSTREAM_HOST`, `OPENPROOF_GATEWAY_UPSTREAM_PORT` and
`OPENPROOF_GATEWAY_UPSTREAM_TLS`. The interactive defaults are
`127.0.0.1:18080` without TLS; these values can later be changed with
`sudo openproof config main`.

## Email delivery

OpenProof deliberately separates verification issuance from message delivery.

\`\`\`text
OpenProof -> authenticated delivery boundary -> SMTP / Postfix / custom webhook
\`\`\`

During setup choose one of:

- **Authenticated SMTP** — OpenProof's local delivery adapter submits to a
  configured SMTP relay through Postfix.
- **Local Postfix / direct MX** — useful for operators who manage their own mail
  reputation, PTR/rDNS, SPF, DKIM and DMARC.
- **HTTPS delivery webhook** — integrates an existing notification service.
- **Configure later** — public email/password self-service remains disabled until
  delivery is configured.

See [DELIVERY_WEBHOOK.md](DELIVERY_WEBHOOK.md) for the delivery contract.

## Operations

The bundle installs the \`openproof\` management command:

\`\`\`bash
openproof info
openproof status
openproof status --full
sudo openproof doctor

sudo openproof start
sudo openproof stop
sudo openproof restart
openproof logs --lines 200
openproof logs --follow

sudo openproof config
sudo openproof config providers

sudo openproof update
sudo openproof upgrade --channel rc
sudo openproof upgrade --version 1.1.0

sudo openproof backup /var/backups/openproof.dump
sudo openproof restore /var/backups/openproof.dump POSTGRES_URL

sudo openproof uninstall
sudo openproof uninstall --purge-data
\`\`\`

\`openproof info\` summarizes the installed version, configured identity domain,
service state, local paths, self-hosted data model, and operator responsibility.
\`openproof doctor\` checks the binary, configuration, systemd service, local
readiness, PostgreSQL, Nginx, public readiness and OIDC discovery. Uninstall keeps
\`/etc/openproof\` by default; \`--purge-data\` also removes local OpenProof
configuration and credentials, but never drops PostgreSQL databases automatically.

## Security

The installer never writes provider secrets or cryptographic material into the
repository or public configuration examples. Generated secrets are stored under
\`/etc/openproof/credentials\` with restricted ownership and permissions.
Bootstrap owner passwords are accepted through the process environment only and
are not written to disk by the installer.

For production hardening and backup/restore procedures, continue with
[OPERATIONS.md](OPERATIONS.md).
