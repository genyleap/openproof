# Installing OpenProof

The recommended production installation path is the Genyleap bootstrap installer:

\`\`\`bash
curl -fsSL https://genyleap.com/install/openproof | sudo sh
\`\`\`

The bootstrap script detects the supported Debian/Ubuntu release and CPU
architecture and prefers the matching GitHub Release package, verified against
the published SHA-256 manifest. If no prebuilt release exists yet, Ubuntu hosts
automatically install the qualified build dependencies, compile OpenProof, package
it locally as a .deb, and continue into the same setup wizard.

## Supported systems

The packaged installer currently targets:

- Ubuntu 24.04 or newer;
- Debian 13 or newer;
- AMD64 and ARM64;
- systemd-based hosts.

Source builds remain available for development and unsupported distributions.

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
8. Nginx and Let's Encrypt, an existing certificate, or an external TLS ingress;
9. systemd services and final readiness checks.

Provider credentials are requested only for providers selected during setup. The
shared federation callback is derived from the configured identity domain:

\`\`\`text
https://identity.example.com/auth/federated/callback
\`\`\`

## Package-only installation

To install a release without running the setup wizard:

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

The package installs the \`openproof\` management command:

\`\`\`bash
sudo openproof status
sudo openproof doctor
sudo openproof config
sudo openproof config providers
sudo openproof update
sudo openproof backup /var/backups/openproof.dump
sudo openproof uninstall
\`\`\`

\`openproof doctor\` checks the binary, configuration, systemd service, local
readiness, PostgreSQL, Nginx, public readiness and OIDC discovery.

## Security

The installer never writes provider secrets or cryptographic material into the
repository or public configuration examples. Generated secrets are stored under
\`/etc/openproof/credentials\` with restricted ownership and permissions.
Bootstrap owner passwords are accepted through the process environment only and
are not written to disk by the installer.

For production hardening and backup/restore procedures, continue with
[OPERATIONS.md](OPERATIONS.md).
