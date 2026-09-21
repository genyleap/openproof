# Deployment templates

For supported Debian/Ubuntu hosts, prefer the packaged installer documented in
[../docs/INSTALLATION.md](../docs/INSTALLATION.md):

```bash
curl -fsSL https://genyleap.com/install/openproof | sudo sh
```

This directory contains the generic Linux deployment templates used by that
packaging flow and available to operators who need a custom deployment.

- `openproof.service` — hardened systemd unit for the OpenProof server.
- `nginx-openproof.conf` — TLS reverse-proxy example for a loopback-only OpenProof listener.
- `openproof.toml.example` — production-oriented configuration template.
- `openproof.env.example` — environment-only settings.
- `providers.env.example` — external provider credentials.
- `openproof-delivery.service`, `openproof-delivery.env.example` and
  `verification-delivery-postfix.php` — optional same-host verification delivery adapter.

## Suggested layout

Install the built runtime under `/opt/openproof`:

```text
/opt/openproof/
  bin/opp
  migrations/
  openproof.toml
  delivery/
```

Keep operational configuration under `/etc/openproof` and secret material in a
secret manager or read-only runtime mount such as `/run/openproof/secrets`.

The included systemd unit intentionally grants no writable application path.
OpenProof persists durable state in PostgreSQL and writes logs to journald.

## Before enabling

1. Replace example hostnames, certificate paths, organization IDs and upstreams.
2. Mount every required secret with owner-only permissions.
3. Validate configuration:

```bash
/opt/openproof/bin/opp check-config --config /opt/openproof/openproof.toml
nginx -t
systemd-analyze verify /etc/systemd/system/openproof.service
```

4. Keep the OpenProof listener on loopback and terminate public TLS at a trusted
   ingress.
5. Do not publish `/metrics`; scrape it from a private authenticated path.
6. Review the full [operations guide](../docs/OPERATIONS.md) before production use.

## Secrets

Do not commit credentials to TOML, environment examples or deployment manifests.
Use secret references such as `file:/run/openproof/secrets/...` and keep provider
credentials outside the repository.

The public templates are starting points, not a replacement for target-specific
hardening, certificate automation, PostgreSQL HA, backup policy or secret-store
controls.
