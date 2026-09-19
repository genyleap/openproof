# OpenProof Linux deployment templates

These files are reviewed starting points for a single-node identity deployment:

- `openproof.service` runs an unprivileged, filesystem-restricted `opp` process;
- `nginx-openproof.conf` terminates TLS and overwrites the trusted client-IP
  header rather than forwarding an attacker-controlled chain;
- `openproof.toml.example` composes account, OAuth/OIDC and protected API
  surfaces;
- `openproof.env.example` lists optional environment-only feature credentials
  without containing usable ones;
- `verification-delivery-postfix.php`, `openproof-delivery.service` and
  `openproof-delivery.env.example` provide an optional loopback-only email adapter
  for deployments that operate a local Postfix MTA.

Install the release binary as `/opt/openproof/bin/opp`, copy `migrations/` to
`/opt/openproof/migrations`, configuration to `/etc/openproof/openproof.toml`
and have the target secret-store/KMS agent mount these exact read-only files:

- `/run/openproof/secrets/master.key` — at least 32 random bytes;
- `/run/openproof/secrets/credential-encryption.key` — exactly 32 bytes after
  optional trailing line-ending removal (generate with `openssl rand -base64 24`);
- `/run/openproof/secrets/password-pepper.key` — at least 32 random bytes;
- `/run/openproof/secrets/recovery-code-pepper.key` — at least 32 random bytes;
- `/run/openproof/secrets/audit-chain.key` — at least 32 random bytes;
- `/run/openproof/secrets/oauth-client-secret.key` — at least 32 random bytes;
- `/run/openproof/secrets/database.url` — the PostgreSQL connection string;
- `/run/openproof/secrets/verification-webhook.token` — delivery bearer;
- `/run/openproof/secrets/metrics-bearer.token` — at least 32 random bytes for
  the private Prometheus scraper;
- `/run/openproof/secrets/oidc-private.pem` — active RSA private key.

They should be regular files readable by the `openproof` process and by no
unrelated account. The unit runs `opp check-config` before startup, so missing
secret mounts and invalid key references fail before the listener opens. This
file boundary works with a host secret agent, CSI-style mount or an init step;
do not write secret values into the TOML or image. Validate the edited Nginx
configuration with `nginx -t`, execute `opp check-config --config
/etc/openproof/openproof.toml`, and validate the service unit with
`systemd-analyze verify` on the target distribution before enabling either.

The unit intentionally grants no writable filesystem path. OpenProof state is
in PostgreSQL and logs go to journald. If a deployment adds local state, grant
only its exact directory with a reviewed `ReadWritePaths=` override.

### Optional local Postfix delivery adapter

When direct transactional email is appropriate for the deployment, install a local
Postfix instance that accepts SMTP only from loopback, then copy
`verification-delivery-postfix.php` to `/opt/openproof/delivery/`, copy the delivery
unit to `/etc/systemd/system/openproof-delivery.service`, and create
`/etc/openproof/delivery.env` from `openproof-delivery.env.example`.

Point `[account].delivery_host` at `127.0.0.1`, port `18444`, with TLS disabled only
for this same-host loopback hop. Keep `delivery_authorization` backed by the same
secret file referenced through `OPENPROOF_DELIVERY_TOKEN_FILE`. The adapter validates
the bearer, accepts only email verification purposes, and submits the message to the
loopback SMTP listener. It does not require setuid/setgid helpers, so the systemd unit
retains `NoNewPrivileges=true`.

Before sending public mail, configure forward-confirmed reverse DNS, SPF, DKIM and
DMARC for the envelope/header domain. If the host has IPv6 but no IPv6 PTR, do not let
the MTA prefer IPv6 until reverse DNS is provisioned. See
[`docs/DELIVERY_WEBHOOK.md`](../docs/DELIVERY_WEBHOOK.md) for the complete checklist.

Do not enable `trust_proxy_client_ip` unless the listener remains loopback-only
and every connection is forced through the proxy template (or an equivalent
ingress that overwrites `X-Forwarded-For` with one valid address). For RFC 8705
mTLS, use an ingress capable of generating OpenProof's authenticated,
request-bound forwarding envelope; ordinary Nginx must strip those headers as
shown here.

Follow `docs/OPERATIONS.md` for bootstrap, probes, backup/restore, rotation,
qualification and incident response. These templates do not replace target
distribution hardening, certificate automation, database HA or secret-store
policy.

The credential-key file and `credential_encryption_key_version` are one
deployment unit. Rotate them only with the offline `opp rekey-totp` runbook;
changing either one during an ordinary restart makes persisted TOTP credentials
unreadable. Keep all five persistent-key mounts independent from `master.key`;
that separation is the prerequisite for the offline `opp rotate-master-key`
ceremony documented in `docs/OPERATIONS.md`. For a legacy deployment, use
`opp materialize-persistent-keys` only while the fleet is stopped, import its
five owner-read-only hexadecimal outputs into the secret store, and reference
them with `hexfile:` so they decode back to the exact legacy binary values.

The public Nginx template returns `404` for `/metrics`. Scrape the loopback
listener directly from a local Prometheus agent (or through a separately
authenticated private management ingress) and send the exact bearer from
`metrics-bearer.token`. Never publish this endpoint on the identity hostname.
