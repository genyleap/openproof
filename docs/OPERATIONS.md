# OpenProof operations runbook

This runbook covers the minimum safe operating contract for the `opp` identity
service. OpenProof listens only on loopback HTTP; a trusted reverse proxy must
terminate public TLS and preserve request/response headers without allowing
clients to forge trusted ingress metadata.

Production reverse proxies should set `trust_proxy_client_ip=true` and overwrite
`X-Forwarded-For` with the directly observed client IP. Never pass through or
append a client-supplied chain: OpenProof deliberately accepts one address only
and fails closed otherwise.

## Health probes

- `GET /health/live` returns `200` when the process and HTTP worker are alive.
- `GET /health/ready` performs a PostgreSQL health check. It returns `200` only
  when the service can reach its database, otherwise `503`.

Neither endpoint returns configuration, version, database, or error details.
Use liveness only to restart a stuck process and readiness to control traffic.

## Metrics and alerting

Prometheus exposition is disabled by default. Generate a dedicated credential,
mount it through the secret store and enable the bounded endpoint:

```toml
[operations]
metrics_enabled = true
metrics_bearer_token = "file:/run/openproof/secrets/metrics-bearer.token"
metrics_maximum_series = 512
```

The public Nginx template deliberately returns `404` for `/metrics`. A local
Prometheus agent can scrape the loopback listener without placing the token on
the command line:

```yaml
scrape_configs:
  - job_name: openproof
    authorization:
      type: Bearer
      credentials_file: /run/prometheus/secrets/openproof-metrics.token
    static_configs:
      - targets: ["127.0.0.1:18443"]
```

The endpoint returns `401` for a missing/wrong token and authenticates `GET` and
`HEAD` only. It exports `openproof_process_starts_total`,
`openproof_metrics_scrapes_total`, `openproof_http_requests_total` and
`openproof_http_request_duration_seconds`. Built-in HTTP metrics use a fixed
method/status-class matrix and a lock-free request fast path; the configured
ceiling applies to extensible registry series. A non-zero
`openproof_metrics_updates_dropped_total` means an extensible update was rejected
and requires investigation before raising the reviewed bound. Request metrics
are intentionally limited to method and status class; never add raw path,
identity, tenant, client, token or IP labels.

At minimum alert on an absent `up{job="openproof"}`, a sustained non-zero 5xx
ratio, and latency against the product SLO. Example expressions:

```promql
sum(rate(openproof_http_requests_total{status_class="5xx"}[5m]))
/
clamp_min(sum(rate(openproof_http_requests_total[5m])), 1e-9) > 0.01

histogram_quantile(0.95,
  sum by (le) (rate(openproof_http_request_duration_seconds_bucket[5m])))
```

Rotate the metrics bearer like any other independent integration credential:
update the scraper secret and OpenProof mount as one controlled deployment,
verify an authenticated `HEAD /metrics`, then retire the old version. The
current endpoint accepts one credential, so overlap requires the deployment
orchestrator to coordinate the restart and scraper update.

## Startup and shutdown

The process applies forward-only checksummed migrations before accepting
traffic. A migration failure prevents startup. `SIGTERM` and `SIGINT` stop the
listener gracefully. Use a termination grace period longer than the configured
HTTP deadline (15 seconds by default).

Required production secrets must be delivered by `env:NAME`, `file:/path` or
binary-safe `hexfile:/path` references; never commit them into TOML. At minimum
protect:

- the master derivation secret (prefer a read-only `file:` mount over a
  process-wide environment value);
- the dedicated 32-byte TOTP credential-encryption key and its configured
  version;
- the dedicated password, recovery-code, audit-chain and OAuth-client-secret
  keys; these must remain independent of the master;
- the OIDC RSA private signing key file;
- `OPENPROOF_BOOTSTRAP_PASSWORD` only during one-time bootstrap;
- optional SCIM, verification-webhook, mTLS-forwarding and upstream-provider secrets.

After the secret-store/KMS agent has mounted the selected versions, but before
the service is allowed to start, run:

```bash
opp check-config --config /etc/openproof/openproof.toml
```

This validates the closed configuration schema and resolves all configured
secret references without opening the listener or contacting dependencies. The
deployment template wires this command into `ExecStartPre`.

## Backup

Use PostgreSQL-native encrypted storage and retention controls around the dump.
The script refuses to overwrite an existing backup and creates a SHA-256 sidecar.

```bash
export OPENPROOF_DATABASE_URL='postgresql://openproof@db/openproof'
./scripts/backup-postgres.sh /secure/backups/openproof-2026-08-13.dump
```

Back up the database and secret-store versions together. A database backup
without the matching master/signing keys cannot restore authentication
continuity; a key backup without the database exposes credentials without
providing recoverability.

## Restore drill

Restore is intentionally accepted only into a database with zero user tables in
all non-system schemas. The script verifies the checksum before opening the target
and uses one transaction, so it never cleans or overwrites an existing database.

```bash
export OPENPROOF_RESTORE_DATABASE_URL='postgresql://openproof@db/openproof_restore_drill'
export OPENPROOF_RESTORE_ACK=YES_RESTORE_TO_EMPTY_DATABASE
./scripts/restore-postgres.sh /secure/backups/openproof-2026-08-13.dump
```

After restore, start `opp` against the restored database with a copy of the
matching secret versions, verify `/health/ready`, Discovery/JWKS, login, token
refresh, logout, audit-chain verification and a representative protected API.
Never use the restore drill target as production without a separately reviewed
cutover plan.

## Incident response

For a suspected credential or token compromise:

1. remove traffic with readiness/routing controls;
2. preserve database, audit outbox and reverse-proxy logs;
3. revoke affected sessions, OAuth clients or token families through the admin
   APIs rather than editing database rows;
4. rotate the exposed external/provider secret;
5. validate the HMAC audit chain and determine the exposure window;
6. restore traffic only after login, refresh-replay, introspection and gateway
   checks pass.

The current release supports a controlled **offline** master-key retirement.
Never change only `token_signing_key`: use the master-key runbook below so
master-derived transient state is invalidated atomically and the database
journal remains bound to the active version and key fingerprint.

Routine retirement and compromise recovery are not identical. If the dedicated
durable keys were generated independently, a master compromise is contained to
master-derived transient state and the retirement invalidates it. If a legacy
master was exposed, every legacy-derived/materialized password, recovery, TOTP,
audit and OAuth-client key must also be treated as exposed. Materialization is a
compatibility bridge, not compromise remediation; require password/recovery-code
and client-secret resets, TOTP re-enrollment/rekey as appropriate, and a new
audit-chain trust anchor under the reviewed incident plan.

## TOTP credential-key rotation

OpenProof supports offline, atomic rotation of the dedicated AES-256-GCM key
used for persisted TOTP seeds. This is a separate operation from master-key
retirement: TOTP rekey decrypts and re-encrypts durable seed envelopes, while
master retirement invalidates transient bearer/challenge state after every
durable credential and integrity key has been separated.

Before the first rotation, configure an explicit version-1 key. Existing
deployments that omit it use the compatible version-1 key derived from the
master. Then use this exact procedure:

1. Remove OpenProof from traffic, stop every `opp server` instance that can
   reach the database, and verify no server process remains.
2. Take a PostgreSQL backup plus checksum and record the active master,
   credential-key and OIDC-key versions together.
3. Generate and mount a new secret-store value containing exactly 32 bytes
   after optional line-ending removal, for example:

   ```bash
   openssl rand -base64 24 > /run/openproof/secrets/credential-encryption-v2.key
   chmod 0400 /run/openproof/secrets/credential-encryption-v2.key
   ```

4. Validate the currently active configuration, then exercise every row in a
   transaction that is always rolled back:

   ```bash
   opp check-config --config /etc/openproof/openproof.toml
   opp rekey-totp \
     --config /etc/openproof/openproof.toml \
     --new-key-ref file:/run/openproof/secrets/credential-encryption-v2.key \
     --new-key-version 2 \
     --dry-run
   ```

5. If and only if the dry run succeeds, commit the same operation explicitly:

   ```bash
   opp rekey-totp \
     --config /etc/openproof/openproof.toml \
     --new-key-ref file:/run/openproof/secrets/credential-encryption-v2.key \
     --new-key-version 2 \
     --acknowledge-offline
   ```

6. Before restarting, atomically change both
   `credential_encryption_key` and `credential_encryption_key_version` to the
   new reference/version. Run `opp check-config`, start one instance, verify
   readiness and perform a password+TOTP login, then restore the fleet and
   traffic.
7. Inspect `openproof.credential_key_rotations` and retain the previous key and
   pre-rotation backup until a restore drill using them has passed.

The command takes a deployment-wide advisory lock and an exclusive TOTP-table
lock, decrypts and freshly encrypts every row with identity-bound associated
data, refuses unknown versions, wrong/identical keys and repeated target
versions, and commits data plus journal in one transaction. It never prints key
material. `--dry-run` and `--acknowledge-offline` are mutually exclusive.

After a committed rekey, never roll back only the configuration: version-2
rows are unreadable with version 1. Operational rollback is a database restore
to the pre-rotation backup together with the matching old configuration and
secret versions. If commit fails, the transaction leaves every row and journal
entry unchanged.

## Master-key rotation

`token_signing_key` is the master for transient session, OAuth-token and
protocol-challenge digests. OpenProof can retire it offline without resetting
passwords, recovery codes, TOTP credentials, the audit chain or confidential
OAuth client secrets, provided those five durable uses already have independent
keys.

For an existing version-1 deployment that still derives durable subkeys from
the master, perform this one-time separation ceremony first:

1. Remove OpenProof from traffic, stop every `opp server` connected to the
   database, take a PostgreSQL backup, and record all active secret versions.
2. As the service account, create an existing, empty, non-symlink directory
   owned by that account and accessible only to it (`0700`). Export the exact
   legacy-derived values without exporting the master itself:

   ```bash
   install -d -m 0700 /run/openproof/materialized-v1
   opp materialize-persistent-keys \
     --config /etc/openproof/openproof.toml \
     --output-directory /run/openproof/materialized-v1 \
     --acknowledge-secret-export
   ```

   The command refuses non-empty, linked, foreign-owned or group/world-accessible
   directories. It creates `credential-encryption.key`, `password-pepper.key`,
   `recovery-code-pepper.key`, `audit-chain.key` and
   `oauth-client-secret.key` as owner-read-only hexadecimal files and never
   prints their values.
3. Move those files into the target secret store, then configure version 1 with
   `hexfile:` references for `credential_encryption_key`, `password_pepper`,
   `recovery_code_pepper`, `audit_chain_key` and `oauth_client_secret_key`.
   Keep `master_key_version = 1`. Run `opp check-config`, start one instance,
   and verify password+TOTP login, recovery, client authentication and audit
   verification. Stop it again before rotation.

   ```toml
   [security]
   token_signing_key = "file:/run/openproof/secrets/master-v1.key"
   master_key_version = 1
   credential_encryption_key = "hexfile:/run/openproof/secrets/credential-encryption.key"
   credential_encryption_key_version = 1
   password_pepper = "hexfile:/run/openproof/secrets/password-pepper.key"
   recovery_code_pepper = "hexfile:/run/openproof/secrets/recovery-code-pepper.key"
   audit_chain_key = "hexfile:/run/openproof/secrets/audit-chain.key"
   oauth_client_secret_key = "hexfile:/run/openproof/secrets/oauth-client-secret.key"
   ```
4. Preferably use the TOTP runbook to replace the materialized legacy TOTP key
   with a newly generated independent credential key. The other four values are
   now operationally separated, but remain cryptographically derivable by
   anyone who had the legacy master; retain that provenance in the secret-store
   inventory and incident model.

New deployments should configure all five dedicated keys from the beginning
and skip materialization. Then retire the active master as follows:

1. Generate and mount a new master of at least 32 random bytes under a new
   secret-store version. Do not change the running configuration yet.
2. Exercise the full transaction and roll it back:

   ```bash
   opp rotate-master-key \
     --config /etc/openproof/openproof.toml \
     --new-key-ref file:/run/openproof/secrets/master-v2.key \
     --new-key-version 2 \
     --dry-run
   ```

3. Review the reported counts. If and only if the dry run succeeds, commit the
   identical operation:

   ```bash
   opp rotate-master-key \
     --config /etc/openproof/openproof.toml \
     --new-key-ref file:/run/openproof/secrets/master-v2.key \
     --new-key-version 2 \
     --acknowledge-offline
   ```

4. Update **only** `token_signing_key` and `master_key_version` to the new
   values. Keep all five durable key references unchanged. Run `opp
   check-config`, start one instance, verify readiness and fresh password/TOTP
   and OAuth-client logins, then restore the fleet and traffic.
5. Inspect `openproof.master_key_rotations`. Retain the backup and matching old
   secret set until a restore drill has passed.

The serializable transaction takes a deployment advisory lock and exclusive
locks on transient parent tables, invalidates authentication transactions,
sessions, account challenges, incomplete passkey-registration ceremonies,
authorization codes, token families, device authorizations and PAR objects,
then commits their exact counts with the new version and a non-secret
fingerprint. Every existing session/token/challenge is therefore expected to
fail after cutover, and a browser that was part-way through registering a
passkey must request fresh registration options. Existing passkey credentials,
passwords, recovery codes, TOTP envelopes, audit records and OAuth clients
remain intact.

At startup, OpenProof compares the configured version and master fingerprint
with the latest journal row. A config-only rollback or stale instance is
rejected before accepting traffic. Operational rollback after a committed
rotation means restoring the pre-rotation database **and** its matching old
configuration and complete secret set together; never roll back only one side.

## OIDC signing-key rotation

OIDC rotation supports verification overlap across a rolling restart:

1. generate a new RSA private key (at least 2048 bits) in the secret store with
   a new unique key ID;
2. export the current public key only into
   `previous_signing_keys_directory/<old-kid>.pem`;
3. deploy the new `key_id` and `signing_key` while retaining the old public key;
4. verify JWKS publishes both IDs and newly issued ID Tokens use the new ID;
5. keep the old public key published for at least the maximum issued JWT
   lifetime plus clock skew and cache propagation;
6. remove the old public PEM in a later reviewed deployment.

Never place an old private key in the previous-key directory. OpenProof parses
only public PEM there and rejects symbolic links and duplicate/active key IDs.

## Repeatable load smoke

The dependency-free Node harness exercises a read-only endpoint with bounded
concurrency and reports throughput plus p50/p95/p99/max latency. Run it only
against an environment explicitly approved for load testing:

```bash
OPENPROOF_LOAD_ORIGIN=https://identity.staging.example.com \
OPENPROOF_LOAD_PATH=/.well-known/openid-configuration \
OPENPROOF_LOAD_REQUESTS=10000 \
OPENPROOF_LOAD_CONCURRENCY=50 \
node scripts/load-smoke.mjs
```

The harness refuses plaintext/non-HTTPS origins, cross-origin paths, unbounded
request counts and unbounded concurrency. Production promotion still requires
product-shaped mixes for authorize/token/UserInfo/introspection and observation
of CPU, memory, PostgreSQL pool saturation, upstream latency and error budgets.

## Identity-platform E2E

The dependency-free E2E driver uses a real `opp` process, an empty PostgreSQL
database, a locally trusted TLS reverse proxy, an authenticated HTTPS delivery
webhook and a protected upstream. It exercises signup, email verification,
password reset, IAL2 owner login, admin provisioning, Authorization Code + PKCE,
ID Token signature/claim validation with Node's independent crypto stack,
UserInfo, introspection, gateway scope/audience enforcement, refresh replay,
restart persistence and overlapping OIDC signing-key rotation. Before every
process start it runs `opp check-config`. The real edge also proves that
unauthenticated metrics fail with `401`, authenticated Prometheus exposition
works and no path/identity/token enters the output. It also performs legacy persistent-key
materialization, dry-run and committed TOTP rekey, dry-run and committed full
master retirement, proves the retired master cannot restart, and proves migrated
password/TOTP and OAuth client credentials still work. It then runs 600 mixed concurrent
reads by default across readiness, Discovery, JWKS, UserInfo,
introspection and the protected gateway, reporting throughput and p50/p95/p99.

Create a dedicated empty database whose name contains a standalone `e2e`
segment. The driver refuses databases with existing user tables and never drops
or truncates its target:

```bash
createdb openproof_e2e_local

export OPENPROOF_E2E_POSTGRES='postgresql:///openproof_e2e_local'
export OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE
node scripts/e2e-identity-platform.mjs
```

For a request-count-based product-shaped soak on an approved target class, use
a fresh E2E database and raise the bounded mix explicitly (maximum 1,000,000
requests and concurrency 1,000):

```bash
export OPENPROOF_E2E_LOAD_REQUESTS=100000
export OPENPROOF_E2E_LOAD_CONCURRENCY=50
node scripts/e2e-identity-platform.mjs
```

Observe CPU, memory, PostgreSQL connections/locks and the protected upstream;
throughput from the local harness is not a capacity commitment.

The gateway token-bucket defaults to a burst capacity of 1,000, refill of 100
requests/second and 100,000 tracked keys. These closed-schema values are
deployment-tunable under `[gateway]`, each bounded to 1,000,000. Raising them
without fleet-wide edge throttling increases abuse and memory-pressure risk;
lowering them below legitimate aggregate traffic produces expected `429`
responses. Record the selected values with every load result.

## Coverage-guided boundary fuzzing

The opt-in GCC fuzz profile instruments implementation units for HTTP targets,
redirect URIs, trace context, password hashes, encoding and JOSE/JWK parsing.
Its mutation queue retains only inputs that reveal previously unseen execution
features and persists them under the artifact directory for later resume. It
runs with ASan and UBSan:

```bash
OPENPROOF_FUZZ_RUNS=100000 \
OPENPROOF_FUZZ_ARTIFACTS=/secure/fuzz/openproof \
./scripts/qualify-fuzzing.sh
```

Any uncaught exception is written as `crash-*`; sanitizer findings terminate
the process with a non-zero result. Preserve the exact artifact, compiler,
module fingerprint and command for triage. Longer release campaigns should use
millions of executions and merge reviewed learned corpus files back into
`fuzz/corpus/`; this local harness does not replace independent protocol review.

The database is retained for audit or a representative-data restore drill.
Inspect it before explicitly removing it. Temporary keys and self-signed test
certificates are created under a process-owned temporary directory and removed
after shutdown; they are never suitable for deployment.

The complete qualification command additionally requires a separate disposable
database for destructive PostgreSQL integration fixtures:

```bash
export OPENPROOF_TEST_POSTGRES='postgresql:///openproof_qualification'
export OPENPROOF_TEST_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_IS_DESTRUCTIVE
export OPENPROOF_E2E_POSTGRES='postgresql:///openproof_e2e_qualification'
export OPENPROOF_E2E_DATABASE_ACK=YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE
./scripts/qualify-production.sh
```

Reviewed Linux starting points for the service unit, TLS ingress, runtime
configuration and environment file are in [`deploy/`](../deploy/README.md).
They must be validated on the target distribution and edited for its hostnames,
certificate automation, upstream, organization and secret store.
