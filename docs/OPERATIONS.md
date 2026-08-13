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

## Startup and shutdown

The process applies forward-only checksummed migrations before accepting
traffic. A migration failure prevents startup. `SIGTERM` and `SIGINT` stop the
listener gracefully. Use a termination grace period longer than the configured
HTTP deadline (15 seconds by default).

Required production secrets must be delivered by `env:NAME` or `file:/path`
references; never commit them into TOML. At minimum protect:

- the master derivation secret (prefer a read-only `file:` mount over a
  process-wide environment value);
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

The current release does not support online rotation of the master derivation
secret. Treat its compromise as a controlled migration requiring explicit
re-encryption and revocation tooling, not as a configuration-only restart.

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
process start it runs `opp check-config`. It also runs 600 mixed concurrent
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
