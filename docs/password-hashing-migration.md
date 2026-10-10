# Password hashing policy (scrypt + Argon2id)

OpenProof supports two formats for local-account password hashes:

- Legacy `scrypt$v1$...`: OpenSSL scrypt applied to HMAC-SHA256(pepper, password).
- `$argon2id$v=19$...`: libsodium Argon2id applied to the **same** HMAC-SHA256(pepper, password) prehash.

**The format of the STORED hash, not the current policy, controls verification.**
The preferred algorithm only controls **new** passwords, password resets,
and best-effort rehash after successful credential verification. Existing
scrypt users can authenticate when the preference is Argon2id, and existing
Argon2id users can authenticate when the preference returns to scrypt.

## Choose on a new installation

Interactive `sudo openproof setup` asks which password algorithm to use.
Non-interactive setup accepts `OPENPROOF_PASSWORD_HASH_ALGORITHM=scrypt|argon2id`.
The default is `scrypt` for backward-compatible unattended installs.
The generated `[security]` section includes:

```toml
password_hash_algorithm = "argon2id" # or "scrypt"
```

For source installation, `libsodium-dev` is installed with the other build
dependencies. A build without libsodium still supports all existing scrypt
passwords, but rejects an Argon2id policy at startup and in `opp check-config`.

## Change after installation

Run `sudo openproof config hashing`. The command displays a warning,
requires an explicit `CHANGE` confirmation, backs up the configuration,
checks it with the installed binary, restarts the service, checks readiness,
and automatically restores the previous configuration if readiness fails.

Operators can also edit `[security].password_hash_algorithm` in
`sudo openproof config main`. The override
`OPENPROOF_PASSWORD_HASH_ALGORITHM`, if present, takes precedence.

### Safety consequences — read before switching

1. A policy change **does not instantly rewrite the database**. The user's
   plaintext password cannot be recovered from an existing password hash.
2. On successful credential verification, old hashes may be upgraded using
   a conditional `UPDATE ... WHERE password_hash=old_hash`, which prevents an
   in-flight migration from clobbering a concurrent password reset.
3. With password + TOTP authentication, rehashing happens only once the TOTP
   ceremony was fully accepted. A failed opportunistic rehash never blocks
   a successful login: the original hash remains valid. Recovery-code login
   uses a password-only pre-check before consuming the second factor, so it
   does NOT opportunistically rehash in that early step; the account remains
   compatible and is upgraded on a later eligible login/password change.
4. Password changes/resets use the newly selected preferred algorithm.
5. **Do not roll back to an OpenProof binary without Argon2id support after
   any Argon2id hashes exist.** It could no longer verify those accounts.
   Switching the preference back to scrypt is safe ONLY while the binary
   still knows how to verify Argon2id.
6. **Never rotate, discard, or replace the password pepper** simply to
   switch algorithms. Both encodings depend on the same stable dedicated
   pepper. Pepper rotation requires a separate explicit versioned migration.
7. Do not delete or modify existing hashes, and do not bulk-convert them
   without plaintext passwords (that is mathematically impossible).
8. Benchmark KDF latency, concurrent logins, RAM, and login-abuse controls.
   Argon2id currently uses 64 MiB of RAM per hash and 3 iterations,
   and a successful first-time migration may perform two KDF operations.
9. While both KDFs coexist, their unequal runtimes may make account-existence
   timing behavior harder to normalize, even with dummy verification. Preserve
   edge and identity-based rate limits, monitor auth latency, and do not claim
   equal-time verification across both work factors.
10. Backup the password table, matching pepper and configuration **securely**
   before any production deployment. Keep these backups access-controlled.

The password store requires no SQL schema migration: `password_hash` is
a bounded text field that already holds both self-identifying encodings.
This migration does not modify OAuth/OIDC signing, sessions, existing TOTP
secrets, or external identity provider credentials.

## Verification

Automated regression tests cover legacy scrypt hashing, new Argon2id hashing,
cross-policy verification, incorrect passwords, rejection of excessively
costly encoded hashes, configuration selection, and invalid algorithm values.

Deployment: build and test in an isolated worktree, stage a replacement
release, and carry out an explicit maintenance/rollout with canary login tests.
**Never replace the running server binary merely because the branch compiles.**
