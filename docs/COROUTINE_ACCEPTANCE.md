# OpenProof — end-to-end coroutine acceptance gate

**State: NOT APPROVED.** The protocol is implementation-independent; no feature may couple OpenProof to any business, application, vendor-specific tenant, GenyCaster or Genyleap deployment.

This document is a **hard release gate**, not a schedule or a claim of completed work. Do not merge or deploy the performance branch based on synthetic benchmark gains or the presence of `co_await` alone.

## Architectural contract

- **Incoming HTTP**: accept, read, dispatch and write must be coroutine-based, bounded, independently cancellable, deadline-aware and secure under adversarial slow clients. Preserve header/body limits, forwarded-IP validation, TLS boundaries and HTTP method/target validation.
- **Application handlers**: request processing must remain nonblocking along any ordinary request path. Keep the core/provider protocol-neutral. The current compatibility `asio::thread_pool` is TEMPORARY and must not be misreported as an end-to-end coroutine migration.
- **PostgreSQL**: asynchronously connect, acquire and release leases; use nonblocking libpq protocol (e.g., `PQsendQueryParams`, `PQconsumeInput`, `PQisBusy`, `PQgetResult`, `PQsocket` with reactor readiness). Protect atomic transactions, rollback, logical consistency, serialization retries, revocation/single-use semantics, cancellation and thread affinity of each `PGconn`. Never suspend while holding a blocking mutex, a `PGresult` borrowed buffer or a database operation whose lifetime may end at suspension.
- **External providers**: async DNS, TCP, TLS, HTTP, OAuth exchanges, Web3/Farcaster RPC, and any enterprise directory/service I/O. Keep certificate/hostname verification and SSRF boundaries. Establish total request deadlines and safely cancel network activity.
- **Proxy**: async DNS/connect/TLS/write/read/shutdown, bounded retries with idempotency rules, independent request cancellation, backpressure, and complete security-context propagation.
- **Crypto/CPU-heavy work**: coroutines do not make Argon2id/scrypt, JWT signing, or WebAuthn verification nonblocking; run bounded compute jobs on a separately sized CPU executor with memory/work limits and rate controls. Avoid starving the socket reactor.
- **Lifetime and concurrency**: completion handlers must hold owning state; no captures of ephemeral coroutine closure state; no unbounded queues, unsafe `this` after stop, missed cancellation, held locks across suspension, concurrent use of one libpq connection or double resumption.

## Automatic static pre-gate

```sh
node scripts/verify-coroutine-coverage.mjs
```

Fails nonzero until every critical boundary has a native coroutine site and the known direct synchronous I/O primitives are absent. `--json` outputs machine-readable evidence. This is deliberately conservative. A green scan is **not approval**; manual and dynamic verification remain mandatory.

## Dynamic release checklist

1. GCC16.2 C++26 clean release build, plus Debug and ASan/UBSan builds, pass on supported environments.
2. Entire test suite, independent OAuth/OIDC/PKCE/JAR/PAR/DPoP, passkey/Web3/evidence, token refresh replay, session revoke, SCIM, email/account lifecycle, tenant isolation and negative security tests pass.
3. End-to-end PostgreSQL disposable-database tests cover transaction atomicity, failed rollback, duplicate processing, overlapping requests, connection pool exhaustion, timeout/cancellation and cross-provider adversarial inputs.
4. Gateway request/response behavior (including Set-Cookie multiples, protected route context binding, hop-by-hop stripping and safe errors) stays byte-compatible where protocol contracts require it.
5. Under forced upstream/database delays and client disconnects, reactor latency stays bounded, no callback crashes, no memory leaks, no deadlock, no uncaught exception, no orphaned request execution.
6. Matched baseline versus optimized OpenProof **at identical revision except the intended optimization**, on isolated CPU and PostgreSQL. Capture warm-up, connection counts, mixed route workloads, 1/8/32/128 concurrency, p50/p95/p99, req/s, RSS, CPU, allocations, errors, timeouts and normalized response correctness in multiple runs.
7. Candidate must improve measured performance materially on the chosen I/O-heavy workloads, with no security regression, no unfair resource amplification, no unacceptable p99/error cost on CPU-limited workloads and no inter-tenant starvation.
8. Third-party neutral module graph and protocol-independence audit pass, including clean startup and absence of product-specific behavior.

## Verified partial checkpoint (2026-10-26)

The previous offloading-only patch built `openproof_gateway_http`, and six focused HTTP CTest integration tests passed. That is not end-to-end coroutine execution. Current work is replacing its callback-based socket accept/read/write with native Boost.Asio awaitables. The migration remains blocked by synchronous libpq, synchronous outbound provider HTTP and synchronous Gateway Proxy, plus transport-neutral application SPIs. The branch must remain unapproved until all gates pass.

## PostgreSQL adapter validation checkpoint — still NOT APPROVED

A separate internal `async_detail::AsyncConnection` adapter now uses
`PQconnectStart/PQconnectPoll` for socket connection state and
`PQsendQueryParams/PQflush/PQconsumeInput/PQisBusy/PQgetResult`
for parameterized SQL, suspending on PostgreSQL socket readiness with Asio.
Every wait shares the operation's absolute deadline. A timeout or I/O error
closes the PGconn rather than placing an indeterminate transaction state back
in a connection pool. Raw SQL, credentials and database error strings are not
included in thrown exception messages. Connection ownership is single-owner;
overlapping operations are forbidden.

**Limitations:** this internal adapter has NOT replaced existing synchronous
repository methods, transaction/retry APIs, connection pooling, credential
rotation, migrations or health checks. Native hostname resolution performed
by libpq may still be synchronous on some platforms. Cancellation behavior
and pool lease ownership need fault-injection validation; nonblocking cannot
be inferred merely from the presence of `co_await`.

The standalone C++26 target `openproof_postgres_async_tests` compiled and
linked on GCC 16.2, but its two tests were **skipped locally** because no
isolated test PostgreSQL URI was supplied. CI must run these tests with the
isolated `OPENPROOF_TEST_POSTGRES` database and fail if it is missing.

These are compatibility foundations only. The release gate remains red.

### Native libpq data-integrity checkpoint

The isolated adapter preserves PostgreSQL SQL NULL distinctly from an empty text
value using `std::optional<std::string>` for both bound SQL parameters and
returned cells. It copies cell values with `PQgetlength` instead of relying
on NUL-terminated strings. A dedicated disposable-DB integration test binds a
NULL parameter and an empty-string parameter into `SELECT $1::text, $2::text`,
preventing silent corruption of account/consent semantics during repository migration.
The test and adaptation are **not sufficient** to approve the repository migration.

### Build integration boundary

The native libpq adapter now has a standalone, ordinary-C++ CMake library
target `openproof_postgres_async_io`, and the PostgreSQL module links against
it without exporting Boost.Asio types in OpenProof domain module interfaces.
The focused `openproof_postgres_async_tests` executable links this same
library rather than recompiling a second copy of the transport. This is a
prerequisite for replacing the legacy synchronous repositories but **does not
yet make their runtime SQL calls nonblocking**. Local GCC16.2 library + test
link passed; the extra nullable-bound-parameter integration test still
requires execution against the disposable CI database.

### Transaction return-to-pool invariant

`AsyncConnection::healthy()` means the physical connection is available;
that does **not** prove it is safe for a different request or tenant.
The new `reusable()` check requires `PQTRANS_IDLE` and no in-flight query
before any future async pool is allowed to recycle a lease. The disposable
PostgreSQL integration suite tests `BEGIN`, rejection of reuse during an
open transaction, and `ROLLBACK` restoring the idle state.
This is an invariant check only; connection leasing and cleanup remain
unmigrated, and this branch is still NOT APPROVED.

### Enterprise LDAP static-gate correction

The coroutine release verifier explicitly flags OpenLDAP's synchronous
`ldap_sasl_bind_s`, `ldap_search_ext_s` and `ldap_unbind_ext_s` call sites
in the Enterprise provider. These were previously omitted from the static
pattern list even though the manual audit identified them. They remain
**blocking** and must be replaced by reactor-driven LDAP operations with
correct TLS validation, cancellation and connection lifetime tests before
release. The verifier continues to fail until the actual adapter and call
paths are converted; **adding a coroutine keyword without eliminating blocking
LDAP does not satisfy this gate**.

### Source coverage: no hidden blocking implementation files

The automated gate scans every `.cpp`, `.cppm`, `.cc` and `.cxx`
implementation under `src/` in addition to the explicitly named eleven
critical execution boundaries. Any unlisted file containing a known
synchronous PostgreSQL, HTTP, LDAP, cURL or OpenSSL transport call causes a
hard failure and appears under `uncoveredBlockingSources` in the JSON output.
This is a *source-level completeness check*, not a runtime proof: function
pointer dispatches, third-party internals, synchronous DNS inside libpq and
CPU-heavy password hashing must also be profiled and manually reviewed.

At this checkpoint the release gate reports **40 known outstanding static
findings across eleven named areas**, including the three explicit synchronous
Enterprise LDAP operations. This number is a count of source-level findings,
not a count of runtime paths, requests or performance regressions.
