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

### Libpq parameter NUL-boundary regression

The native async libpq adapter now refuses embedded NUL bytes in text
parameters before invoking `PQsendQueryParams`, whose text inputs are
NUL-terminated by libpq. Without this validation an attacker-controlled
value could be truncated silently (a correctness and identity-isolation risk).
The isolated database test verifies the value is rejected while the clean
connection remains available for future safe queries. This does not replace
negative application-level authorization and tenant-isolation tests.

### Coroutine-aware inbound HTTP handler dispatch (experimental)

The Beast listener now recognizes `openproof::gateway::http::CoroutineHttpHandler`
at runtime,
launches `handleAsync(HttpRequest)` with `asio::co_spawn` on its bounded
handler executor, and marshals the completed HTTP response back to the
socket reactor. A native coroutine suspends without occupying a handler
thread; legacy `HttpHandler::handle` remains isolated on the executor until
all synchronous repository and provider implementations are removed.

The focused HTTP wire tests exercise **more than eight outstanding
asynchronous handler calls with only eight handler workers** (a genuine
`steady_timer` suspension rather than a blocking sleep), plus a provider
exception thrown after suspension, which must produce a sanitized HTTP 500.
Both legacy blocking-handler and parser/connection-limit regression tests
are retained.

This boundary is **NOT the full migration**: application OAuth/account
handlers and the production PostgreSQL repository SPI still call
synchronous methods. The coroutine-aware listener must not be advertised
as an async identity platform until their real I/O dependencies are
converted and the release gate passes. A successfully built but unused
coroutine adapter is insufficient evidence.

The wire suite also includes a real TCP loopback proxy integration: a
`CoroutineHttpHandler` delegates to `BeastProxyTransport::sendAsync` and
returns the upstream response without ever calling its synchronous
`handle()` fallback. It proves the listener and existing asynchronous
Beast proxy transport can compose through an Asio executor.

Passing this adapter test is **not equivalent** to converting the
OpenProof Gateway's authorization, OAuth, account and storage call chains.
Those interfaces remain subject to the NOT_APPROVED release gate.

### Transport-neutral Gateway forwarding state machine (experimental)

The independent `openproof.gateway` module now prepares an **owned**
`GatewayForwardPlan` after **all existing** routing, rate limiting, delegated
sender proof verification, policy authorization, privileged header stripping,
Trusted Context sealing and service discovery have finished. This plan cannot
be constructed by transport clients. The same Gateway domain methods own
circuit-breaker selection, retry policy and response security headers for both
the legacy synchronous `handle()` and the asynchronous transport path, so
the security and tenant logic is not copied into Beast.

`CoroutineGatewayAdapter` resides **only** in the
`openproof.gateway.http` transport adapter. It drives the shared plan via
`co_await BeastProxyTransport::sendAsync`. The no-authentication gateway
composition in `apps/opp/main.cpp` now uses this real async forwarding path
when its listener is not wrapped by synchronous HTTP middleware. The
Gateway+Beast integration test uses this adapter for an actual TCP roundtrip,
retaining Trusted Context response and cookie assertions.

**Unfinished:** the production HTTP middleware chain
(OAuth/account/administration/metrics, and protected repository/provider
authentication) still exposes synchronous handlers. The async plan's
authorization phase remains synchronous until the PostgreSQL repository,
provider and session SPIs are converted. This is a step toward the end-to-end
implementation, not an approval.

### Async Gateway with authenticated Prometheus middleware

The `openproof.gateway.http` transport adapter now contains
`CoroutineMetricsAdapter`, an optional wrapper for a
`CoroutineHttpHandler` behind the existing `MetricsHttpApi` facade.

- **Exact `/metrics` requests remain in the original MetricsHttpApi**
  (its constant-time bearer-token verification, supported-method checks,
  fixed no-store response headers and bounded/low-cardinality counters
  remain authoritative).
- All other requests are passed to the coroutine fallback via
  `co_await handleAsync`. The facade's observer receives the same method,
  response status and elapsed time as the legacy HTTP instrumentation.
- In the `opp` composition root this bridge activates automatically only
  when metrics is enabled **and the underlying handler supports async**.
  Authentication-enabled stacks that have not been migrated continue to
  use their existing synchronous middleware until migrated, so no auth
  decision or protected route is bypassed.
- A focused Beast/TCP integration regression verifies that an unauthenticated
  metrics scrape remains HTTP 401, a valid scrape stays HTTP 200, and a
  non-metrics request reaches an actually suspended Coroutine handler,
  with exactly one response observation.

This is a partial transport/middleware migration. Production repository,
OAuth account and enterprise provider blocking operations still fail the
independent release acceptance gate.

### Native PostgreSQL coroutine bounded-polling and SQL integrity

The isolated asynchronous libpq transport now checks an **absolute
connection deadline during every PQconnectPoll iteration**, including
the `PGRES_POLLING_ACTIVE` state, and yields to its Asio executor when
libpq requests immediate repolling, rather than monopolizing a worker.
The connection is discarded if polling fails. This addresses a potential
runaway active-poll CPU loop; it does **not** eliminate possible blocking
name resolution inside libpq, and the normal repository SPI remains
synchronous.

Before sending `PQsendQueryParams`, the adapter also rejects SQL text
containing embedded NUL and parameter counts beyond libpq's signed-int
bound. An isolated disposable-PostgreSQL regression checks SQL NUL
rejection and that a validated connection remains reusable afterward.

The updated `openproof_postgres_async_tests` executable compiles and
links with GCC 16.2 locally; the **new** disposable-database assertion
has not passed CI until a subsequent workflow executes it. The
whole-project Coroutine gate remains NOT APPROVED.

### Async metrics failure accounting and isolation regression

The instrumented `CoroutineMetricsAdapter` records the same bounded
HTTP status-class and duration aggregates as the legacy Metrics HTTP
middleware. When an asynchronous downstream handler throws **after a
suspension**, the adapter records the eventual sanitized HTTP 500 outcome
and rethrows so the Beast listener preserves the existing error boundary.
Failures inside the observer itself are ignored: instrumentation must
never change a legitimate downstream HTTP 200 into a 500. The old
synchronous middleware now likewise counts downstream exceptions as HTTP
500 instead of silently omitting them. Focused TCP tests exercise both
conditions, keeping raw paths/tokens out of metric labels.

This does **not** convert the synchronous identity or storage repositories.
No release approval is implied by metrics middleware compatibility.

The security regression now also composes all three actual layers —
`BeastHttpServer` -> `CoroutineMetricsAdapter` ->
`CoroutineGatewayAdapter` — with a protected Gateway route. Without an
authenticated session, the request must be rejected with HTTP 401 before
contacting any upstream, despite the metrics middleware taking the native
coroutine path. A separately authenticated `/metrics` request continues
to use the original metrics authorization guard, and must not increment the
protected API observation count. Neither wrapper may synthesize or bypass
authorization in the independent OpenProof Gateway core.

### Aborted transaction disposal (native coroutine libpq)

The disposable PostgreSQL integration suite now intentionally opens
`BEGIN`, runs a SQL statement that fails, and verifies that the connection
is **physically invalidated** before any future lease can see PostgreSQL's
`PQTRANS_INERROR` state. This is a critical invariant for the eventual
nonblocking connection pool: stale transaction state from one user or
organization must never become another tenant's session. The test does not
assert that the legacy synchronous repository is already migrated.

### Total Gateway upstream retry deadline (coroutine and compatibility)

Gateway retry attempts now share **one monotonic upstream time budget**,
starting after trusted-context sealing and endpoint discovery. The core owns
this deadline inside `GatewayForwardPlan` (which cannot be constructed by a
transport caller), and calculates the remaining time independently for each
attempt. Both the legacy `ProxyTransport::send` loop and the native
`CoroutineGatewayAdapter::handleAsync` loop pass this remaining budget to
the actual transport instead of resetting it between retries. If a legacy
upstream ignores its timeout and completes after the deadline, the Gateway
rejects even a successful response with a sanitized 504 and does not contact
a second upstream. The core regression suite tests late successes, exhausted
retry budgets, and shrinking budgets on fast failures. A separate actual
Gateway/Beast/TCP regression proves that a slow first upstream cannot trigger
a fresh full-budget retry to an otherwise healthy second upstream.
The network transport already uses one deadline for
DNS/connect/TLS/write/read within each attempt.

**Scope:** this change bounds the Gateway's *upstream forwarding sequence*;
it does not establish a whole-request deadline for slow PostgreSQL, OAuth,
session authorization, or unrelated provider calls. Cross-layer cancellation,
end-to-end deadlines, and the remaining 40 static findings still block
release approval.

### Async PostgreSQL result-copy limits (experimental)

The internal `AsyncConnection::query()` now limits the application-owned
copy of SQL results to 8 MiB of non-NULL cell payloads and 250,000 cells,
checks the absolute deadline during row materialization, and closes the
physical connection if a result violates either bound. A disposable DB
regression intentionally returns an oversized string and asserts both a
sanitized exception and rejection of the connection for future pool leases.
The limits are conservative transport defaults, not protocol fields.

`PQsetSingleRowMode` is now enabled immediately after the parameterized
send, and `PQconsumeInput`/`PQisBusy`/`PQgetResult` advance each individual
`PGRES_SINGLE_TUPLE` without buffering all rows in one `PGresult`.
Rows are retained only until the terminal `PGRES_TUPLES_OK` arrives; an
error *after* some rows discards all accumulated data and invalidates the
connection. Tests cover multiple rows, late streaming SQL errors, and an
oversized single field that exceeds the copy limit.

**Remaining memory-safety gap:** a single enormous row or field can still
be buffered internally by libpq before its length is checked; the 8 MiB
application-owned result limit does not provide a strict wire-level buffer
ceiling. Reactor-driven cancellation, a bounded in-flight network buffer,
backpressure, resource accounting, and actual async repository integration
are still required before end-to-end acceptance.


### Coroutine-native PostgreSQL pool permit and lease adapter

An experimental internal `AsyncConnectionPool` now uses an Asio
`experimental::concurrent_channel` of exactly N move-only connection
permits instead of a condition-variable wait. `acquire()` suspends with an
acquisition deadline and returns an exclusive move-only lease. A null permit
creates its physical libpq connection asynchronously; a healthy idle lease
returns the same connection, while a failed query or in-flight transaction
returns only a null permit so the next owner must establish a fresh physical
connection. A failed connection attempt also returns its permit automatically.
The channel supports multiple executor workers without unsynchronized queue
access. The pool lifetime is retained by outstanding leases.

The tests now check capacity/deadline validation and restoration of pool
permits after a failed libpq connection **without requiring a database**.
The disposable database suite checks bounded nonblocking acquisition,
lease return after a timed-out waiter, and fail-closed physical reconnection
both after a still-open transaction and after a SQL error inside an explicit
transaction. Every recycled connection is now subject to an asynchronous,
deadline-bounded PostgreSQL `DISCARD ALL` before the next lease is handed out;
this is required because `PQTRANS_IDLE` alone does **not** reset session
variables, role state, prepared objects, temporary relations or advisory
locks. An isolated-database test sets a session marker on one lease and
asserts it does not survive into the next lease. Failed session reset closes
the physical connection and fails the acquisition rather than passing an
untrusted session to another tenant. Invalid pool capacities and nonpositive
deadlines are rejected before any network activity.

**Not release approved:** this internal pool is deliberately not wired to the
legacy synchronous repository SPIs or the active production service. It
retains a live connection string in process memory for reconnection. Connection
string handling, per-tenant fairness, coordinated shutdown, and transaction
cancellation across the public repository and HTTP boundaries need further
design and tests. The existing synchronous pool and repository operations
remain forbidden by the full migration gate.


### CI run preservation while migration is incomplete

GitHub Actions now keeps a running complete CI/benchmark run for the named
performance branch instead of cancelling it on every follow-up commit.
Pending runs can still be coalesced by GitHub's concurrency scheduler. Mainline
and ordinary PR workflows retain cancellation of superseded runs. A
successful isolated PostgreSQL/Gateway/E2E build job does not override the
deliberately failing static completeness gate or authorize deployment.


### Native session token SQL critical section (in integration)

An internal `AsyncSessionSql` now executes the existing PostgreSQL session
`UPDATE ... RETURNING` use/last-seen transition and compare-and-swap digest
rotation as **real** asynchronous `AsyncConnection::query` calls. Its fixed
production table is `openproof.sessions`; the separate test-only selector
targets only `pg_temp.sessions` so isolated integration tests cannot mutate
production schema objects. Digest inputs are verified as exactly 64
hexadecimal characters before query submission, and all user-controlled
values remain SQL parameters. A successful use can return the 16-column
session data contract only when the updated state remains active. Expired,
revoked or unknown tokens return no authenticated row; rotation requires the
expected old digest and checks both inclusive expiry boundaries atomically.
A single lookup never renews idle time.

The test fixture uses a session-local temporary table with the real schema's
sixteen session columns; it checks a successful touch, token rotation,
old-digest replay denial, inclusive idle deadline, bad-digest rejection,
persistent expired state, and no late identity disclosure. The test still
requires an isolated PostgreSQL database and its result must be verified in
CI. This is genuine nonblocking SQL for the **session command layer**, not
yet an implementation of the public `session::SessionRepository` interface.
The required type restoration into `session::Session`, application-service
async SPI, complete session CRUD/revocation and production HTTP wiring remain
unfinished. Do not merge or deploy based on this checkpoint.


The same coroutine SQL command layer also implements idempotent
single-session revocation and identity-scoped bulk revocation. Single-session
revoke distinguishes an original successful transition, an already-revoked
row, an unknown identifier and an expired row, matching the legacy API's
authorization consequences. The bulk operation is one atomic
`UPDATE ... RETURNING` on the identity ID; it never crosses tenant identity
boundaries. A disposable-PG temporary-table regression verifies that a revoked
token cannot be used, repeated revocation is idempotent, a missing row is not
confused with success, and revoking one identity's sessions does not revoke an
unrelated identity's session. These are internal SQL primitives only; real
request handlers and public SessionService still require coroutine wiring.

The two-query idempotent revoke path now shares one monotonic time budget:
its follow-up state lookup cannot silently reset the caller's deadline after
the initial update. This is a scope-limited SQL deadline, not yet request
cancellation propagated from the HTTP socket.
