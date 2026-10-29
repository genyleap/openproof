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

The first GCC 16.2 CI build of the native session SQL test identified a
third-party Boost.Asio coroutine-frame allocation diagnostic:
`-Wmismatched-new-delete` in a large inlined test coroutine, with the
allocator originating inside Asio's `aligned_alloc` implementation. The
warning is now demoted from error to warning **for that one test source only**
so it stays in build logs. Production compilation and all other source files
retain the original `-Werror` policy. This is a compiler/allocator warning
mitigation, not evidence that the new SQL tests have passed yet.


### Bounded bulk-session revocation count

The native async bulk-revocation statement now uses one data-modifying CTE,
`WITH changed AS (UPDATE ... RETURNING 1) SELECT count(*) FROM changed`,
instead of returning one identity/session identifier per affected row.
Previously, a sufficiently large `RETURNING id` result could exceed the
adapter's 8 MiB / 250,000-cell copy budget **after** the database had already
committed the modification. The scalar count remains part of the same atomic
statement, is strictly parsed as an unsigned integer, and requires only one
client-visible row regardless of the number of sessions revoked. An isolated
PostgreSQL regression exercises 2,048 sessions, an idempotent second call,
and a different identity left untouched.


### Native async session SQL command coverage

The internal `AsyncSessionSql` SQL command layer now also implements active
session insertion (`add`), 16-column identity-scoped and last-seen-sorted
listing, session count and expiry purging. The insertion uses bound parameters,
validates session IDs, digest, assurance/factor ranges, timestamps and positive
idle timeout, and preserves SQL NULL in optional user-agent/remote-address
fields. Bulk expiry deletion uses a data-modifying CTE with a scalar count,
matching the safe bounded response shape of the bulk-revoke fix. The isolated
temporary-table test verifies insert/list ordering, NULL fields, inclusive
expiry purging, and rejection of an invalid digest without modifying the table.
These methods complete the **internal SQL command coverage**, not the
public coroutine session SPI, domain object materialization, or production
integration. A session list that exceeds the transport's result cap still
fails closed; a paginated client-facing API is needed before deployment.


### Storage-to-domain session row boundary

A synchronous, deterministic `AsyncSessionSql::decodeRow` now converts the
native libpq adapter's fully owned sixteen-column result into a typed
`SessionSnapshot` with numeric assurance, factor, state and timestamps,
SQL NULL-safe optional fields, and an owned hexadecimal token digest. It
rejects invalid PostgreSQL boolean text, invalid digest encodings, missing
required columns, invalid enum ranges, impossible timestamp order, invalid
idle timeout and inconsistent revoked-state timestamps. A DB-independent
negative test exercises valid and intentionally malformed rows. Domain
`session::Session::restore` still must run after this storage validation
when the actual repository interface is migrated.

### Coroutine SQL-to-domain session restoration (module boundary)

The storage module now exports a `PostgresSessionDomainAdapter::restore()`
function taking an **owned** sixteen-column SQL result. Its implementation
calls the native `AsyncSessionSql::decodeRow` validator and the actual
`session::Session::restore` aggregate constructor. A malformed digest,
revocation state, timestamp, row shape or client metadata fails closed with
a sanitized `Internal` error and **never** yields a usable authenticated
session. Unlike a new duplicate session type, the restored result is the
same C++ module-defined `session::Session` used by the synchronous
repositories, OAuth and HTTP layers.

A separate `openproof_postgres_domain_tests` binary imports the actual
`openproof.storage.postgres` and `openproof.session` C++ modules to
verify valid active/revoked restoration and malformed-row rejection without
needing a database. This is a real cross-module seam, but public
`SessionRepository` and `SessionService` remain synchronous and still
must be migrated; the new adapter must not be counted as production
end-to-end coroutine acceptance.

### First domain-typed native coroutine PostgreSQL repository path

An experimental `CoroutinePostgresSessionRepository` now lives in the
real `openproof.storage.postgres` C++ module, next to (but separate from)
the legacy synchronous `PostgresSessionRepository`. Its native
`use()`, `find()`, `add()`, `rotate()`, `revoke()`, `revokeAll()`, `list()`,
`purgeExpired()`, and `size()` suspend on a bounded
`AsyncConnectionPool::acquire()` and execute `AsyncSessionSql` calls with a
deadline. Lookup and list results restore **real domain
`session::Session`** objects through `PostgresSessionDomainAdapter`.
A missing/revoked/expired digest is denied as `AuthenticationFailed`;
an unavailable database results in a sanitized `Unavailable`, with no
exception leaked to a route handler. The coroutine owns all identity/digest
argument values across suspension. A module-importing regression verifies
two successive failed connection attempts without touching a live database.

This is **not a production request-path migration** yet. Additional
methods and a coroutine-native `SessionService`, OAuth consent and
authentication handler integration, shared cancellation budgets, lifecycle
shutdown and extensive DB integration tests are required before this
repository replaces the synchronous interface. The live deployment remains
untouched.

### Isolated real-schema coroutine session repository regression

A dedicated test now exercises the **real domain-typed repository** end to
end against a new, disposable, CI-owned `openproof_coroutine_ci` database,
including applying the project SQL migrations, creating two test identities,
issuing a session, reading and touching it, rotating its digest, rejecting
old-token replay, revoking twice, rejecting the revoked digest, revoking all
sessions for one identity while preserving another, and purging expired rows.

The database setup is intentionally impossible to run against an arbitrary
configured connection string: the test enforces the exact local CI-only URI
and a second explicit acknowledgement. CI creates that disposable database
in its own isolated PostgreSQL instance immediately before the dedicated
test step; the generic CTest pass skips this destructive fixture when those
environment variables are absent. A passing SQL fixture alone is not enough;
these assertions verify the real exported C++ domain types and the actual
Asio/libpq pool through the full call chain. The test has **not** passed yet
until the new branch CI completes.

This is still not an authenticated HTTP request-path migration. Neither
synchronous `SessionService` nor other domain repositories/providers may be
counted as complete.

### GCC 16 coroutine allocation warning: scoped test-only mitigation

The isolated CI build at `cca2290` compiled the **production**
`coroutine_session_repository.cpp` with `-Werror` after eliminating
shadowed names and separating synchronous record preparation from the
awaitable insert. Its remaining failure was the already observed GCC 16
false-positive `-Wmismatched-new-delete` in an inlined Boost.Asio
coroutine in a GoogleTest translation unit. Exactly the two new coroutine
**test sources** have `-Wno-error=mismatched-new-delete` to preserve
the warning in logs; **production and all other diagnostics retain
`-Werror`**. The new isolated real PostgreSQL full-lifecycle test remains
unapproved until it actually passes.

The same isolated fixture now also checks **live-format repository
interoperability**: it inserts an active session through the original
synchronous `PostgresSessionRepository`, reads and touches the bearer from
the new coroutine repository, revokes that row using the coroutine path,
and verifies that the legacy synchronous repository immediately refuses
reuse of the revoked token. The test is intentionally sequential across
the reactor/synchronous boundary and never calls a blocking repository
method from within an Asio worker coroutine. This verifies durable session
format compatibility, not thread-level throughput or full service migration.

For the reverse direction, the fixture inserts a session through the
**coroutine** repository and checks the existing synchronous repository
can authenticate it, then revokes it through the synchronous path and
checks that the coroutine repository denies its bearer. Thus creation,
validation and revocation are checked in both cross-implementation directions
against the same isolated real PostgreSQL schema.

### Isolated C++ module test link boundary

The CI build of `b3a1180` compiled the actual coroutine PostgreSQL
repository and the module-importing domain tests, then failed only at
linking the independent test executable. Storage's transitive Evidence
static library uses Boost.JSON, whose out-of-line implementation is linked
by HTTP binaries but was not present in this standalone test target.
The focused test target now compiles the existing
`src/authentication/http/boost_json.cpp` implementation translation unit
directly, without linking unrelated HTTP services or changing the
production executable. No Boost.JSON package version is silently mixed,
and there is exactly one implementation TU per test executable.

### Boost.Asio co_spawn result compatibility in the test harness

The `4b9db21` isolated CI run linked the domain binary dependencies and
reached the interoperability test source. Boost 1.88 `co_spawn(use_future)`
requires a default-constructible result type for its exception path, while
`foundation::Result<session::Session>` is intentionally not
default-constructible. The test now awaits that Result inside a `void`
coroutine and reports only the denial assertion back to GoogleTest. The
domain Result type was not weakened or given a synthetic default Session.


### VPS-only validation without noisy GitHub Actions (2026-10-27)

The experimental branch's ordinary GitHub CI now remains restricted to
`main` pushes, pull requests and manual dispatch; the extra
`native-coroutine.yml` workflow is manual-dispatch only. Work-in-progress
changes are committed **locally** and not pushed per edit. One final
consolidated push can follow an actual passing local verification, without
automatically starting the branch's workflows.

The Asio-based coroutine session repository has been moved out of the
exported `openproof.storage.postgres` C++ module and into the conventional
`openproof_postgres_async_repository` library. The core storage module
contains no Asio declarations, preventing the GCC 16 duplicate Asio TLS
symbol encountered when module-importing GoogleTests included Asio headers.

For real local DB tests, `python3 scripts/ci/test-local-coroutine-postgres.py`
uses Debian `pg_virtualenv -t` on the dedicated localhost **55432** port,
not the system-managed PostgreSQL instance. It verifies the port is unused,
creates the temporary PostgreSQL cluster with disposable credentials,
checks the real `data_directory` lives in `/tmp/pg_virtualenv.*`,
creates a disposable role/database, runs the real domain repository CTest
and destroys the temporary cluster on exit. The C++ test enforces the same
directory check before applying any migration. Neither the script nor the
local test may be used with a production database.

Acceptance remains **NOT_APPROVED** until a complete local build, real DB
regressions, full request-path coroutine migration, security checks and
full-workload performance comparisons pass.

### Native coroutine session bearer authentication (local-only)

The experimental async storage integration now provides a
`CoroutineSessionAuthenticator` that accepts an **owned**
`foundation::SecretString` bearer, validates the same minimum 32-byte
server-side HMAC key used by the synchronous SessionService, computes the
HMAC-SHA-256 token digest *before its first suspension*, and awaits the
nonblocking `CoroutinePostgresSessionRepository::use` call. The raw bearer
is never passed to SQL, put into a coroutine I/O frame or included in a
database error. An empty token fails as `AuthenticationFailed` without
opening a DB connection; a cryptographic provider failure maps to
`Internal`, rather than being misreported as an invalid credential.
The fake-connection local test also requires a sanitized `Unavailable`
result for a syntactically valid bearer.

This is a first application-level authentication bridge, not proof the
existing HTTP/SessionService path is migrated. It is not deployed, and
its new test remains pending compilation on the resource-limited shared
server.

### Verified local disposable PostgreSQL 16 integration checkpoint — 2026-10-27

Using `scripts/ci/test-local-coroutine-docker.py` on the shared server,
a freshly initialized and temporary PostgreSQL 16 container was bound only
to `127.0.0.1:55432`, with a tmpfs-backed data directory, a distinct
`cluster_name` checked by the C++ test, CPU/memory limits, and guaranteed
container removal. The local `pg_virtualenv` method could not switch UID
on this host, so the Docker fixture supplies real SQL isolation without
touching the managed service or database.

**Actual passing results** (not skipped, not mocks):
- **24/24** native libpq, pool and async session SQL tests, covering
  cancellations/timeouts, tenant-state isolation, poisoned and aborted
  transactions, bounded results, non-blocking slow SQL, and atomic session
  rotation/revocation (including 2,048 sessions).
- **5/5** standalone domain security tests, including strict typed row
  restoration and the new HMAC bearer authentication bridge.
- **1/1** isolated real-schema integration test, including bidirectional
  synchronous/coroutine repository interoperability, identity scoping,
  replay protection, and actual HMAC bearer authentication with wrong-bearer,
  wrong-signing-key and revoked-session rejection.
- The real-schema test ran in **469 ms**, and the native set in **1,760 ms**
  on this server. These are **test elapsed times**, not comparative production
  throughput or valid old-versus-new latency benchmarks.

The Docker runner rejects occupied ports, existing containers and unexpected
server identities. It checks published TCP readiness, runs both test binaries
with strict pass/no-skip assertions, and removes the disposable database in a
finally block. The ordinary CI workflow was not triggered and changes remain
local-only.

**Release status: NOT_APPROVED.** This verifies native storage/session
components only. Production HTTP handlers, full coroutine SessionService,
other synchronous SQL repositories, external OAuth/OIDC/wallet/LDAP transports,
cancellation budgets, security acceptance and paired end-to-end workload
benchmarks still require migration and testing.

### Coroutine first-party SessionService adapter — local checkpoint

A dedicated `CoroutinePostgresSessionService` now provides **native
Asio-awaitable** first-party session issuance, current-cookie replacement,
authentication, token rotation, revocation, bulk revocation, active-session
listing and identity-scoped revocation. It owns a minimum-32-byte server
HMAC key, accepts only the original trusted
`authentication::VerifiedAuthentication` as an issuance authority, uses
the project's CSPRNG for 32-byte session IDs and bearer secrets, and
persists native `session::Session` objects through the nonblocking
`CoroutinePostgresSessionRepository` instead of blocking pool calls.

The independent `CoroutineSessionGrant` holds a move-only
`foundation::SecretString`. This adapter intentionally remains outside
the portable OpenProof C++ modules until the public async repository SPI
and gateway integration are designed. It is not the original
`session::SessionGrant` and **is not yet wired to HTTP**.

**Security parity checks:** an old browser cookie is revoked only *after*
the replacement is persisted; on failure to revoke the previous browser
session, the replacement bearer is never returned and a compensating
revocation of the replacement is attempted. Database unavailability
during old-cookie lookup is not treated as an invalid/stale cookie, so it
must not issue a new token. A missing, stale or revoked cookie does not
authorize revocation of an unrelated browser session. Identity-scoped
revoke-first checks map missing or foreign sessions to the same NotFound.
Listing hides inactive and expired sessions. Token rotation compares
the expected digest atomically, so replay cannot recover a valid bearer.

**Local verification:** GCC 16.2 `RelWithDebInfo` compiled the new
service with `-Werror` retained. A restricted `-fno-inline` GCC
source option on the *service translation unit only* prevents a verified
false-positive in Boost.Asio's aligned coroutine-frame allocation without
disabling allocator warnings or changing the rest of the optimization
profile. A real, ephemeral Docker PostgreSQL 16 test included a genuine
`VerifiedAuthentication` minted by the domain's
`AuthenticationService`, browser metadata, two independently active
cookies, successful replacement of only the presented cookie, stale-cookie
handling, and owner isolation. Real PostgreSQL native transport tests
remained 24/24 green and the domain integration 1/1 green.

**Final local regression in this checkpoint:** the additional domain
failure-injection test confirmed that an unavailable PostgreSQL connection
prevents both ordinary issuance and old-cookie replacement, without exposing
a freshly minted bearer. Six out of six standalone domain tests passed.
A repeat isolated Docker PostgreSQL run passed all twenty-four native tests
and the expanded trusted-login/session-replacement integration test
(449 ms in this run); the container was removed afterward. The new service
compiled under GCC 16.2 with `-Werror`, with only its single source file
configured to avoid the compiler's Boost.Asio allocation inlining false
positive.

Pending: cancellation after partial commit; complete domain-to-HTTP
coroutine propagation; external providers; and whole-application paired
performance tests. The release gate remains NOT_APPROVED until all original
blockers are eliminated and CI is green.

### Experimental coroutine HTTP session mutation adapter

A separate, **opt-in** `CoroutineSessionHttpHandler` now targets the three
existing POST endpoints `/auth/session/rotate`, `/auth/logout`, and
`/auth/logout-all`. Unlike a synchronous forwarding shim, its
`handleAsync()` genuinely suspends on
`CoroutinePostgresSessionService` and the native PostgreSQL repository.
The original `takeSessionCredential()` parser is reused so ambiguous
cookie/Bearer combinations and malformed tokens do not bypass protocol
rules. The existing per-IP auth rate limit, session-cookie attributes
(Secure, HttpOnly, SameSite=Strict, Path=/), cache headers, error mapping,
missing-token logout behavior, token rotation and post-revocation logout
semantics are preserved. An unavailable DB cannot produce a fresh cookie
or clear a session cookie misleadingly. Other paths are passed unchanged
to an asynchronous fallback callback.

The adapter exposes only `handleAsync()`, not a synchronous
`handle()` method. It cannot silently dispatch session mutations to
the old blocking repository. This class is not wired into the canonical
server; activation requires an explicit network transport bridge, audited
shutdown/executor lifetime handling, full HTTP policy parity and integration
with the nested auth/OAuth handler chain.

A new suite `PostgresCoroutineHttpTest` exercises genuine
`HttpRequest`/`HttpResponse` objects through the coroutine session
application handler (without constructing the heavyweight Beast listener)
to check unauthenticated rotation, anonymous logout cookies, database
outage, ambiguous simultaneous Bearer and Cookie credentials, forbidden
HTTP methods, and async fallback continuity. The isolated real-PostgreSQL integration fixture additionally
issues a trusted login, rotates the bearer through the coroutine HTTP
adapter, verifies cookie delivery, rejects old-token replay and revokes
the new token by HTTP Logout. These two suites must pass locally before
this HTTP application bridge is considered verified. The listener integration
is expressly **not verified** until a true Beast loopback wire test passes.
The full Gateway HTTP compiler rebuild was stopped locally after it spent
over half an hour compiling the existing `gateway/http.cpp` with GCC 16
on the shared single-vCPU server. To avoid modifying production optimization
or disrupting other services, the new handler instead depends only on the
transport-neutral `openproof.gateway` module and an asynchronous callback.
The listener wiring remains a tracked blocker. No production redeployment
or GitHub Actions push is authorized.

### Verified coroutine HTTP application handler checkpoint (local-only)

The initial Beast-coupled adapter was decomposed into a small
`CoroutineSessionHttpHandler` depending on the transport-neutral
`openproof.gateway` module and an awaitable fallback callback. This
preserves the true `HttpRequest`/`HttpResponse` contract, including
credential extraction, no-store error responses and session cookie headers,
without rebuilding the heavyweight `openproof.gateway.http` transport for
every experimental revision. In particular, the HTTP handler does **not**
inherit the live listener's transport interface and has **not** been
registered in `apps/opp`.

The new application handler compiled with GCC 16.2 and `-Werror`.
Eight `PostgresCoroutineHttpTest` cases passed on the server and all
six standalone domain tests remained green: uncredentialed rotation,
anonymous Logout, fail-closed 503 on unavailable DB, ambiguous
Bearer+Cookie rejection, rejecting wrong HTTP methods, throttling on
IP rate-limit exhaustion, rejecting repeated session cookies and coroutine
fallback to other routes. These are real application message objects,
**not socket-level HTTP/1.1 wire tests**.

The disposable PostgreSQL 16 container also passed 24/24 native SQL,
connection and pool tests, and 1/1 real-schema domain integration test.
That expanded end-to-end *application handler* fixture covers successful
Rotate response, accepting the replacement session cookie, rejecting
old-token replay, individual Logout, and Logout-All with two sessions
belonging to the requesting identity while a third session belonging to
a different identity remains authenticated. The last expanded database
integration ran in 424 ms; this is wall time for the test, not a
comparative throughput benchmark. The runner removed the container.

The pending transport tasks are: an audited Beast
`CoroutineHttpHandler` bridge; insertion in the live auth/OAuth handler
chain without sync fallback; use of a shared executor/lifetime budget;
request cancellation; and real loopback/synthetic production workload
comparisons. HTTP transport migration remains **NOT_APPROVED**.

### Experimental listener-bound coroutine session bridge (not yet verified)

A separate opt-in `CoroutineSessionListenerAdapter` now implements the
original `openproof.gateway.http::CoroutineHttpHandler` virtual contract,
forwarding real `handleAsync()` dispatch to the audited session HTTP
application adapter. Its synchronous `handle()` entry always returns
a sanitized 503 and no session cookie, instead of falling back to the
blocking legacy session repository. Both the application handler and
fallback must outlive in-flight requests. This target is not referenced
by `apps/opp`, does not change the active network listener or routes,
and does not create a production cutover.

A dedicated independent `openproof_postgres_network_tests` executable
provides socket-level Beast HTTP/1.1 tests against `127.0.0.1` and
port zero (assigned by the OS). Planned assertions include native
asynchronous fallback dispatch, missing-credential rotation, anonymous
logout cookie attributes, database outage preserving cookies, ambiguous
Bearer+Cookie rejection, and the fail-closed synchronous entry point.
The adapter explicitly uses the existing standalone Asio thread-context
extern-template declaration to avoid GCC 16 module TLS duplication.

**Verification status:** this network test and the listener bridge have
not yet passed a complete build and must not be described as tested.
The GCC 16 full optimized `gateway/http.cpp` rebuild took a disproportionate
share of a shared single-vCPU production host, and a separate unrelated
project began compiling concurrently. The OpenProof test Build was
interrupted deliberately to protect shared host responsiveness. Never
work around this by weakening application `-Werror`, deploying changes
or firing GitHub Actions for each experimental fix. The previously
verified 39 application/domain/real-PostgreSQL tests remain distinct;
only a **successful socket test** closes this specific transport gap.

#### Compile-only proof, pending listener test

The original listener bridge object and the new socket-test translation
unit both compiled independently with GCC 16.2 and `-Werror`, using existing
module BMI artifacts and without rebuilding the large Gateway transport.
This verifies translation-unit correctness only; no new linked executable
or loopback socket test is claimed. All 14 existing domain/application
handler tests and all 6 existing focused Beast transport tests were
re-run and passed independently, while the neutrality audit remains green.

A follow-up `CoroutineSessionListenerStack` now constructs and owns the
application adapter and native listener adapter in a defined order, while
accepting an already-native fallback handler. Its fallback lambda explicitly
awaits `CoroutineHttpHandler::handleAsync()`; it never invokes legacy
`handle()`. The socket fixture now uses that composition to exercise
true caller lifetime. The updated composition still needs its own
compile/link and socket checks. Two unrelated builds occupied the shared
server's limited CPU capacity, so a full optimized Gateway rebuild was
not accepted as a production-safe shortcut. Production is untouched.

#### 2026-10-28 verification and network security regression checkpoint

The standalone `postgres_coroutine_network_test.cpp` translation unit,
including the composition stack and three additional negative socket tests,
compiled successfully with GCC 16.2/C++26. The new tests cover rejected
HTTP GET session mutation, duplicate session cookies, and a fully exhausted
per-IP rate limiter before database access. The existing manual-only
`native-coroutine.yml` workflow now explicitly builds and invokes the
socket-level test target; this does not trigger any automatic CI run.

On the isolated worktree, the 14 previously linked coroutine domain/HTTP
tests and 6 focused Beast tests passed (20/20), as did protocol neutrality,
migration checksum preservation, the gateway benchmark summary regression
when run without competing heavy compiler load, and `git diff --check`.
These are historical linked binaries, not proof of the newly compiled
socket fixture executing. A heavyweight full Gateway rebuild was stopped
after prolonged single-vCPU contention; until the listener object is linked
with a matching Gateway library and the network test executable actually
runs, the new transport regressions remain **NOT VERIFIED**.

The full protocol coroutine coverage scan still reports 40 findings across
11 critical areas. End-to-end migration and deployment approval remain
**NOT APPROVED**.

#### Atomic first-party coroutine session replacement (2026-10-28)

The coroutine service previously performed `add(new)` followed by
`revoke(old)` with two independent database operations and a compensating
revocation on failure. A cancellation or failed compensation could leave the
old and new sessions simultaneously active. Native replacement now uses a
single parameterized PostgreSQL writable-CTE statement, contingent on the
prior ID/digest still being active, unrotated and unexpired. PostgreSQL
commits the revocation and insertion together or neither. Stale/unknown
prior cookies retain the existing fresh-login behavior, but a verified
prior that becomes invalid during replacement refuses to issue a bearer.

The new low-level disposable PostgreSQL tests cover stale digest, successful
replacement and replay. A real-schema disposable-database integration
regression deliberately collides with another session's primary key
*after attempting revocation*, then verifies via a fresh pool lease that
the previous session survived, the unrelated session was unchanged and
a subsequent legitimate replacement still works. A query error causes the
native libpq connection to be discarded, never reused across tenants.

**Focused verification:** the changed async SQL, repository, session
service, and both PostgreSQL test translation units have compiled with
GCC 16.2/C++26 without a full application release build. The GCC/Asio
aligned-allocation false positive required the existing narrowly scoped
`-fno-inline` workaround for the two affected storage files; `-Werror`
remains enabled for production code. These object compilations **do not**
execute the newly written disposable-database tests, link an application
binary, or prove cancellation/rollback semantics at runtime.

No production migration, release build, GitHub Actions run or deployment
is authorized by this checkpoint.

#### Additional post-suspension network error containment regression

The native socket fixture now includes an opt-in fallback that deliberately
suspends on an Asio timer and then throws a test-only diagnostic. Its wire
assertions require a sanitized HTTP 500 with `Cache-Control: no-store`, no
diagnostic reflected in the response body, and a successful independent
HTTP request afterward (so a handler exception cannot poison future
dispatch). This regression is distinct from synchronous exception handling.

On the single-vCPU host, the first full Release build of the new network test
spent approximately ten minutes rebuilding the unrelated optimized Gateway
transport without reaching the link stage; it was terminated rather than
impact shared production services. A focused compilation of the changed test
translation unit is the bounded local gate. Successful object compilation is
**not** a substitute for a linked socket test, nor a reason to merge the
experimental branch.


#### Shared coroutine provider HTTPS transport (2026-10-29)

An ordinary C++26 adapter library `openproof_provider_async_https` now
provides a common native-Boost.Asio/Beast HTTPS transport for future GitHub,
OIDC, X and Web3 provider migrations. Unlike the blocking provider-specific
`httpsRequest()` helpers, its DNS resolution, TCP connection, verified TLS
handshake, HTTP write/read and shutdown are awaitable, with a shared monotonic
operation deadline. Its TLS context is configured once and held by the client;
no request can disable certificate/hostname verification. Caller-controlled
Host, framing and hop-by-hop headers, duplicate header names, CRLF insertion,
absolute-form HTTP targets and oversized requests are rejected;
upstream response headers/bodies are bounded, and redirects are returned to
provider policy without being followed. No OAuth credential
or upstream response body is logged on failure.

The opt-in target has a dedicated local-only test executable. Seven focused
tests cover malformed hosts and injected/duplicate headers, configuration
bounds, an ephemeral loopback TLS server trusted through a disposable CA,
untrusted certificate rejection, upstream body limit, an undereferenced
cross-origin 302 redirect and a deliberately delayed upstream response
failing within the total deadline. Test certificates and their private keys
are generated afresh in process: no private key or external provider calls
are required.

**Boundary still open:** This is a reusable I/O transport, not yet a
replacement for the synchronous `AuthenticationProvider` SPI or any active
provider calls. Provider-level endpoint policy, DNS rebinding / private IP
restrictions, SSRF decisions, OAuth/JWKS validation and complete coroutine
application-handler wiring remain required. It is NOT proof of end-to-end
provider migration and does not authorize a release, main merge, GitHub
Actions run or deployment. Full coroutine acceptance remains NOT APPROVED.


#### GitHub provider native OAuth completion (2026-10-29)

The GitHub provider has a dedicated `completeAuthenticationAsync` coroutine.
It owns the move-only OAuth callback across suspensions and performs the
authorization-code token exchange, authenticated user lookup and optional
verified primary email lookup through the shared nonblocking HTTPS adapter.
The code preserves the provider's PKCE/state constant-time verification,
access-token grammar, scope/type validation, account identifier checks,
verified-email selection, evidence and claim-boundary rules. Public GitHub
hostname, API version and token/user/email endpoints remain fixed.
The legacy synchronous provider SPI remains separately implemented for
compatibility; its full orchestrator migration, concurrent transaction
single-use handling and dispatch wiring are not yet complete.

A separate local-only coroutine provider test target verifies that missing
code/state or an incorrect state are rejected before any outbound I/O.
These tests do not use real OAuth credentials or contact GitHub and do not
replace end-to-end tests with a disposable fake OAuth provider. The acceptance
gate stays NOT APPROVED until compiled and runtime-tested on the full
nonblocking authentication pipeline.


#### Outbound provider DNS-rebinding / SSRF guard (2026-10-29)

The shared nonblocking HTTPS transport now rejects nonpublic DNS answers
**before creating a TCP connection**, including any mixed public/private
answer set. The default policy denies loopback, RFC1918, CGNAT, link-local
metadata, documentation/benchmarking, multicast, reserved IPv4 ranges,
non-global IPv6, mapped/tunnelled/private and known documentation prefixes.
This protects the new GitHub coroutine path even if a public DNS hostname is
unexpectedly resolved to an internal destination. Trusting a TLS certificate
by itself is not a replacement for the network destination boundary.

The override `PermitPrivate` is explicit at the request site and is reserved
for a separately trusted endpoint such as the local disposable TLS tests;
provider configuration or caller-provided URLs must never select it.
An isolated network test requires PublicInternet to fail closed when DNS
resolves `localhost`; the existing pinned-CA localhost tests opt into the
disposable-only override.

This gate supplements, but does not replace, provider-level hostname
allowlisting, proxy egress rules and end-to-end authenticated request flow
tests. Release approval remains NOT APPROVED.


#### OIDC coroutine federation pathway (2026-10-29)

The OIDC provider now has opt-in `beginAuthenticationAsync` and
`completeAuthenticationAsync` methods. Native discovery is async and
uses the same trusted issuer, RS256 / authorization-code, subject type,
client-auth, PKCE S256, response-mode and metadata validation as the legacy
synchronous code. Token exchange, signing-key JWKS retrieval and optional
subject-bound UserInfo use the shared nonblocking HTTPS transport with the
default public-destination DNS policy. Callback inputs are owned across every
suspension. The code retains ID Token RS256 verification, issuer, audience,
authorized-party, nonce, at_hash, iat/exp and claim/evidence validation;
there is no skip-signature or fallback-to-unsigned path.

The coroutine entry points are opt-in. The existing synchronous
`AuthenticationProvider` interface and `AuthenticationService`
orchestrator still require migration before production dispatch can use them.
The current isolated negative tests verify invalid provider and malformed
or unbound callbacks fail prior to network operations; real disposable
issuer/JWKS/TLS interoperability and concurrent transaction cancellation
remain required acceptance checks. Build/test status is independently
recorded; source presence is not release approval.


#### Multi-hop OAuth total deadline propagation (2026-10-29)

The native HTTPS request type can now carry an optional **absolute monotonic**
deadline in addition to its per-request relative timeout. DNS, TCP, verified
TLS, write, read and shutdown take the earlier of the two deadlines. An
already-expired flow is refused before DNS/network allocation. Both native
GitHub and native OIDC entry points now establish one 15-second total budget
and pass that same deadline to every outbound token/user/email or
discovery/token/JWKS/UserInfo exchange; a successful first call can no longer
reset the clock for subsequent calls. Individual exchanges retain a smaller
10-second cap. The interactive browser redirect interval is separate and
remains governed by its authentication transaction expiry.

Dedicated HTTPS tests verify immediate fail-closed on a previously expired
absolute deadline, and a deliberately slow TLS peer is cancelled within a
short shared budget despite an individually longer request timeout. This
does not yet replace request-scoped cancellation propagation from the HTTP
socket or bounded CPU executor accounting, which remain release blockers.


#### X OAuth 1.0a native coroutine pathway (2026-10-29)

The X provider now exposes nonblocking `beginAuthenticationAsync` and
`completeAuthenticationAsync` entry points. The request-token and access-token
POSTs use the shared HTTPS client's public-internet address policy, fixed
`api.x.com` hostname, peer verification, no-follow redirects and a 10-second
total per-operation deadline. OAuth 1.0a signing (including signed callback,
nonce/timestamp, verifier and request-token secret), AEAD-sealed challenge
ownership and constant-time callback-token comparison are unchanged.
Provider state and the move-only completion response stay alive across
`co_await` suspension. The coroutine does not log untrusted upstream
message bodies or OAuth credentials on transport failures.

Independent negative coroutine tests check wrong-provider starts, incomplete
callbacks and forged challenge envelopes fail before outbound network I/O.
The synchronous compatibility provider remains for the existing SPI; the
trusted authentication service and HTTP dispatch have not yet been migrated.
This does not authorize a main merge, production rollout or release.
