# OpenProof performance audit — 2026-10-26

Status: **IN PROGRESS; not production-approved**. Scope: the public `genyleap/openproof` `main` revision `ccb396182936d717960fdca319999baf2f580ff9`. Production service was not modified.

## Source audit

The reproducible `node scripts/perf-source-audit.mjs` inventory scanned 216 C++ source/module files (52,875 lines) under `src/`. These counts refer to syntactic call sites, not execution frequency or a profiling result.

- C++ coroutine keywords: 0.
- Blocking SQL call sites: 3 (`PQexec` and `PQexecParams`; the helper functions are invoked from many repository operations).
- Blocking `condition_variable::wait_for` in connection acquisition: 1.
- Synchronous HTTP read/write call sites: 10; synchronous resolver call sites: 5.
- Async HTTP `async_read`, `async_write`, and `async_accept`: 3.

Critical path: `gateway/http.cpp` receives requests asynchronously but invokes `HttpHandler::handle` synchronously on an `io_context` worker. The handler may transitively execute synchronous libpq calls, synchronous provider HTTP requests, and synchronous upstream proxy operations. Thus unrelated clients can lose event-loop service during slow I/O.

The pool in `storage/postgres/postgres.cpp` creates blocking libpq connections, acquires them with a timed condition-variable wait, and executes queries synchronously. Provider integrations under `providers/github`, `providers/oidc`, `providers/x`, `providers/web3`, plus `gateway/http.cpp` proxy, use synchronous resolve/connect/HTTP calls.

## Implemented, isolated HTTP compatibility optimization

On branch `perf/openproof-full-optimization-20261026`:
- Move synchronous `HttpHandler::handle` from socket `io_context` to a finite `boost::asio::thread_pool`; preserve async HTTP read/write and original security-validated request parsing.
- Limit outstanding dispatches; reject overload with a bounded HTTP 503 and Retry-After rather than allowing an arbitrarily long handler backlog.
- Catch exceptions at the handler boundary and produce a sanitized HTTP 500 rather than terminating an event-loop worker.
- Add integration tests for concurrent handler execution and safe exception behavior.

This is **not** a coroutine conversion; it is a compatibility optimization whose value must be verified in product-shaped load tests.

## Synthetic performance data (not OpenProof throughput)

Reproducible local simulation: Boost.Asio/Beast HTTP; one pinned CPU; two socket workers; eight mock I/O slots; 32 clients; 1 ms synthetic CPU/request; mock blocking/waiting I/O.

| Mock I/O wait | Blocking req/s | Bounded handler executor req/s | Coroutine req/s | Offload speedup |
|---:|---:|---:|---:|---:|
| 0 ms | 990.0 | 1001.2 | 984.6 | 1.01x |
| 2 ms | 565.4 | 773.7 | 968.0 | 1.37x |
| 20 ms | 93.9 | 281.9 | 363.3 | 3.00x |
| 50 ms | 38.7 | 149.9 | 150.9 | 3.87x |

20 ms mock I/O p95: 343.62 ms blocking, 118.91 ms bounded executor, 89.63 ms coroutine. Single-run synthetic measurements; not statistical confidence intervals. These show scheduler-level potential, not a product performance commitment.

Repeated 20 ms test (five samples per mode): mean **93.78 / 281.10 / 351.10 req/s** (blocking / executor / coroutine), sample standard deviation **0.20 / 7.26 / 8.35 req/s**, and mean p95 **345.35 / 121.07 / 103.37 ms**. Thus bounded offload averaged **3.00x**, and true nonblocking coroutines averaged **3.74x**, versus the isolated blocking model. Zero request errors in all fifteen samples. Repeated samples are still synthetic, short-run measurements.

## Required verification and remaining work

1. Finish the **full** GCC 16.2 / C++26 build and complete CTest, sanitizer profile and concurrency regressions on the isolated worktree. The focused HTTP component builds and its six tests pass, but this is not the full project gate.
2. Capture a baseline **of the same OpenProof commit** with an isolated PostgreSQL disposable `e2e` database and TLS edge, then optimized performance for matched OAuth token, UserInfo, introspection, consent, passkey, and reverse-proxy workloads. Report p50/p95/p99, RPS, CPU, RSS, errors, pool wait time and DB connections; repeat to control noise.
3. Implement genuine non-blocking provider networking using Boost.Asio coroutines, persistent/reusable TLS sessions where safe, cancellation and propagated request deadlines, bounded provider concurrency and circuit/failure isolation.
4. Implement genuinely asynchronous libpq read/write readiness and transaction-safe connection ownership. Preserve serializable administration, single-use tokens, refresh replay protection, optimistic locks and fail-closed security invariants; prohibit suspension while holding mutable sync locks.
5. Profile CPU-limited Argon2id, WebAuthn, JWT signing and claim/policy handling; cap expensive operations separately instead of assuming coroutines optimize CPU work.
6. Instrument per-endpoint handler queue duration, active handlers, DB wait duration, upstream DNS/connect/TLS/response duration, lock contention and error/timeout rates with **bounded cardinality** and no secrets.
7. Compare optimized vs baseline on independent hardware as production has one vCPU and limited free disk; require no critical security/latency regressions before rollout.

### Release gate

Not deployable until matched E2E tests and benchmarks pass. No claim of complete end-to-end optimization is made by the bounded HTTP executor patch alone.

### Build attempt and host contention

A separate GCC 16.2 release build configured successfully, but was intentionally stopped at **274/624** Ninja steps (SIGTERM, not a compiler failure). The production host has one vCPU; at that time a separate GenyCaster WASM build was simultaneously active, disk usage was **92%**, and memory available was about **2.1 GiB**. Continuing two competing C++26 builds on that host would risk shared-service responsiveness. A later targeted RelWithDebInfo build of `openproof_gateway_http` completed successfully (**38/38 build steps; exit 0**), followed by a separate focused HTTP integration test executable (**20/20 build steps; exit 0**). The focused CTest run passed **6/6 tests in 0.46 seconds**, covering concurrent handlers, sanitized exception responses, loopback-proxy IP validation, reverse-proxy round trip, HTTP parser limits and maximum socket connections. **The complete application build, complete CTest suite and real before/after OpenProof E2E performance benchmark remain unfinished**. The independent `openproof-canonical.service` remained active and untouched.


## Coroutine migration checkpoint (2026-10-26; **NOT APPROVED**)

The incoming Beast HTTP listener now uses native `boost::asio::co_spawn` and `asio::awaitable` for accept, request read and response write. It is not an end-to-end async request path: the bounded compatibility handler executor still invokes synchronous `HttpHandler::handle`. The coroutine-native listener built successfully with GCC 16.2.0 (RelWithDebInfo), and all six focused HTTP integration tests passed.

A new `BeastProxyTransport::sendAsync` API has been introduced with asynchronous DNS resolution (cancelable via a deadline timer), TCP connect, TLS handshake with unchanged certificate/hostname verification, HTTP write/read and TLS shutdown. The existing synchronous `ProxyTransport::send` implementation has deliberately NOT been removed or silently replaced. Gateway routing still calls it, so this does **not** unlock real end-to-end coroutine execution. The native async proxy API and its direct round-trip integration test are under separate build verification.

Run `node scripts/verify-coroutine-coverage.mjs` to see the failing static migration gate. It currently flags synchronous libpq/pool acquisition, the legacy synchronous proxy, Github/OIDC/X/Web3 and Enterprise LDAP providers, and application HTTP handlers. A native `co_await` counter is not a substitute for proving that a request cannot block a socket reactor; targeted static review and fault-injection E2E tests remain mandatory.

No production cutover, merge recommendation, or performance improvement factor is justified at this checkpoint.

## Actual-product E2E benchmark instrumentation

The feature branch CI builds the real `opp` binary with GCC 16.2 and runs the real `scripts/e2e-identity-platform.mjs` against a disposable, empty `openproof_e2e` PostgreSQL database (separate from the `openproof_ci` CTest database). The harness exercises full identity/security workflows and a 600-request mixed-read sample at 24-way concurrency. Upon successful completion it writes **only aggregate throughput and percentile latency measurements**, and CI uploads `openproof-e2e-metrics.json`.

To compare baseline and candidate *real-product* measurements:

```sh
node scripts/compare-e2e-metrics.mjs baseline.json candidate.json
```

This comparison **does not indicate statistical significance or justify release** from single samples. Paired repetitions on identical hardware, full error budgets, and transaction/cancellation fault tests remain required. A successful CTest or E2E result cannot bypass the independent `verify-coroutine-coverage.mjs` hard-failure gate. The branch release workflow now runs that gate before any publication.


## CI and native libpq checkpoint (2026-10-26)

- On commit `d9a593a`, full application linking failed with duplicate Boost.Asio `keyword_tss_ptr<...>::value_` between the C++ module `http.cpp.o` and ordinary OAuth provider objects. No executable or product E2E benchmark was produced.
- On commit `e88e75c`, switching all GNU/Linux OpenProof targets to Boost.Asio's pthread TSS backend exposed the same ODR problem at `call_stack<thread_context,thread_info_base>::top_`. This confirms uniform TLS configuration is necessary but **insufficient**.
- A dedicated ordinary C++ translation unit, `src/gateway/asio_thread_context.cpp`, now owns the explicit Asio thread-context template instantiation, while the C++ module unit declares an `extern template`. This is a **candidate fix only** until a clean application link succeeds.
- The new native PostgreSQL coroutine adapter builds locally with GCC 16.2. Its two local GTest cases were skipped without a disposable DB. In the `1de8777` CI workflow, the independent `Native PostgreSQL coroutine integration` step **succeeded** with CI-provisioned PostgreSQL. It does not establish async repository, transaction or pooling coverage.
- `opp` before/after E2E figures remain **unavailable** because full candidate linking has not yet passed. Synthetic benchmark numbers must not be advertised as OpenProof application performance.

## CI regression checkpoint — link isolation

On commit `d7e53d7` the CI Build progressed past linking
`apps/opp/opp` after moving the GCC16/Asio explicit TSS instantiation to a
non-module TU with its `extern template` declaration included from the
global module fragment. However, the same full Build failed while linking
`tests/openproof_tests`: the Beast HTTP integration source was compiled into
both the umbrella binary and its separate focused test binary. The umbrella
link also pulls OIDC Asio objects, producing a duplicate
`call_stack<thread_context,thread_info_base>::top_` symbol.

The tests have therefore been partitioned: the full suite retains
`gateway/gateway_test.cpp`, and the exact Beast HTTP integration source is
compiled exclusively in `openproof_gateway_http_tests` (already
CTest-discovered). No coverage is intentionally dropped. This test-target
partition requires clean CI validation before it is considered fixed.

There are still **no successful end-to-end `opp` benchmark results**, because
the full Build/Test CI job stops before the E2E step. Migration acceptance
remains NOT APPROVED.

## 2026-10-26 late CI validation

- Commit `3d7f663` CI confirmed `apps/opp/opp` **linked successfully** and the umbrella unit test runner `tests/openproof_tests` linked successfully.
- The remaining independent `tests/openproof_gateway_http_tests` link failed with duplicate Boost.Asio `call_stack<thread_context,thread_info_base>::top_`, between its Beast test translation unit and the named HTTP module implementation. This is **not** an OpenProof security test failure; it is a compiler/module interop/linker failure.
- The pending fix makes the test and HTTP module include a common explicit-instantiation declaration **before** `boost/asio.hpp`; the non-module `asio_thread_context.cpp` retains ownership of the sole definition. Until clean link this is only a candidate fix.
- E2E/benchmark in the CI workflow is now ordered immediately after the successful `opp` binary link, ahead of independently linking the full test binaries. This isolates real-product E2E evidence from unrelated test-executable linker problems, **without approving the candidate or bypassing tests as a release gate**.
- The main application remains partly synchronous in database repositories, OAuth providers, LDAP and the proxy dispatch. Native libpq transport is not yet used by production repository methods. The release gate remains **NOT APPROVED**.

## CI E2E harness release-candidate compatibility

CI run `40396015855` confirmed that the `opp` executable links and that
the isolated real-application E2E workflow **started**. Its first failure
was a test assertion on Prometheus' process-start metric: the executable
correctly reported `version="1.1.0-rc6"` while the harness insisted on
release-only `version="1.1.0"`. This is a version-label assertion defect,
not evidence of a production or authentication defect.

The E2E test now accepts **exactly** either `1.1.0` or
`1.1.0-rc<positive-integer>` and still requires a single correct process
start metric. All remaining identity and security E2E steps must still pass
before an aggregate benchmark artifact is emitted. No valid real-product
throughput/latency result exists from the failed attempt.

## Matched mainline versus optimized E2E benchmark (prepared, not yet executed)

The new CI helper `scripts/ci/run-paired-e2e-baseline.sh` pins the
pre-optimization **base commit**
`ccb396182936d717960fdca319999baf2f580ff9`, builds its own `opp`
binary with the same GCC16/Boost toolchain on the *same CI runner* as the
candidate and runs the **candidate branch's identical E2E harness** with
600 mixed read requests and concurrency 24 against a **different empty**
disposable PostgreSQL database. It attributes the baseline artifact to the
actual baseline commit through `OPENPROOF_E2E_COMMIT`, rather than wrongly
using the candidate's `GITHUB_SHA`.

The paired baseline only runs after the candidate E2E and complete CTest
suite pass. Separate CI artifacts will expose both aggregate metric records
and a human-readable comparison. No p50/p95/p99, throughput improvement,
or significance claim is valid until the job completes successfully.

The initial paired run is a **smoke comparison, not a statistically robust
benchmark**. Production-grade release criteria remain: multiple paired
repetitions, warm-up controls, fixed CPU quota and PostgreSQL settings,
errors and timeouts, CPU/RSS data, and regression checks on CPU-heavy routes.
The full Coroutine coverage gate still independently blocks release.

## Compiler fragment regression corrected (CI 40397926993)

The CI attempt containing the earlier Asio TLS predeclaration failed before
linking: GCC16's `-Werror=global-module` prohibits spelling
`namespace boost::asio::detail {...}` directly inside a Global Module
Fragment. The incomplete forward declarations have now been moved to the
preprocessor-included `asio_thread_context_extern.hpp` header, while the
early inclusion ordering remains intact. This is a candidate correction that
must pass a fresh CI build; no suppressed warning or permissive linker flag
has been introduced.

## E2E telemetry and secret-safe diagnostics

The identity E2E harness now avoids printing OAuth authorization codes,
`state` values or unexpected HTTP response bodies in CI failure messages.
External-tool stderr and application startup logs are suppressed in the
public CI error path because those sources can contain confidential
test/database material. Error status and failing stage remain visible.

On Linux runners, the harness also measures the **opp server process**
(not its Node.js load generator) before and after the mixed-read sample:
CPU user+system ticks consumed and final RSS in KiB. These aggregate values
are included only when procfs inspection succeeds. Baseline/candidate
comparison prints them on the same runner, which has a common CPU tick
frequency. Single-run estimates remain insufficient to establish a
statistically significant performance improvement or release readiness.

## First successful real-product E2E result — CI 40403283036

The GitHub Actions run on commit `e915059ac16ef54cded0ca53c441729b02ae2b2c`
has passed the complete OpenProof identity E2E workflow against an isolated
PostgreSQL database, as well as the `opp` executable build, full Build and
CTest. Its uploaded `openproof-e2e-metrics` artifact reports:

- 600 mixed read HTTP requests, concurrency 24 (five endpoint classes).
- **450.5598123 requests/second**.
- p50 **52.530854 ms**, p95 **58.725514 ms**, p99 **62.767793 ms**.
- Timestamp: 2026-10-26T21:26:30.700Z.

This is a **measured real `opp` result**, not an Asio timer simulation.
It is **NOT a before/after speedup claim**: the pinned baseline is still
being built/tested, and no paired repeats or latency error bars exist. The
effective I/O hot paths are still partly synchronous and the full
Coroutine release gate still fails. Do not ship or merge based on this
single result.

## Measured paired baseline comparison — GitHub Actions 40403283036

The completed CI run on candidate `e915059ac16ef54cded0ca53c441729b02ae2b2c`
has **passed**: native async PostgreSQL integration tests, the `opp`
executable link, complete isolated identity E2E, full C++ project Build,
CTest, pinned-baseline E2E comparison, and release package build.
**Static Coroutine coverage intentionally remains FAIL**, so the branch
is **NOT APPROVED** for merge or production deployment.

The independently archived metrics are:

| Metric | Original `ccb3961` | Candidate `e915059` | Change from original |
| --- | ---: | ---: | ---: |
| Throughput (req/s) | 446.52 | 450.56 | +0.90% |
| p50 (ms) | 53.13 | 52.53 | -1.13% |
| p95 (ms) | 59.94 | 58.73 | -2.03% |
| p99 (ms) | 62.85 | 62.77 | -0.13% |

Both had 600 HTTP requests at 24 concurrent clients and an identical
mixed-read E2E workload, on the same GitHub Actions runner with separate
disposable PostgreSQL databases and the same GCC16/Boost toolchain.
This is a single paired run, **not a significance test**. A 0.90%
throughput change is far too small to present as a confirmed speedup.
In particular, the old simulated coroutine microbenchmarks showing
multiples of throughput were **not** real OpenProof application results.

Raw artifacts are in the GitHub Actions workflow run
`https://github.com/genyleap/openproof/actions/runs/40403283036`.
Until the remaining synchronous repository, HTTP dispatch, provider, LDAP
and proxy paths are migrated and independently revalidated with repeated,
fault-injected benchmarks, the full Coroutine acceptance decision remains
**NOT APPROVED**.

## New operational Gateway Coroutine measurement protocol

A second **actual `opp` executable** benchmark is now available:
`scripts/benchmark-gateway-upstream.mjs` starts the OpenProof Gateway
with authentication and metrics middleware disabled, a localhost Node HTTP
upstream that introduces **50ms of controlled response latency**, then
records 600 end-to-end HTTP/TCP requests at concurrency 24 after warmup.
The full path exercises the candidate's `CoroutineGatewayAdapter` from the
`opp` composition root, including service discovery and signed trusted
headers. The exact same script runs the pinned original `ccb3961` binary
with a distinct local upstream and the same runner/toolchain configuration.
The associated comparison and both source JSON measurement files are
uploaded as `openproof-gateway-tcp-benchmark`.

This **controlled upstream-wait** experiment is deliberately separate from
the complete identity/OAuth PostgreSQL E2E workload; it is not a proxy for
identity throughput, nor evidence that authentication and repository calls
are nonblocking. Each sample must report zero errors, and no claimed
improvement is accepted from a single paired run. CPU ticks and RSS are
collected from the actual `opp` server process, not from the Node generator.

The first attempted CI for `36f8291` failed to compile Gateway forwarding
because `WeightedRoundRobin::choose` returns
`std::expected<Endpoint, Error>` rather than the newly exposed
`std::optional<Endpoint>`. The conversion is corrected in the following
branch revision, but **the full build, E2E, new Gateway TCP benchmark and
new authorization tests must pass before this patch is accepted**.

## Repeatability upgrade for the dedicated Gateway experiment

The controlled-latency **real OpenProof binary** benchmark now uses **five
paired candidate/baseline trials**, alternating candidate-first and
baseline-first ordering on the same CI runner. Every trial constructs a
fresh no-auth Gateway, warms it up, and exercises 600 HTTP requests at 24-way
concurrency against a local upstream that deliberately responds after 50ms.
The input workload and configured network delay are verified identical
before comparison. Any failed HTTP request causes a hard failure.

`scripts/summarize-gateway-bench.mjs` reports the *median paired
throughput/p50/p95/p99 changes* and exploratory percentile-bootstrap
intervals. The source JSON files for each individual run and machine-readable
aggregate summary are uploaded together, not only the preferred run. These
intervals are descriptive: five pairs on one shared CI runner do not meet the
requirements of an isolated, production-grade significance study, and this
workload says **nothing about blocking authenticated PostgreSQL/OAuth paths**.

A passing numerical comparison can NEVER override the independent
Coroutine-completeness gate or the security regression suite.
