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
