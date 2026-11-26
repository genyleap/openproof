#!/usr/bin/env node
// Strict, deliberately incomplete-by-design migration gate.
// A green source scan alone is NEVER sufficient for release approval.
// Runtime verification, security regressions and real-system benchmarks
// are independent mandatory gates documented in COROUTINE_ACCEPTANCE.md.
import fs from "node:fs";
import path from "node:path";
import { cppExecutableText } from "./cpp-lexical-scan.mjs";

const root = path.resolve(import.meta.dirname, "..");
const segments = [
  ["HTTP listener + proxy", "src/gateway/http.cpp"],
  ["PostgreSQL storage", "src/storage/postgres/postgres.cpp"],
  ["GitHub OAuth", "src/providers/github/github.cpp"],
  ["OIDC federation", "src/providers/oidc/oidc.cpp"],
  ["X provider", "src/providers/x/x.cpp"],
  ["Wallet + Farcaster RPC", "src/providers/web3/web3.cpp"],
  ["Enterprise LDAP", "src/providers/enterprise/enterprise.cpp"],
  ["Enterprise LDAP native HTTP boundary", "src/authentication/http/enterprise.cpp"],
  ["Trusted authentication canonical completion", "src/authentication/service.cpp"],
  ["HTTP authentication API", "src/authentication/http/http.cpp"],
  ["HTTP Web3 coroutine API", "src/authentication/http/web3.cpp"],
  ["PostgreSQL coroutine session issuance", "src/storage/postgres/coroutine_session_service.cpp"],
  ["PostgreSQL coroutine canonical finalization", "src/storage/postgres/coroutine_canonical_finalizer.cpp"],
  ["PostgreSQL bounded coroutine connection pool", "src/storage/postgres/async_pool.cpp"],
  ["PostgreSQL native asynchronous hostname resolution", "src/storage/postgres/async_connection.cpp"],
  ["PostgreSQL atomic native owned revocation", "src/storage/postgres/async_session.cpp"],
  ["PostgreSQL native bounded recovery-code SQL", "src/storage/postgres/async_recovery_code.cpp"],
  ["Native recovery-code domain service", "src/credentials/coroutine_recovery_codes.cpp"],
  ["PostgreSQL native recovery-code adapter", "src/storage/postgres/coroutine_recovery_code_repository.cpp"],
  ["Native HTTP recovery-code issuance", "src/authentication/http/coroutine_recovery_code_http.cpp"],
  ["PostgreSQL fail-closed coroutine listener", "src/storage/postgres/coroutine_session_listener.cpp"],
  ["HTTP OAuth API", "src/oauth/http/http.cpp"],
  ["HTTP account API", "src/account/http/http.cpp"],
  ["Native account session HTTP adapter", "src/account/http/coroutine_session_http.cpp"],
  ["HTTP administration API", "src/authentication/http/admin.cpp"],
];

const forbidden = [
  ["blocking PostgreSQL", /\bPQ(?:exec|execParams|connectdb|reset)\s*\(/g],
  ["blocking HTTP transport", /\b(?:beastHttp|http)::(?:read|write)\s*\(/g],
  ["blocking DNS", /\b(?:resolver|m_resolver)\.resolve\s*\(/g],
  ["blocking stream connect", /\b(?:stream|m_stream)\.connect\s*\(/g],
  ["blocking TLS handshake", /\b(?:stream|m_stream)\.handshake\s*\(/g],
  ["blocking pool acquisition", /\b(?:m_condition|m_cv|m_cond)\.wait_for\s*\(/g],
  ["blocking LDAP bind/search", /\bldap_(?:sasl_bind_s|search_ext_s|simple_bind_s)\s*\(/g],
  ["blocking LDAP shutdown", /\bldap_unbind_ext_s\s*\(/g]
];
const checked = segments.map(([name, relative]) => {
  // Gateway's heavy Beast listener, TLS proxy and coroutine dispatch now
  // live in separate implementation units of ONE C++26 named module.
  // Scan all of them as one auditable boundary, including legacy facades:
  // splitting a translation unit must never hide blocking compatibility.
  const sourcePaths = relative === "src/gateway/http.cpp"
    ? ["src/gateway/http.cpp", "src/gateway/http_proxy.cpp",
       "src/gateway/http_coroutine.cpp"]
    : relative === "src/authentication/http/admin.cpp"
      ? [relative, "src/authentication/http/coroutine_admin_read_http.cpp",
         "src/storage/postgres/coroutine_admin_store.cpp"]
      : relative === "src/oauth/http/http.cpp"
        ? [relative,"src/oauth/http/coroutine_token_read_http.cpp",
           "src/oauth/http/coroutine_consent_http.cpp","src/oauth/http/coroutine_discovery_http.cpp"]
      : relative === "src/account/http/http.cpp"
        ? [relative,"src/account/http/coroutine_session_http.cpp","src/account/http/account_pages.cpp",
           "src/authentication/http/coroutine_federated_start_http.cpp"]
        : [relative];
  const source = sourcePaths.map(file =>
    fs.readFileSync(path.join(root,file),"utf8")).join("\n");
  const executable = cppExecutableText(source);
  const issues=[];
  for (const [label,regex] of forbidden) {
    for (const match of executable.matchAll(regex)) {
      const line = executable.slice(0,match.index).split("\n").length;
      issues.push({line, kind:label, expression:match[0]});
    }
  }
  const awaitCount=[...executable.matchAll(/\bco_await\b/g)].length;
  // The named boundary must have directly auditable coroutine implementation.
  if(awaitCount===0)issues.push({line:0,kind:"no native coroutine",expression:"co_await missing"});
  if(relative==="src/gateway/http.cpp"){
    if(!/asyncHandler\s*&&\s*asyncHandler->nativeEnabledFor\s*\(\s*operation\s*\)/.test(source))
      issues.push({line:0,kind:"missing request-scoped coroutine dispatch guard",
        expression:"asyncHandler->nativeEnabledFor(operation)"});
    const syncProxy=executable.slice(executable.indexOf("BeastProxyTransport::send("),
      executable.indexOf("BeastProxyTransport::sendAsync("));
    const app=fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
    // Require a retired synchronous ABI AND actual native runtime wiring.
    // Removing the nested event loop alone must never pass this boundary.
    if(!/return foundation::fail\(foundation::ErrorCode::Unavailable,/.test(syncProxy)
       || /co_spawn|sendAsync|m_implementation->|\.get\s*\(/.test(syncProxy)
       || !/co_await m_implementation->sendAsync\s*\(/.test(executable)
       || !/co_await m_transport->sendAsync\s*\(/.test(executable)
       || !/const bool nativeProtectedGatewayEnabled = platform\.auth\(\)\.enabled\(\)\s*\|\|/.test(app)
       || !/platform\.auth\(\)\.enabled\(\) && nativeProtectedGatewayFlag && \*nativeProtectedGatewayFlag == "0"/.test(app)
       || !/createCoroutineWebhookVerificationDelivery\(/.test(app)
       || /createWebhookVerificationDelivery\(/.test(app))
      issues.push({line:0,kind:"proxy synchronous ABI or production native wiring is not retired",
        expression:"deny synchronous send; mandatory native proxy and delivery"});
    // Private io_context.run() still occupies a legacy handler thread.
    // A coroutine-only migration cannot approve this compatibility facade.
    if(/\bcontext\.run\s*\(\s*\)/.test(executable))
      issues.push({line:0,kind:"legacy proxy facade still blocks a calling thread",
        expression:"context.run()"});
    const interfaceSource=fs.readFileSync(
      path.join(root,"src/gateway/http.cppm"),"utf8");
    if(!/CoroutineMetricsAdapter[\s\S]*?nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+m_fallback->nativeEnabled\s*\(\);/.test(interfaceSource))
      issues.push({line:0,kind:"missing middleware coroutine capability propagation",expression:"m_fallback->nativeEnabled()"});
    if(!/virtual\s+bool\s+nativeEnabled\s*\(\)\s*const\s*noexcept\s*\{\s*return\s+false;\s*\}/.test(interfaceSource)
       || !/nativeEnabledFor\s*\([\s\S]*?return\s+nativeEnabled\s*\(\s*\);/.test(interfaceSource))
      issues.push({line:0,kind:"unsafe default-enabled coroutine handler capability",
        expression:"CoroutineHttpHandler::nativeEnabledFor(request) defaults to nativeEnabled()"});
    if(!/class\s+CoroutineMetricsAdapter[\s\S]*?nativeEnabledFor\s*\([\s\S]*?request\.path\s*\(\s*\)\s*!=\s*"\/metrics"[\s\S]*?m_fallback->nativeEnabledFor\s*\(request\)/.test(interfaceSource))
      issues.push({line:0,kind:"metrics wrapper does not preserve request-specific native routing",
        expression:"/metrics stays compatibility and other requests delegate"});
    const metricsAsync = executable.slice(
      executable.indexOf("CoroutineMetricsAdapter::handleAsync("),
      executable.indexOf("CoroutineGatewayAdapter::CoroutineGatewayAdapter("));
    if(!/request\.path\s*\(\s*\)\s*==\s*"\/metrics"/.test(source.slice(
      source.indexOf("CoroutineMetricsAdapter::handleAsync("),
      source.indexOf("CoroutineGatewayAdapter::CoroutineGatewayAdapter(")))
       || !/!m_fallback->nativeEnabledFor\s*\(\s*request\s*\)/.test(metricsAsync)
       || /m_metricsFacade->handle\s*\(/.test(metricsAsync))
      issues.push({line:0,kind:"metrics coroutine entry can execute synchronous or disabled downstream work",
        expression:"handleAsync /metrics and disabled native fallback must fail closed"});
    if(!/class\s+CoroutineGatewayAdapter[\s\S]*?nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+true;\s*\}/.test(interfaceSource))
      issues.push({line:0,kind:"missing explicit native gateway opt-in",
        expression:"CoroutineGatewayAdapter::nativeEnabled() true"});
    // A complete TLS response must not be held hostage by a peer that
    // keeps its connection open after a fully-framed HTTPS message.
    const nativeProxy = executable.slice(
      executable.indexOf("asio::awaitable<foundation::Result<HttpResponse>> sendAsync("),
      executable.indexOf("BeastProxyTransport::BeastProxyTransport("));
    const tlsResponse = nativeProxy.slice(
      nativeProxy.indexOf("auto response = co_await exchangeAsync(stream, endpoint, request, deadline);"));
    if(!/beast::get_lowest_layer\(stream\)\.socket\(\)\.close\(ignored\)/.test(tlsResponse)
       || /co_await\s+stream\.async_shutdown\s*\(/.test(tlsResponse)
       || !/beastHttp::async_read\s*\(/.test(nativeProxy)
       || !/parser\.body_limit\(/.test(nativeProxy)
       || !/parser\.header_limit\(/.test(nativeProxy))
      issues.push({line:0,kind:"native gateway TLS response waits for peer shutdown or skips bounded framing",
        expression:"complete bounded response then close one-shot TLS socket"});
  }
  if([
    "src/providers/github/github.cpp",
    "src/providers/oidc/oidc.cpp",
    "src/providers/x/x.cpp",
    "src/providers/web3/web3.cpp"
  ].includes(relative)){
    // All network provider bridges must be retired, not moved to a helper.
    // Even with native transport, this legacy facade waits synchronously
    // for the future; do not mark its caller nonblocking until retired.
    if(/\bio\.run\s*\(\s*\)/.test(executable))
      issues.push({line:0,kind:"legacy provider facade still blocks a calling thread",
        expression:"io.run()"});
  }
  if (relative==="src/providers/web3/web3.cpp") {
    const app=fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
    const native=fs.readFileSync(path.join(root,"src/authentication/http/web3.cpp"),"utf8");
    const syncWallet=executable.slice(executable.indexOf("WalletAuthenticationProvider::completeAuthentication("),
      executable.indexOf("WalletAuthenticationProvider::beginAuthenticationAsync("));
    const syncFarcaster=executable.slice(executable.indexOf("FarcasterAuthenticationProvider::beginAuthentication("),
      executable.indexOf("FarcasterAuthenticationProvider::beginAuthenticationAsync("));
    if (!/return foundation::fail\(foundation::ErrorCode::Unavailable,/.test(syncWallet)
        || (syncFarcaster.match(/return foundation::fail\(foundation::ErrorCode::Unavailable,/g)||[]).length!==2
        || /\b(?:rpc|rpcString|rpcChainMatches|contractWalletValid|universalSignatureValid|farcasterIdOf|farcasterAuthAddressValid|io_context|use_future)\s*\(/.test(executable)
        || !/co_await client.exchange\(/.test(executable)
        || (executable.match(/co_await rpcStringAsync\(/g)||[]).length!==6
        || !executable.includes("co_await universalSignatureValidAsync(")
        || !executable.includes("co_await contractWalletValidAsync(")
        || !executable.includes("co_await native->authorizeSignerAsync(")
        || !executable.includes("co_await native->verifySignatureAsync("))
      issues.push({line:0,kind:"Web3 synchronous network path remains or native verification is incomplete",
        expression:"native EOA/ERC1271/ERC6492 and Farcaster signer probes"});
    const startup=app.slice(app.indexOf("const auto nativeWeb3Flag"),app.indexOf("const auto nativeAuthSessionFlag"));
    if (!startup.includes('platform.auth().enabled() && nativeWeb3Flag && *nativeWeb3Flag == "0"')
        || !startup.includes("const bool nativeWeb3Enabled = platform.auth().enabled()")
        || !startup.includes("return ExitCode::ConfigurationError;")
        || !app.includes("nativeCanonical->authorizeDelegatedAccountAsync("))
      issues.push({line:0,kind:"native Web3 runtime may be disabled or lacks delegated access",
        expression:"mandatory native Web3 startup"});
    for (const route of ["/auth/web3/start","/auth/web3/complete","/auth/web3/handoff",
        "/auth/web3/handoff/redeem","/account/connections/web3/start",
        "/account/connections/web3/handoff","/account/connections/web3/complete"]) {
      if (!app.includes('nativePaths.emplace_back("'+route+'")'))
        issues.push({line:0,kind:"missing strict Web3 route overlay",expression:route});
    }
    for (const method of ["beginAsync","completeAsync","beginConnectionAsync","completeConnectionAsync",
      "issueBrowserAuthenticationHandoffAsync","redeemBrowserAuthenticationHandoffAsync",
      "publishBrowserAuthenticationHandoffAsync","issueBrowserConnectionHandoffAsync","consumeBrowserConnectionHandoffAsync"]) {
      if (!native.includes("co_await m_authentication->"+method+"("))
        issues.push({line:0,kind:"missing native Web3 lifecycle operation",expression:method});
    }
  }
  if (["src/providers/oidc/oidc.cpp","src/providers/x/x.cpp"].includes(relative)) {
    const oidc=relative.includes("/oidc/");
    const type=oidc?"OidcAuthenticationProvider":"XAuthenticationProvider";
    const sync=executable.slice(executable.indexOf(type+"::beginAuthentication("),
      executable.indexOf(type+"::beginAuthenticationAsync("));
    const native=executable.slice(executable.indexOf(type+"::beginAuthenticationAsync("));
    const app=fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
    const legacy=fs.readFileSync(path.join(root,"src/authentication/http/federated.cpp"),"utf8");
    const nativeStart=fs.readFileSync(path.join(root,"src/authentication/http/coroutine_federated_start_http.cpp"),"utf8");
    const nativeCallback=fs.readFileSync(path.join(root,"src/authentication/http/coroutine_federated_callback_http.cpp"),"utf8");
    if ((sync.match(/return foundation::fail\(foundation::ErrorCode::Unavailable,/g)||[]).length!==2
        || /\b(?:httpsRequest|io_context|use_future|completion\.get|discovery)\s*\(/.test(executable)
        || (executable.match(/co_await httpsRequestAsync\(/g)||[]).length!==(oidc?4:2)
        || (oidc && (native.match(/co_await m_implementation->discoveryAsync\(/g)||[]).length!==2))
      issues.push({line:0,kind:"redirect provider retains a blocking path or misses native exchanges",
        expression:type+" native start and completion"});
    if (!app.includes("authApi, nullptr, true}")
        || !app.includes("authApi, &tokenService, true}")
        || !app.includes('nativePaths.emplace_back("/account/connections/handoff")')
        || !app.includes('nativePaths.emplace_back("/account/connections/start")')
        || !legacy.includes('|| request.path()=="/account/connections/handoff"')
        || !legacy.includes('|| request.path()=="/account/connections/start"')
        || !nativeStart.includes("co_await m_authentication->issueBrowserConnectionHandoffAsync(")
        || !nativeStart.includes("m_authenticateBearer")
        || !nativeStart.includes("co_await m_authentication->consumeBrowserConnectionHandoffAsync(")
        || !nativeStart.includes("co_await m_authentication->beginConnectionAsync(")
        || !nativeCallback.includes("co_await m_authentication->completeConnectionAsync("))
      issues.push({line:0,kind:"delegated connection initiation can bypass native federation",
        expression:"runtime-required native browser handoff and callback"});
  }
  if(relative==="src/providers/x/x.cpp"){
    const signing=source.slice(source.indexOf("oauthAuthorization("),
      source.indexOf("struct HttpResponse final",source.indexOf("oauthAuthorization(")));
    if(!source.includes("class SensitiveSigningKeyGuard final")
       || !source.includes("foundation::secureWipe(m_value.data(), m_value.size())")
       || !signing.includes("SensitiveSigningKeyGuard wipeSigningKeyOnExit{signingKey}")
       || !signing.includes("wipeSigningKeyOnExit.wipe();")
       || signing.includes("std::ranges::fill(signingKey"))
      issues.push({line:0,
        kind:"X OAuth1 signing key can outlive the HMAC exchange without guaranteed scrubbing",
        expression:"RAII volatile secret scrub on normal and exceptional exits"});
  }
  if(relative==="src/providers/github/github.cpp"){
    // The retired synchronous GitHub SPI must reject unconditionally.
    // Require the actual native exchanges AND mandatory runtime routing,
    // not merely absence of the io.run spelling.
    const sync = executable.slice(
      executable.indexOf("GitHubAuthenticationProvider::completeAuthentication("),
      executable.indexOf("GitHubAuthenticationProvider::beginAuthenticationAsync("));
    const complete = executable.slice(executable.indexOf("GitHubAuthenticationProvider::completeAuthenticationAsync("));
    const completeWithLiterals = source.slice(source.indexOf("GitHubAuthenticationProvider::completeAuthenticationAsync("));
    const app = fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
    const callback = fs.readFileSync(path.join(root,
      "src/authentication/http/coroutine_federated_callback_http.cpp"),"utf8");
    const startup = app.slice(app.indexOf("const auto nativeFederatedStartFlag"),
      app.indexOf("if (nativeCatalogEnabled && !platform.auth().enabled())"));
    if (!/return\s+foundation::fail\(foundation::ErrorCode::Unavailable,/.test(sync)
        || /\bhttpsRequest\s*\(/.test(executable)
        || /\b(?:io_context|use_future|completion\.get)\b/.test(executable)
        || (complete.match(/co_await\s+httpsRequestAsync\s*\(/g)||[]).length!==3
        || !completeWithLiterals.includes('"/login/oauth/access_token"')
        || !completeWithLiterals.includes('"/user"')
        || !completeWithLiterals.includes('"/user/emails?per_page=100"'))
      issues.push({line:0,kind:"GitHub completion still has a synchronous path or missing native exchange",
        expression:"reject sync SPI; await token, user and email exchanges"});
    for (const leg of ["Start","Callback"]) {
      if (!startup.includes("const bool nativeFederated"+leg+"Enabled = platform.auth().enabled()")
          || !startup.includes("platform.auth().enabled() && nativeFederated"+leg+'Flag && *nativeFederated'+leg+'Flag == "0"')
          || !app.includes('nativePaths.emplace_back("/auth/federated/'+leg.toLowerCase()+'")'))
        issues.push({line:0,kind:"GitHub native federation runtime is optional or lacks strict route",
          expression:leg});
    }
    if (!callback.includes("co_await m_authentication->completeAsync(")
        || !callback.includes("co_await m_authentication->completeConnectionAsync("))
      issues.push({line:0,kind:"native federated callback cannot complete both login and connection",
        expression:"completeAsync and completeConnectionAsync"});
    // All four native OAuth providers share one awaitable HTTPS transport.
    // Completing a verified and framed HTTP response must not wait for the
    // peer's optional TLS close_notify before returning the result.
    const tlsSource = cppExecutableText(fs.readFileSync(
      path.join(root,"src/providers/http/async_https.cpp"),"utf8"));
    const exchange = tlsSource.slice(
      tlsSource.indexOf("AsyncHttpsClient::exchange("));
    const afterResponse = exchange.slice(
      exchange.indexOf("auto received = parser.release();"));
    if (!/co_await\s+wire::async_read\s*\(/.test(exchange)
        || !/parser\.body_limit\(m_maxBodyBytes\)/.test(exchange)
        || !/parser\.header_limit\(/.test(exchange)
        || !/beast::get_lowest_layer\(stream\)\.socket\(\)\.close\(ignored\)/.test(afterResponse)
        || /co_await\s+stream\.async_shutdown\s*\(/.test(afterResponse))
      issues.push({line:0,kind:"native OAuth HTTPS completion still waits for TLS peer close or skips framing checks",
        expression:"bounded async HTTP read then immediate socket close, never async_shutdown"});
  }
  if(relative==="src/providers/enterprise/enterprise.cpp"){
    // The old OpenLDAP network bind and search have been deleted, not moved
    // to another synchronous worker. A compatibility completion must deny
    // all calls; only the native Asio LDAPS verifier may authenticate.
    const legacy = executable.slice(
      executable.indexOf("LdapAuthenticationProvider::completeAuthentication("),
      executable.indexOf("LdapAuthenticationProvider::beginAuthenticationAsync("));
    if(!/foundation::fail\(foundation::ErrorCode::Unavailable/.test(legacy)
       || /\b(?:openLdap|simpleBind|ldap_search|ldap_sasl_bind|co_spawn|context\.run)\s*\(/.test(legacy))
      issues.push({line:0,kind:"LDAP synchronous compatibility can still execute network I/O",
        expression:"sync LDAP completion must deny; native LDAPS verifier is async-only"});
    // LDAP is a ChallengeResponse provider: /auth/ldap/start and
    // /auth/ldap/complete live in enterprise.cpp, not in the federated
    // redirect callback. Never count unrelated OAuth work as LDAP coverage.
    // The configured directory must use the native stack. Source-level
    // wiring is not a replacement for build/E2E or production acceptance.
    const enterpriseHttp = cppExecutableText(fs.readFileSync(
      path.join(root,"src/authentication/http/enterprise.cpp"),"utf8"));
    const ldapNative = enterpriseHttp.slice(
      enterpriseHttp.indexOf("EnterpriseAuthenticationHttpApi::handleAsync("));
    const appSource = fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
    const app = cppExecutableText(appSource);
    const nativeWiring = /co_await\s+m_authentication->beginAsync\s*\(/.test(ldapNative)
      && /co_await\s+m_authentication->completeAsync\s*\(/.test(ldapNative)
      && /co_await\s+m_asyncSessions->issueReplacingAsync\s*\(/.test(ldapNative)
      && !/m_sessions->issue\s*\(/.test(ldapNative)
      && /std::make_unique<\s*postgres::CoroutinePostgresAuthenticationTransactionStore>/.test(app)
      && /std::make_unique<\s*postgres::CoroutinePostgresCanonicalFinalizer>/.test(app)
      && /std::make_unique<\s*postgres::CoroutinePostgresSessionRepository>/.test(app)
      && /std::make_unique<\s*postgres::CoroutinePostgresSessionService>/.test(app)
      && /std::make_unique<auth::AuthenticationService>/.test(app)
      && /nativeCanonical.get\(\)/.test(app)
      && /nativeAuthentication\s*\?\s*\*nativeAuthentication\s*:\s*authentication/.test(app)
      && /fallback, nativeSessions.get\(\)/.test(app)
      && /auto nativeTrust = trust;/.test(app)
      && /CoroutineRouteOverlay nativeRoutes/.test(app)
      && /runListener\(platform, nativeRoutes, logger\)/.test(app)
      && /runWithScim\(enterpriseApi, enterpriseApi\)/.test(app)
      // Exact paths must be added ONLY for enabled LDAP configuration.
      // An independent Web3 opt-in must not expose an unconfigured directory.
      && /if\s*\(nativeLdapEnabled\)\s*\{\s*nativePaths\.emplace_back\("\/auth\/ldap\/start"\);\s*nativePaths\.emplace_back\("\/auth\/ldap\/complete"\)/.test(appSource)
      && /nativeHandler\s*=\s*&nativeEnterprise/.test(app)
      && /CoroutineRouteOverlay\s+nativeRoutes\s*\{\s*evidenceApi\s*,\s*nativeHealth\s*,\s*std::move\(nativePaths\)/.test(app)
      && /CoroutineHealthAdapter nativeHealth\{\*nativeHandler,/.test(app);
    if (!nativeWiring)
      issues.push({line:0,kind:"LDAP native HTTP login not connected to runtime transaction/canonical/session stack",
        expression:"real /auth/ldap start+complete -> native auth + canonical finalizer + PostgreSQL session issuer"});
    // Configured LDAP must select the native-only path by default.
    // Require the positive configuration predicate, explicit override,
    // validation and fail-closed dependency check, not just absence of the
    // previous experimental expression. Full live E2E remains mandatory.
    else if (!/const\s+auto\s+ldapUri\s*=\s*environment\.get\("OPENPROOF_LDAP_URI"\)/.test(appSource)
      || !/const\s+bool\s+nativeLdapEnabled\s*=\s*nativeLdapFlag\s*\?\s*\*nativeLdapFlag\s*==\s*"1"\s*:\s*ldapUri\s*&&\s*!ldapUri->empty\(\)\s*;/.test(appSource)
      || !/nativeLdapFlag\s*&&\s*\*nativeLdapFlag\s*!=\s*"0"\s*&&\s*\*nativeLdapFlag\s*!=\s*"1"/.test(appSource)
      || !/if\s*\(nativeLdapEnabled\)\s*\{\s*if\s*\(!platform\.auth\(\)\.enabled\(\)\s*\|\|\s*!ldapUri\s*\|\|\s*ldapUri->empty\(\)\)/.test(appSource))
      issues.push({line:0,kind:"LDAP configured native default or fail-closed override is missing",
        expression:"configured LDAP -> native by default; explicit 0 disables; invalid configuration fails closed"});

    const iface = fs.readFileSync(
      path.join(root,"src/providers/enterprise/enterprise.cppm"),"utf8");
    const native = cppExecutableText(fs.readFileSync(
      path.join(root,"src/providers/enterprise/async_ldaps.cpp"),"utf8"));
    const nativeCompletion = executable.slice(
      executable.indexOf("LdapAuthenticationProvider::completeAuthenticationAsync("),
      executable.indexOf("SamlProviderConfig::SamlProviderConfig("));
    if(!/class\s+LdapAuthenticationProvider\s+final\s*:\s*public\s+identity::provider::AuthenticationProvider,\s*public\s+identity::provider::CoroutineAuthenticationProvider/.test(iface)
       || !/co_await\s+async_detail::AsyncLdapsClient::authenticate\s*\(/.test(nativeCompletion)
       || !/security::constantTimeEquals/.test(nativeCompletion)
       || !/resolver\.async_resolve\s*\(/.test(native)
       || !/async_connect\s*\(/.test(native)
       || !/stream\.async_handshake\s*\(/.test(native)
       || !/asio::async_read\s*\(/.test(native)
       || !/asio::async_write\s*\(/.test(native)
       || !/ssl::host_name_verification\s*\(/.test(native)
       || !/kMaximumLdapFrame\s*=\s*65536U/.test(native)
       || !/kTotalDeadline/.test(native)
       || /\bldap_\w+\s*\(/.test(native)
       || /\b(?:io|context)\.run\s*\(/.test(native))
      issues.push({line:0,kind:"LDAP native provider lacks bounded nonblocking TLS transport",
        expression:"native CoroutineAuthenticationProvider -> Asio TLS/BER bind/search"});
  }
  if(relative==="src/authentication/http/enterprise.cpp"){
    const iface=fs.readFileSync(
      path.join(root,"src/authentication/http/enterprise.cppm"),"utf8");
    const compatibility=executable.slice(
      executable.indexOf("EnterpriseAuthenticationHttpApi::startLdap("),
      executable.indexOf("EnterpriseAuthenticationHttpApi::nativeEnabledFor("));
    const native=executable.slice(
      executable.indexOf("EnterpriseAuthenticationHttpApi::handleAsync("));
    const cap=executable.slice(
      executable.indexOf("EnterpriseAuthenticationHttpApi::nativeEnabledFor("),
      executable.indexOf("EnterpriseAuthenticationHttpApi::handleAsync("));
    if(!/public gateway::http::CoroutineHttpHandler/.test(iface)
       || !/nativeEnabled\(\) const noexcept override \{ return false; \}/.test(iface)
       || !/session::CoroutineReplacingSessionIssuer\* asyncSessions = nullptr/.test(iface)
       || !/m_asyncSessions == nullptr/.test(cap)
       || !/m_authentication->nativeProviderAuthenticationEnabled/.test(cap)
       || !/if \(!nativeEnabledFor\(request\)\)/.test(native)
       || !/co_await m_authentication->beginAsync\(/.test(native)
       || !/co_await m_authentication->completeAsync\(/.test(native)
       || !/co_await m_asyncSessions->issueReplacingAsync\(/.test(native)
       || !/co_await native->handleAsync\(/.test(native)
       || !/foundation::ErrorCode::Unavailable/.test(compatibility)
       || /m_authentication->(?:begin|complete)\s*\(/.test(compatibility)
       || /m_sessions->(?:issue|authenticate)\s*\(/.test(compatibility)
       || /m_sessions->/.test(native)
       || /m_fallback->handle\s*\(/.test(native))
      issues.push({line:0,
        kind:"enterprise LDAP HTTP coroutine can bypass async readiness or execute blocking credentials/session",
        expression:"native provider+issuer readiness, awaited proof and persisted session, denied compatibility"});
    const completion=executable.slice(
      executable.indexOf("EnterpriseAuthenticationHttpApi::completeLdapAsync("));
    const parsedGuard=completion.indexOf("SensitiveParsedPasswordGuard wipeParsedOnExit");
    const fieldValidation=completion.indexOf("!onlyFields(body.value()");
    const copiedGuard=completion.indexOf("SensitiveCredentialCopyGuard wipePasswordCopyOnExit");
    const earlyReturn=completion.indexOf("if (!transaction || !challenge");
    const beforeVerify=completion.indexOf("co_await m_authentication->completeAsync(");
    const requestType=fs.readFileSync(path.join(root,"src/gateway/gateway.cppm"),"utf8");
    const requestImpl=cppExecutableText(fs.readFileSync(
      path.join(root,"src/gateway/gateway.cpp"),"utf8"));
    if(!/class SensitiveParsedPasswordGuard final/.test(executable)
       || !/class SensitiveCredentialCopyGuard final/.test(executable)
       || !/class SensitiveRequestCookieGuard final/.test(executable)
       || !/void wipeCookieHeader\(\) noexcept/.test(requestType)
       || !/void HttpRequest::wipeCookieHeader\(\) noexcept/.test(requestImpl)
       || !/foundation::secureWipe\(found->second.data\(\), found->second.size\(\)\)/.test(requestImpl)
       || parsedGuard < 0 || fieldValidation < 0 || parsedGuard > fieldValidation
       || copiedGuard < 0 || earlyReturn < 0 || copiedGuard > earlyReturn
       || !/SensitiveCredentialCopyGuard wipeContinuationOnExit/.test(completion)
       || !/SensitiveCredentialCopyGuard wipeBindingOnExit/.test(completion)
       || beforeVerify < 0
       || completion.indexOf("request.wipeBody();") < 0
       || completion.indexOf("request.wipeBody();") > beforeVerify
       || completion.indexOf("request.wipeCookieHeader();") < 0
       || completion.indexOf("request.wipeCookieHeader();") > beforeVerify
       || !/foundation::SecretString continuationSecret\{std::move\(\*continuation\)\}/.test(completion))
      issues.push({line:0,
        kind:"LDAP HTTP credential copies or cookies are retained on early error or coroutine suspension",
        expression:"RAII scrub parsed JSON, extracted password, cookie copies, and request-owned credential buffers"});
    // A native LDAP login must not leave an authenticated prior browser
    // session active. Require the stronger atomic replacement capability,
    // a scrubbed owned token before suspension, and SQL issuer integration.
    const replacement=completion.indexOf(
      "co_await m_asyncSessions->issueReplacingAsync(");
    const previousOwner=completion.indexOf(
      "std::optional<foundation::SecretString> previousSessionToken");
    const previousGuard=completion.indexOf(
      "SensitiveCredentialCopyGuard wipePreviousSessionOnExit");
    const cookieRead=source.includes(
      'cookieValue(request, "__Host-openproof-session")');
    if(!cookieRead
       || !iface.includes("session::CoroutineReplacingSessionIssuer* m_asyncSessions")
       || previousGuard < 0 || previousOwner < 0
       || previousGuard > beforeVerify || previousOwner > beforeVerify
       || replacement < 0 || replacement < beforeVerify
       || !completion.includes("std::move(previousSessionToken)")
       || completion.includes("m_asyncSessions->issueAsync(")
       || !source.includes('required(body.value(), "password", 1024U)')
       || !completion.includes("bearer.empty() || bearer.size() > 128U"))
      issues.push({line:0,
        kind:"LDAP native re-login does not atomically replace the prior browser session",
        expression:"CoroutineReplacingSessionIssuer, scrubbed old cookie, issueReplacingAsync and native SQL replace"});
    if (!completion.includes("const auto& bearer = grant->token.expose();")
        || completion.includes("const auto bearer = grant->token.expose();"))
      issues.push({line:0,
        kind:"LDAP issuer copies an unprotected bearer token after native persistence",
        expression:"reference returned SecretString::expose(), never copy into plain std::string"});
  }
  if(relative==="src/authentication/service.cpp"){
    const nativeReady = source.slice(
      source.indexOf("AuthenticationService::nativeProviderAuthenticationEnabled("),
      source.indexOf("foundation::Result<AuthenticationStart> AuthenticationService::begin("));
    for (const [kind, expression] of [
      ["native provider capability", /CoroutineAuthenticationProvider/],
      ["native transaction capability", /CoroutineAuthenticationTransactionStore/],
      ["canonical finalizer capability", /m_asyncCanonical\s*==\s*nullptr/],
      ["operator trust policy", /effectiveMaximum\s*\(/]
    ]) {
      if (!expression.test(nativeReady))
        issues.push({line:0,kind:"missing "+kind,expression:expression.source});
    }
    const begin = source.slice(
      source.indexOf("AuthenticationService::beginAsync("),
      source.indexOf("AuthenticationService::beginConnectionAsync("));
    const completion = source.slice(
      source.indexOf("AuthenticationService::completeAsync("),
      source.indexOf("AuthenticationService::finishVerified("));
    if(!/if\s*\(m_asyncCanonical\s*==\s*nullptr\)/.test(begin))
      issues.push({line:0,kind:"missing pre-challenge canonical gate",
        expression:"m_asyncCanonical == nullptr"});
    if(!/if\s*\(finalizer\s*==\s*nullptr\)/.test(completion)
       || completion.indexOf("finalizer == nullptr")
          > completion.indexOf("completeExchangeAsync("))
      issues.push({line:0,kind:"missing pre-redemption canonical gate",
        expression:"finalizer == nullptr before completeExchangeAsync"});
    if(!/\bco_await\s+finalizer->finishLoginAsync\s*\(/.test(completion)
       || /\bfinishVerified\s*\(/.test(completion))
      issues.push({line:0,kind:"blocking canonical completion in coroutine",
        expression:"co_await finalizer->finishLoginAsync"});
    const connectionStart = source.slice(
      source.indexOf("AuthenticationService::beginConnectionAsync("),
      source.indexOf("AuthenticationService::beginInternal("));
    const connectionFinish = source.slice(
      source.indexOf("AuthenticationService::completeConnectionAsync("),
      source.indexOf("AuthenticationService::finishConnection("));
    if(!/co_await\s+finalizer->authorizeConnectionTargetAsync\s*\(/.test(connectionStart)
       || /\brequireActiveIdentity\s*\(/.test(connectionStart)
       || !/finalizer->nativeConnectionsEnabled\s*\(\)/.test(connectionStart))
      issues.push({line:0,kind:"blocking native connection start",
        expression:"authorizeConnectionTargetAsync"});
    if(!/co_await\s+finalizer->finishConnectionAsync\s*\(/.test(connectionFinish)
       || /\bfinishConnection\s*\(/.test(connectionFinish)
       || !/finalizer->nativeConnectionsEnabled\s*\(\)/.test(connectionFinish)
       || connectionFinish.indexOf("finalizer->nativeConnectionsEnabled()")
          > connectionFinish.indexOf("completeExchangeAsync("))
      issues.push({line:0,kind:"blocking native connection finalization",
        expression:"finishConnectionAsync before proof redemption"});
    const nativeTransactions = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_auth_transaction_store.cpp"),"utf8");
    const beginAt = nativeTransactions.indexOf(
      "CoroutinePostgresAuthenticationTransactionStore::beginAsync(");
    const consumeAt = nativeTransactions.indexOf(
      "CoroutinePostgresAuthenticationTransactionStore::consumeAsync(");
    const syncBeginAt = nativeTransactions.indexOf(
      "CoroutinePostgresAuthenticationTransactionStore::begin(");
    const beginNative = nativeTransactions.slice(beginAt,consumeAt);
    const consumeNative = nativeTransactions.slice(consumeAt,syncBeginAt);
    for (const [kind, method] of [
        ["begin",beginNative],["consume",consumeNative]]) {
      if(!/const Deadline deadline = Clock::now\(\) \+ m_impl->queryTimeout/.test(method)
         || !/m_impl->pool\.acquire\(deadline\)/.test(method)
         || !/remaining\(deadline\)/.test(method)
         || /m_impl->pool\.acquire\(\)/.test(method))
        issues.push({line:0,kind:"native authentication transaction "+kind+" restarts its SQL timeout after pool admission",
          expression:"one absolute deadline across pool and atomic transaction"});
    }
    // A proof challenge can carry up to 64 metadata pairs. Inserting one
    // SQL statement per pair burns the single request deadline on latency.
    // Keep user strings in libpq parameters, never interpolate them into SQL.
    const transactionSql = fs.readFileSync(
      path.join(root,"src/storage/postgres/async_auth_transaction.cpp"),"utf8");
    const transactionBegin = transactionSql.slice(
      transactionSql.indexOf("AsyncAuthenticationTransactionSql::begin("),
      transactionSql.indexOf("AsyncAuthenticationTransactionSql::consume("));
    const batchStart = transactionBegin.indexOf("if (!row.metadata.empty())");
    const batch = transactionBegin.slice(batchStart,transactionBegin.indexOf("co_return true;"));
    if(batchStart < 0
       || !/parameters\.reserve\(row\.metadata\.size\(\) \* 3U\)/.test(batch)
       || !/parameters\.emplace_back\(key\)/.test(batch)
       || !/parameters\.emplace_back\(std::move\(value\)\)/.test(batch)
       || !/std::move\(insert\), std::move\(parameters\), remaining\(deadline\)/.test(batch)
       || (batch.match(/\bco_await\b/g) || []).length !== 2)
      issues.push({line:0,kind:"native authentication metadata still uses repeated SQL insert roundtrips",
        expression:"one bounded parameterized multi-value INSERT before COMMIT"});
    const transactionConsume = transactionSql.slice(
      transactionSql.indexOf("AsyncAuthenticationTransactionSql::consume("));
    if(!/kMaximumTransactionMetadataRows\s*=\s*64U/.test(transactionSql)
       || !/row\.metadata\.size\(\)\s*>\s*kMaximumTransactionMetadataRows/.test(transactionBegin)
       || !/WHERE transaction_id=\$1 ORDER BY key LIMIT/.test(transactionConsume)
       || !/kMaximumTransactionMetadataRows \+ 1U/.test(transactionConsume)
       || !/values\.rows\.size\(\) > kMaximumTransactionMetadataRows/.test(transactionConsume))
      issues.push({line:0,kind:"native authentication redemption fetches unbounded metadata",
        expression:"SQL LIMIT 65 before materializing up to 64 metadata rows"});

  }
  if(relative==="src/storage/postgres/coroutine_canonical_finalizer.cpp"){
    const checks=[
      ["tenant-scoped canonical read", /i\.organization_id=\$3\s+AND\s+i\.status=0/],
      ["active canonical target", /i\.organization_id=\$2\s*"\s*"AND i\.status=0/],
      ["active tenant lifecycle", /o\.state=0/],
      ["tenant-row lifecycle lock", /FOR SHARE OF o/],
      ["canonical row lifecycle lock", /FOR UPDATE OF i/],
      ["canonical profile serialization", /mutationLock\s*\?\s*" FOR UPDATE OF i FOR SHARE OF o"/],
      ["atomic owner-conflict guard", /ON CONFLICT\(provider,external_subject\) DO UPDATE/],
      ["no implicit owner reassignment", /WHERE openproof\.external_identities\.identity_id=EXCLUDED\.identity_id/],
      ["connection presentation-only claims", /ProfilePurpose::Connection/],
      ["login verified-contact claims", /ProfilePurpose::Login/],
      ["profile domain refresh", /co_await\s+saveProfile\s*\(/],
      ["no-op profile WAL suppression", /IS DISTINCT FROM ROW\(EXCLUDED\.display_name/],
      ["SQL commit", /co_await\s+connection\.query\s*\(\s*"COMMIT"/],
      ["bounded coroutine pool", /co_await\s+m_impl->pool\.acquire\s*\(deadline\)/]
    ];
    for(const [kind, regex] of checks)
      if(!regex.test(source))
        issues.push({line:0,kind:"missing "+kind,expression:regex.source});
    if(/\b(?:telegram|genycaster|genyleap)\b/i.test(source))
      issues.push({line:0,kind:"provider-specific canonical storage dependency",
        expression:"native canonical storage must be provider-neutral"});
  }
  if(relative==="src/storage/postgres/async_pool.cpp"){
    for(const [kind, regex] of [
      ["pool uses a caller deadline", /AsyncConnectionPool::acquire\(\s*std::chrono::steady_clock::time_point deadline/],
      ["deadline bounds pool wait", /bounded\(state->acquireTimeout\)/],
      ["deadline bounds connect", /bounded\(state->connectTimeout\)/],
      ["sub-millisecond deadline fails closed", /if\s*\(remaining\s*<=\s*std::chrono::milliseconds::zero\(\)\)/],
      ["post-acquisition expiry gate", /static_cast<void>\(bounded\(state->connectTimeout\)\)/]
    ])
      if(!regex.test(source))
        issues.push({line:0,kind:"missing "+kind,expression:regex.source});
  }
  if(relative==="src/storage/postgres/async_connection.cpp"){
    for(const [kind, regex] of [
      ["bounded Asio DNS", /co_await\s+resolver\.async_resolve\s*\(/],
      ["DNS consumes shared deadline", /asio::cancel_after\s*\(\s*deadline\s*-\s*Clock::now\s*\(\)/],
      ["libpq hostname preserved for TLS", /ownedKeys\.emplace_back\s*\(\s*"hostaddr"\s*\)/],
      ["libpq numeric address connection", /PQconnectStartParams\s*\(/],
      ["nonblocking libpq connection polling", /PQconnectPoll\s*\(/],
      ["scrub parsed credentials before polling", /options\.reset\s*\(\s*\)/],
      ["descriptor constructed before fd duplication", /asio::posix::stream_descriptor\s+descriptor\s*\{\s*executor\s*\};[\s\S]*?::dup\s*\(\s*originalFd\s*\)/],
      ["duplicated fd is closed on Asio adoption failure", /descriptor\.assign\s*\(\s*fd\s*,\s*assignmentError\s*\);[\s\S]*?if\s*\(\s*assignmentError\s*\)\s*\{\s*\(void\)::close\s*\(\s*fd\s*\)/],
      ["multi-host native enumeration", /for\s*\(std::size_t\s+i\s*=\s*0;\s*i\s*<\s*hosts\.size\s*\(\s*\)/],
      ["multi-host port association", /ports\.size\s*\(\s*\)\s*!=\s*hosts\.size\s*\(\s*\)/],
      ["failed DNS hostname cannot suppress HA fallback", /if\s*\(error\s*\|\|\s*endpoints\.empty\s*\(\s*\)\)/],
      ["empty DNS result fails closed", /if\s*\(addressCount\s*==\s*0U\)/],
      ["partial hostaddr still resolves asynchronously", /const\s+auto\s+pinnedAddresses\s*=\s*csv\s*\(hostaddr\)/],
      ["pinned hostaddr selection is explicit", /if\s*\(\s*!pinned\.empty\s*\(\s*\)\s*\)/],
      ["inherited hostname is explicit", /effective\s*\(\s*"host"\s*,\s*"PGHOST"\s*\)/],
      ["inherited pinned address is explicit", /effective\s*\(\s*"hostaddr"\s*,\s*"PGHOSTADDR"\s*\)/],
      ["inherited port list is explicit", /effective\s*\(\s*"port"\s*,\s*"PGPORT"\s*\)/],
      ["cancelled DNS must not silently retry HA hosts", /error\s*==\s*asio::error::operation_aborted\s*\|\|\s*error\s*==\s*asio::error::timed_out/],
      ["cancelled DNS throws before HA skip", /throw\s+std::runtime_error\s*\{\s*"PostgreSQL DNS resolution cancelled"\s*\}/],
      ["service-file indirection must not restart blocking DNS", /optionValue\s*\(\s*"service"\s*\)\.empty\s*\(\s*\)/],
      ["inherited PGSERVICE must be checked", /std::getenv\s*\(\s*"PGSERVICE"\s*\)/],
      ["unsupported service files fail closed", /PostgreSQL service files are unsupported by the native connector/]
    ]){
      if(!regex.test(source)) issues.push({line:0,kind:"missing "+kind,expression:regex.source});
    }
  }
  if(relative==="src/storage/postgres/coroutine_session_service.cpp"){
    if(!/CoroutinePostgresSessionService::issueAsync\s*\(/.test(source)
        || !/\bco_await\s+issue\s*\(/.test(source))
      issues.push({line:0,kind:"missing native session issuer adapter",expression:"issueAsync / co_await issue"});
    if(!/CoroutinePostgresSessionService::issueReplacingAsync\s*\(/.test(source)
       || !/co_await\s+issueReplacing\s*\(/.test(source))
      issues.push({line:0,kind:"missing atomic native session replacement",
        expression:"issueReplacingAsync / co_await issueReplacing"});
    // Once a durable bearer exists, the native HTTP grant must receive
    // ownership, not clone a second sensitive allocation inside the frame.
    const serviceHeader = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_session_service.hpp"),"utf8");
    if (!serviceHeader.includes("foundation::SecretString takeToken() && noexcept")
        || !source.includes("CoroutineSessionGrant::takeToken() && noexcept")
        || (source.match(/std::move\(\*issued\)\.takeToken\(\)/g) || []).length !== 2
        || source.includes("issued->token().clone()"))
      issues.push({line:0,kind:"native session grant duplicates persisted bearer on coroutine return",
        expression:"rvalue-only takeToken transfers SecretString for both issuer variants"});
    // Session storage cannot restart its SQL budget after waiting on the pool.
    // This catches a class of reactor saturation/response-time regressions
    // without falsely approving the still-blocking legacy PostgreSQL SPI.
    const repo = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_session_repository.cpp"),"utf8");
    const methods = ["use","find","replace","rotate","revoke",
      "revokeOwned","revokeAll","list","listActive","purgeExpired","size"];
    const allBounded = methods.every((name) => {
      const start = repo.indexOf("CoroutinePostgresSessionRepository::"+name+"(");
      if(start < 0) return false;
      const end = repo.indexOf("CoroutinePostgresSessionRepository::",start+30);
      const method = repo.slice(start,end<0 ? undefined : end);
      return /const Deadline deadline = Clock::now\(\) \+ m_impl->queryTimeout/.test(method)
        && /m_impl->pool\.acquire\(deadline\)/.test(method)
        && /remaining\(deadline\)/.test(method)
        && !/m_impl->pool\.acquire\(\)/.test(method);
    });
    if(!allBounded
        || !/pool\.acquire\(deadline\)/.test(repo.slice(
             repo.indexOf("insertCapturedSession("),
             repo.indexOf("class CoroutinePostgresSessionRepository::Impl"))))
      issues.push({line:0,kind:"native session operations restart their budget after pool acquisition",
        expression:"shared monotonic deadline for pool, DISCARD ALL and SQL"});
  }
  if(relative==="src/storage/postgres/coroutine_session_listener.cpp"){
    if(!/if\s*\(\s*!allowPartialNativeFallback\s*&&\s*!fallback\.nativeEnabled\s*\(\s*\)\s*\)/.test(source))
      issues.push({line:0,kind:"coroutine session listener accepts disabled native fallback without explicit partial-native opt-in",
        expression:"!allowPartialNativeFallback && !fallback.nativeEnabled()"});
    if(!/throw\s+std::invalid_argument/.test(source))
      issues.push({line:0,kind:"listener composition must reject inactive fallback",
        expression:"throw std::invalid_argument"});
    if(!/\!fallback\.nativeEnabledFor\s*\(\s*request\s*\)/.test(source))
      issues.push({line:0,kind:"coroutine listener ignores per-request native fallback capability",
        expression:"!fallback.nativeEnabledFor(request)"});
    const nativeGuard = executable.slice(
      executable.indexOf("CoroutineSessionListenerAdapter::nativeEnabledFor("),
      executable.indexOf("CoroutineSessionListenerAdapter::handle("));
    const syncEntry = executable.slice(
      executable.indexOf("CoroutineSessionListenerAdapter::handle("),
      executable.indexOf("CoroutineSessionListenerAdapter::handleAsync("));
    if (!/return\s+true\s*;/.test(nativeGuard)
        || /m_fallback|allowCompatibilityFallback|m_allowCompatibilityFallback/.test(nativeGuard)
        || !/foundation::ErrorCode::Unavailable/.test(syncEntry)
        || /(?:m_fallback|fallback)\s*(?:->|\.)\s*handle\s*\(/.test(syncEntry))
      issues.push({line:0,kind:"native listener can enter blocking compatibility dispatch",
        expression:"nativeEnabledFor always true; sync handle fails closed"});
    if(!/m_network\s*\(\s*m_application\s*\)/.test(source))
      issues.push({line:0,kind:"native listener is not composed without a synchronous delegate",
        expression:"m_network(m_application)"});
    const sessionRoutes = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_session_http.cpp"),"utf8");
    const sessionRoutePredicate = sessionRoutes.slice(
      sessionRoutes.indexOf("bool CoroutineSessionHttpHandler::isSessionRoute("),
      sessionRoutes.indexOf("CoroutineSessionHttpHandler::handleAsync("));
    for (const route of ["/auth/session/rotate", "/auth/logout", "/auth/logout-all"]) {
      if(!sessionRoutePredicate.includes('"' + route + '"'))
        issues.push({line:0,kind:"native session mutation may reach legacy compatibility",
          expression:route});
    }
    // Rejected/limited native session mutations must erase the raw
    // Authorization and Cookie headers even before credential extraction.
    const mutation= sessionRoutes.slice(sessionRoutes.indexOf("sessionMutation("),
      sessionRoutes.indexOf("CoroutineSessionHttpHandler::CoroutineSessionHttpHandler("));
    const mutationGuard = sessionRoutes.slice(
      sessionRoutes.indexOf("class SensitiveSessionHeadersGuard final"),
      sessionRoutes.indexOf("[[nodiscard]] gateway::HttpResponse safeResponse("));
    if(!mutationGuard.includes("m_request.wipeAuthorizationHeader()")
       || !mutationGuard.includes("m_request.wipeCookieHeader()")
       || !mutation.includes("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}")
       || mutation.indexOf("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}")
          > mutation.indexOf("limiter.allow("))
      issues.push({line:0,kind:"native rotate/logout leaves session credentials in rejected request buffers",
        expression:"RAII wipe Authorization/Cookie before rate-limit and method rejection"});
    // Partial-native composition cannot bypass the awaitable entry for any
    // route, including unknown routes and provider capability revocation.
    if(/\bm_fallback->handle\s*\(/.test(executable)
       || /\ballowCompatibilityFallback\b/.test(executable))
      issues.push({line:0,kind:"coroutine listener still exposes synchronous compatibility work",
        expression:"no blocking fallback and no compatibility opt-in"});
    if(!/co_return\s+co_await\s+fallback\.handleAsync\s*\(/.test(source))
      issues.push({line:0,kind:"listener fallback must use native awaitable dispatch",
        expression:"co_await fallback.handleAsync"});
    if(/\bfallback\.handle\s*\(/.test(source))
      issues.push({line:0,kind:"listener fallback may not call synchronous handler",
        expression:"fallback.handle("});
    const listenerInterface = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_session_listener.hpp"),"utf8");
    if(!/class\s+CoroutineSessionListenerAdapter[\s\S]*?nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+true;\s*\}/.test(listenerInterface))
      issues.push({line:0,kind:"native PostgreSQL listener lacks explicit opt-in",
        expression:"CoroutineSessionListenerAdapter::nativeEnabled() true"});
  }
  if(relative==="src/authentication/http/http.cpp"){
    // The login leaf must have no synchronous credential or session SPI.
    // The executable must compose all six strict native auth paths, with
    // no legacy constructor or runtime opt-out in authenticated mode.
    const nativeInterface = fs.readFileSync(
      path.join(root,"src/authentication/http/http.cppm"),"utf8");
    const app = fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
    const runtime = cppExecutableText(app);
    const authConstructors = [...runtime.matchAll(/authHttp::AuthenticationHttpApi\s+\w+\s*\{([\s\S]*?)\};/g)];
    const syncEntry = executable.slice(executable.indexOf("AuthenticationHttpApi::handle("),
      executable.indexOf("AuthenticationHttpApi::nativeEnabledFor("));
    if (!/bool\s+nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+false;\s*\}/.test(nativeInterface)
        || /\b(?:m_sessions|m_recoveryCodes|m_localAccounts)\b/.test(nativeInterface)
        || /\b(?:session::SessionService|credentials::RecoveryCodeService|LocalAccountDirectory)\b/.test(nativeInterface)
        || /AuthenticationHttpApi::(?:login|verify|rotate|logout|issueRecoveryCodes)\s*\(/.test(executable)
        || /\bm_authentication->(?:begin|complete)\s*\(/.test(executable)
        || !/SensitiveAuthRequestGuard\s+wipeRequestOnExit\{request\}/.test(syncEntry)
        || !/return\s+error\(foundation::Error\{foundation::ErrorCode::Unavailable\}/.test(syncEntry)
        || authConstructors.length !== 3
        || authConstructors.some(([,args]) => !/^\s*\*nativeLocalAuthentication,\s*\*nativeSessions,/.test(args)))
      issues.push({line:0,kind:"synchronous authentication HTTP entry or dependency remains reachable",
        expression:"native-only login leaf and fail-closed synchronous entry"});
    const flagStart=app.indexOf("const auto nativeLocalFlag");
    const serveMigration=app.indexOf("postgres::Migrator migrator{*pool.value()}",flagStart);
    const beforeMigration=flagStart>=0 && serveMigration>flagStart
      ? app.slice(flagStart,serveMigration) : "";

    for (const [enabled,flag] of [["nativeLocalEnabled","nativeLocalFlag"],
        ["nativeAuthSessionEnabled","nativeAuthSessionFlag"],["nativeRecoveryEnabled","nativeRecoveryFlag"]]) {
      const declaration="const bool "+enabled+" = platform.auth().enabled()";
      const rejection=beforeMigration.indexOf("if (platform.auth().enabled() && "+flag+' && *'+flag+' == "0") {');
      const rejectionEnd=beforeMigration.indexOf("}",beforeMigration.indexOf("return ExitCode::ConfigurationError;",rejection));
      const rejectBlock=rejection>=0 && rejectionEnd>rejection
        ? beforeMigration.slice(rejection,rejectionEnd) : "";
      if (!beforeMigration.includes(declaration)
          || !rejectBlock.includes("return ExitCode::ConfigurationError;"))
        issues.push({line:0,kind:"authenticated runtime can disable native auth dependency",expression:enabled});
    }
    for (const route of ["/auth/login","/auth/mfa/verify","/auth/session/rotate",
        "/auth/logout","/auth/logout-all","/auth/recovery-codes"]) {
      if (!app.includes('nativePaths.emplace_back("'+route+'")'))
        issues.push({line:0,kind:"missing strict native authentication overlay",expression:route});
    }
    if (!runtime.includes("std::make_unique<postgres::CoroutineSessionListenerStack>")
        || !runtime.includes("std::make_unique<authHttp::CoroutineRecoveryCodeHttpAdapter>")
        || !runtime.includes("nativeHandler = &asyncAuthSessions->handler()")
        || !runtime.includes("nativeHandler = asyncRecovery.get()")
        || !runtime.includes("gatewayHttp::CoroutineRouteOverlay nativeRoutes{"))
      issues.push({line:0,kind:"native session and recovery handlers missing from runtime composition",
        expression:"strict native route overlay with session listener and recovery adapter"});
    const preauth=source.slice(source.indexOf("preauthBinding("),
      source.indexOf("decodePreauthSubject(",source.indexOf("preauthBinding(")));
    if(!source.includes("class SensitiveBindingMaterialGuard final")
       || !source.includes("foundation::secureWipe(m_value.data(), m_value.size())")
       || !preauth.includes("SensitiveBindingMaterialGuard wipeMaterialOnExit{material}")
       || preauth.indexOf("wipeMaterialOnExit{material}") > preauth.indexOf("material.append(bindingToken)"))
      issues.push({line:0,kind:"preauthentication HMAC secret input is not scrubbed on all exits",
        expression:"RAII secureWipe of browser-bound binding HMAC material"});
    const nativeSection = source.slice(
      source.indexOf("AuthenticationHttpApi::handleAsync("));
    for(const [kind,regex] of [
      ["native provider capability guard", /nativeEnabledFor\s*\(request\)/],
      ["native challenge start", /co_await\s+m_authentication->beginAsync\s*\(/],
      ["native proof completion", /co_await\s+m_authentication->completeAsync\s*\(/],
      ["atomic native session replacement", /co_await\s+m_asyncSessions->issueReplacingAsync\s*\(/]
    ]) if(!regex.test(nativeSection))
      issues.push({line:0,kind:"missing "+kind,expression:regex.source});
    if(/\bm_sessions->/.test(nativeSection))
      issues.push({line:0,kind:"native HTTP authentication uses legacy session service",
        expression:"m_sessions->"});
    if (!nativeSection.includes("const auto& bearer = issued->token.expose();")
        || nativeSection.includes("const auto bearer = issued->token.expose();"))
      issues.push({line:0,
        kind:"native HTTP authentication copies an unprotected bearer token",
        expression:"reference returned SecretString::expose(), never copy into plain std::string"});
    const localLogin=source.slice(source.indexOf("AuthenticationHttpApi::loginAsync("),
      source.indexOf("AuthenticationHttpApi::verifyAsync("));
    const localVerify=source.slice(source.indexOf("AuthenticationHttpApi::verifyAsync("));
    const awaited=localVerify.indexOf("co_await m_authentication->completeAsync(");
    const rawGuard=source.slice(source.indexOf("class SensitiveAuthRequestGuard final"),
      source.indexOf("class SensitiveParsedAuthSecretsGuard final"));
    const parsedGuard=source.slice(source.indexOf("class SensitiveParsedAuthSecretsGuard final"),
      source.indexOf("class SensitiveAuthCopyGuard final"));
    const copyGuard=source.slice(source.indexOf("class SensitiveAuthCopyGuard final"),
      source.indexOf("[[nodiscard]] gateway::HttpResponse response("));
    const cookieParser=source.slice(source.indexOf("cookieValue("),
      source.indexOf("clientContext(", source.indexOf("cookieValue(")));
    if(!rawGuard.includes("m_request.wipeBody()")
       || !rawGuard.includes("m_request.wipeCookieHeader()")
       || !rawGuard.includes("m_request.wipeAuthorizationHeader()")
       || !parsedGuard.includes("foundation::secureWipe(value.data(), value.size())")
       || !parsedGuard.includes('"recovery_code"')
       || !parsedGuard.includes('"totp"')
       || !copyGuard.includes("foundation::secureWipe(value->data(), value->size())")
       || !localLogin.includes("foundation::SecretString bindingSecret{std::move(bindingToken).value()}")
       || !localLogin.includes("wipeRequestOnExit.wipe()")
       || !localVerify.includes("SensitiveAuthCopyGuard wipeKnowledgeOnExit")
       || !localVerify.includes("SensitiveAuthCopyGuard wipeRecoveryOnExit")
       || !localVerify.includes("SensitiveAuthCopyGuard wipePreviousOnExit")
       || !localVerify.includes("oldToken.emplace(std::move(*previous))")
       || !localVerify.includes("foundation::SecretString continuationSecret{std::move(*continuation)}")
       || awaited < 0
       || localVerify.indexOf("wipeParsedOnExit.wipe()") > awaited
       || localVerify.indexOf("wipeRequestOnExit.wipe()") > awaited
       || localVerify.indexOf("wipeBindingOnExit.wipe()") > awaited
       || !cookieParser.includes("std::optional<std::string_view> found")
       || cookieParser.includes("found = std::string{value}")
       || !source.includes("const auto& text = value->as_string();"))
      issues.push({line:0,
        kind:"native local password/TOTP proof retains plaintext or browser cookie copies across coroutine suspension",
        expression:"wipe parsed JSON, extracted copies and raw request before await, and move bearer/continuation into SecretString"});
  }
  if(relative==="src/account/http/coroutine_session_http.cpp"){
    const native = executable.slice(
      executable.indexOf("CoroutineAccountSessionAdapter::handleAsync("),
      executable.indexOf("CoroutineAccountSessionAdapter::sessionList("));
    if(!/if\s*\(\s*!nativeEnabledFor\s*\(\s*request\s*\)\s*\)/.test(native)
       || /m_legacyAccount->handle\s*\(/.test(native)
       || !/co_await\s+m_asyncFallback->handleAsync/.test(native))
      issues.push({line:0,kind:"native account session dispatch can bypass request capability or execute legacy service",
        expression:"nativeEnabledFor guard, no synchronous account fallback"});
    if(!/co_await\s+m_authenticate\s*\(\s*std::move\s*\(\s*credential->value\s*\(\s*\)\s*\)\s*\)/.test(executable)
       || !/co_await\s+m_list\s*\(/.test(executable)
       || !/co_await\s+m_revokeOwned\s*\(/.test(executable)
       || !/target\.value\s*\(\s*\)\s*==\s*authenticated->id\s*\(\s*\)/.test(executable))
      issues.push({line:0,kind:"native account session services missing authenticated or self-revoke-safe persistence",
        expression:"await authenticate, list, revokeOwned and deny self-revoke"});
    // A storage bug must not expose another identity's session metadata.
    // Validate every row before JSON serialization, never stream partial data.
    const listing = executable.slice(
      executable.indexOf("CoroutineAccountSessionAdapter::sessionList("),
      executable.indexOf("CoroutineAccountSessionAdapter::sessionRevoke("));
    if (!/kMaximumSessionResponseRows\s*=\s*256U/.test(executable)
        || !/values->size\s*\(\s*\)\s*>\s*kMaximumSessionResponseRows/.test(listing)
        || !/std::ranges::any_of\s*\(\s*values\.value\s*\(/.test(listing)
        || !/value\.identity\s*\(\s*\)\s*!=\s*current->identity\s*\(\s*\)/.test(listing)
        || listing.indexOf("value.identity()") > listing.indexOf("json::array sessions;"))
      issues.push({line:0,kind:"native account session list can disclose cross-identity rows",
        expression:"validate all session identities before serializing any row"});
    const header = fs.readFileSync(
      path.join(root,"src/account/http/coroutine_session_http.hpp"),"utf8");
    if(!/nativeEnabled\s*\(\s*\)\s*const\s*noexcept\s*override\s*\{\s*return\s+false\s*;/.test(header)
       || !/nativeEnabledFor\s*\(/.test(header))
      issues.push({line:0,kind:"partial account session migration enabled for all routes",
        expression:"nativeEnabled false; nativeEnabledFor per request"});
    // A refusal before credential extraction (including rate limiting) must
    // scrub both Authorization and Cookie, not just the accepted bearer.
    const guard=source.slice(source.indexOf("class SensitiveSessionHeadersGuard final"),
      source.indexOf("[[nodiscard]] bool sessionListRoute("));
    const list=source.slice(source.indexOf("CoroutineAccountSessionAdapter::sessionList("),
      source.indexOf("CoroutineAccountSessionAdapter::sessionRevoke("));
    const revoke=source.slice(source.indexOf("CoroutineAccountSessionAdapter::sessionRevoke("));
    const parsing=source.slice(source.indexOf("revokeTarget("),
      source.indexOf("CoroutineAccountSessionAdapter::CoroutineAccountSessionAdapter("));
    if(!guard.includes("m_request.wipeAuthorizationHeader()")
       || !guard.includes("m_request.wipeCookieHeader()")
       || !native.includes("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}")
       || !list.includes("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}")
       || !revoke.includes("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}")
       || !parsing.includes('*contentType != "application/json"')
       || !parsing.includes('contentType->starts_with("application/json;")'))
      issues.push({line:0,kind:"native account session rejection retains credentials or accepts ambiguous JSON media types",
        expression:"RAII wipe Authorization/Cookie and exact JSON MIME boundary"});
  }
  if(relative==="src/authentication/http/coroutine_recovery_code_http.cpp"){
    const header=fs.readFileSync(
      path.join(root,"src/authentication/http/coroutine_recovery_code_http.hpp"),"utf8");
    const handle=executable.slice(
      executable.indexOf("CoroutineRecoveryCodeHttpAdapter::handle("),
      executable.indexOf("CoroutineRecoveryCodeHttpAdapter::handleAsync("));
    const native=executable.slice(
      executable.indexOf("CoroutineRecoveryCodeHttpAdapter::handleAsync("),
      executable.indexOf("CoroutineRecoveryCodeHttpAdapter::issue("));
    const issue=executable.slice(
      executable.indexOf("CoroutineRecoveryCodeHttpAdapter::issue("));
    const issuance=issue.indexOf("co_await m_recoveryCodes->issueFenced(");
    const denied=issue.indexOf("if (!issued)");
    const domain=fs.readFileSync(path.join(root,"src/credentials/coroutine_recovery_codes.cpp"),"utf8");
    const fenced=domain.slice(domain.indexOf("CoroutineRecoveryCodeService::issueFenced("),
      domain.indexOf("CoroutineRecoveryCodeService::consume("));
    const response=issue.indexOf("co_return jsonResponse(201");
    if(!/CoroutineRecoveryCodeHttpAdapter final/.test(header)
       || !/nativeEnabled\(\) const noexcept override \{ return false; \}/.test(header)
       || !/boost::asio::awaitable</.test(header)
       || !/return fail\(foundation::Error\{foundation::ErrorCode::Unavailable\}, request\)/.test(handle)
       || /m_nativeFallback->handle\(/.test(native)
       || !/co_return co_await m_nativeFallback->handleAsync\(/.test(native)
       || !/if \(!nativeEnabledFor\(request\)\)/.test(native)
       || !/m_rateLimiter->allow\(limitKey\)/.test(issue)
       || !/gateway::takeSessionCredential\(request\)/.test(issue)
       || !/co_await m_authenticate\(/.test(issue)
       || !/idp::AssuranceLevel::Ial2/.test(issue)
       || issuance<0 || denied<issuance || response<denied
       || /m_recoveryCodes->revoke\(/.test(issue)
       || !/co_await m_repository->captureIssuanceAsync\(/.test(fenced)
       || !/co_await issue\(std::move\(identity\),count,std::move\(fence\).value\(\)\)/.test(fenced)
       || !/co_await m_repository->replaceFencedAsync\(/.test(domain)
       || !/co_return fail\(/.test(issue)
       || !/cache-control/.test(source)
       || !/no-store/.test(source))
      issues.push({line:0,kind:"native recovery HTTP permits synchronous fallback or unverified plaintext issuance",
        expression:"native bearer + IAL2 + generation-fenced atomic issue before JSON"});
    const guard=source.slice(source.indexOf("class SensitiveSessionHeadersGuard final"),
      source.indexOf("[[nodiscard]] bool isRecoveryRoute("));
    if(!guard.includes("m_request.wipeAuthorizationHeader()")
       || !guard.includes("m_request.wipeCookieHeader()")
       || !handle.includes("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}")
       || !native.includes("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}")
       || !issue.includes("SensitiveSessionHeadersGuard wipeHeadersOnExit{request}"))
      issues.push({line:0,kind:"native recovery route leaves a credential header on early denial",
        expression:"RAII wipe request-owned Authorization and Cookie before every return"});
  }
  if(relative==="src/credentials/coroutine_recovery_codes.cpp"){
    const issue = source.slice(
      source.indexOf("CoroutineRecoveryCodeService::issue("),
      source.indexOf("CoroutineRecoveryCodeService::consume("));
    const consume = source.slice(
      source.indexOf("CoroutineRecoveryCodeService::consume("),
      source.indexOf("CoroutineRecoveryCodeService::revoke("));
    const replaceAt = issue.indexOf("co_await m_repository->replaceAsync(");
    const returnCodesAt = issue.indexOf(
      "co_return foundation::Result<std::vector<foundation::SecretString>>");
    if(!/security::randomTokenBase64Url\(20U\)/.test(issue)
       || !/security::hmacSha256\(m_pepper, code\.expose\(\)\)/.test(issue)
       || !/count > 32U/.test(issue)
       || replaceAt < 0 || returnCodesAt < replaceAt
       || !/if \(!saved\) co_return foundation::fail\(saved\.error\(\)\)/.test(issue)
       || !/security::hmacSha256\(m_pepper, presented\.expose\(\)\)/.test(consume)
       || !/co_await m_repository->consumeAsync\(/.test(consume)
       || /m_repository->(?:replace|consume)\s*\(/.test(executable))
      issues.push({line:0,kind:"native recovery-code service exposes uncommitted plaintext or synchronous store",
        expression:"CSPRNG + keyed digest + await atomic persistence before returning secrets"});
  }
  if(relative==="src/storage/postgres/coroutine_recovery_code_repository.cpp"){
    const entryPoints=["replaceAsync","consumeAsync","remainingAsync","eligibleAsync","captureIssuanceAsync","replaceFencedAsync"];
    const bounded = entryPoints.every(name=>{
      const start = source.indexOf(
        "CoroutinePostgresRecoveryCodeRepository::"+name+"(");
      const end = source.indexOf("CoroutinePostgresRecoveryCodeRepository::",
        start+name.length+3);
      const part=source.slice(start,end < 0 ? undefined:end);
      return start>=0
        && /const Deadline deadline\s*=\s*Clock::now\(\)\s*\+\s*m_impl->queryTimeout/.test(part)
        && /co_await m_impl->pool\.acquire\(deadline\)/.test(part)
        && /remaining\(deadline\)/.test(part)
        && !/m_impl->pool\.acquire\(\)/.test(part);
    });
    if(!bounded || !/foundation::ErrorCode::AuthenticationFailed/.test(source)
        || !/m_impl->sql\.eligible\(/.test(source)
        || !/configuredLocalProvider\.value\(\)/.test(source)
        || /\bPQ(?:exec|execParams|connectdb|reset)\s*\(/.test(executable))
      issues.push({line:0,kind:"native recovery-code adapter bypasses the shared SQL deadline or owner-scoped one-time consumption",
        expression:"bounded async pool/SQL + generic failed/replayed redemption"});
  }
  if(relative==="src/storage/postgres/async_recovery_code.cpp"){
    const eligible=source.slice(source.indexOf("AsyncRecoveryCodeSql::eligible("));
    if(!/SELECT EXISTS/.test(eligible)
       || !/external_identities e/.test(eligible)
       || !/i.status=0/.test(eligible)
       || !/password_credentials p/.test(eligible)
       || !/totp_credentials t/.test(eligible)
       || !/e.identity_id=\$1 AND e.provider=\$2/.test(eligible)
       || !/co_await conn.query\(/.test(eligible)
       || !/result != "true" && result != "false"/.test(eligible))
      issues.push({line:0,kind:"native recovery eligibility bypasses active identity, local link or TOTP",
        expression:"one bounded parameterized SELECT EXISTS across active identity, link, password, TOTP"});
    // Recovery-code replay prevention is one identity-scoped DELETE, while
    // replacement must validate the entire batch before atomic BEGIN and
    // must never reintroduce a per-code SQL round trip.
    const header = fs.readFileSync(
      path.join(root,"src/storage/postgres/async_recovery_code.hpp"),"utf8");
    const replace = source.slice(
      source.indexOf("AsyncRecoveryCodeSql::replace("),
      source.indexOf("AsyncRecoveryCodeSql::consume("));
    const consume = source.slice(
      source.indexOf("AsyncRecoveryCodeSql::consume("),
      source.indexOf("AsyncRecoveryCodeSql::remaining("));
    if(!/kMaximumRecoveryCodes\s*=\s*64U/.test(header)
       || !/digestsHex\.size\(\) > kMaximumRecoveryCodes/.test(replace)
       || !/canonicalDigest\(std::move\(digest\)\)/.test(replace)
       || !/std::adjacent_find/.test(replace)
       || !/const Deadline deadline = Clock::now\(\) \+ timeout/.test(replace)
       || !/co_await conn\.query\(\s*"BEGIN ISOLATION LEVEL READ COMMITTED", \{\}, remainingBudget\(deadline\)\)/.test(replace)
       || !/pg_advisory_xact_lock\(hashtextextended\(\$1, 0\)\)/.test(replace)
       || replace.indexOf("pg_advisory_xact_lock") > replace.indexOf('"DELETE FROM "')
       || !/co_await conn\.query\(\s*"COMMIT", \{\}, remainingBudget\(deadline\)\)/.test(replace)
       || !/std::move\(sql\), std::move\(parameters\), remainingBudget\(deadline\)/.test(replace)
       || !/FOR UPDATE OF i FOR SHARE OF o/.test(replace)
       || !/p.changed_at_ms=\$4::bigint AND t.enrolled_at_ms=\$5::bigint/.test(replace)
       || !/FOR SHARE OF p,e,t/.test(replace)
       || replace.indexOf("FOR SHARE OF p,e,t") > replace.indexOf('"DELETE FROM "')
       || !/if \(!exact\(factor\)\)[\s\S]*?co_return false/.test(replace)
       || (replace.match(/\bco_await\b/g) || []).length !== 11
       || !/WHERE identity_id=\$1 AND code_digest=decode\(\$2,'hex'\)/.test(consume)
       || !/RETURNING identity_id/.test(consume)
       || !/co_return !rows\.rows\.empty\(\)/.test(consume))
      issues.push({line:0,kind:"native recovery-code SQL can disclose or replay credentials",
        expression:"identity-scoped single-use DELETE and atomic bounded replacement"});
  }
  if(relative==="src/storage/postgres/async_session.cpp"){
    // List cardinality is a security and latency bound: an authenticated
    // identity can accumulate historical sessions indefinitely.
    const sessionHeader = fs.readFileSync(
      path.join(root,"src/storage/postgres/async_session.hpp"),"utf8");
    const listMethod = source.slice(
      source.indexOf("AsyncSessionSql::list("),
      source.indexOf("AsyncSessionSql::listActive("));
    const activeListMethod = source.slice(
      source.indexOf("AsyncSessionSql::listActive("),
      source.indexOf("AsyncSessionSql::purgeExpired("));
    if (!/kMaximumListedSessions\s*=\s*256U/.test(sessionHeader)
        || !/LIMIT\s*"/.test(listMethod)
        || !/kMaximumListedSessions\s*\+\s*1U/.test(listMethod)
        || !/rows\.rows\.size\s*\(\s*\)\s*>\s*kMaximumListedSessions/.test(listMethod)
        || !/throw\s+std::length_error/.test(listMethod)
        || !/WHERE identity_id=\$1/.test(listMethod))
      issues.push({line:0,kind:"native session list lacks scoped SQL bound and overflow rejection",
        expression:"identity_id parameter + LIMIT max+1 + reject overflow"});
    const sessionService = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_session_service.cpp"),"utf8");
    const sessionRepository = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_session_repository.cpp"),"utf8");
    const nativeActive = sessionRepository.slice(
      sessionRepository.indexOf("CoroutinePostgresSessionRepository::listActive("),
      sessionRepository.indexOf("CoroutinePostgresSessionRepository::purgeExpired("));
    if (!/WHERE identity_id=\$1 AND state=0/.test(activeListMethod)
        || !/absolute_expires_at_ms>\$2::bigint/.test(activeListMethod)
        || !/last_seen_at_ms\+idle_timeout_ms>\$2::bigint/.test(activeListMethod)
        || !/ORDER BY last_seen_at_ms DESC, id ASC LIMIT/.test(activeListMethod)
        || !/kMaximumListedSessions \+ 1U/.test(activeListMethod)
        || !/rows\.rows\.size\(\) > kMaximumListedSessions/.test(activeListMethod)
        || !/throw std::length_error/.test(activeListMethod)
        || !/m_impl->sql\.listActive\(/.test(nativeActive)
        || !/restored->identity\(\) != identity/.test(nativeActive)
        || !/restored->isExpiredAt\(now\)/.test(nativeActive)
        || !/repo\.listActive\(std::move\(identity\), now\)/.test(sessionService))
      issues.push({line:0,kind:"native account session listing counts revoked/expired history or bypasses scoped active SQL",
        expression:"active+unexpired identity predicate before SQL LIMIT, repository check and service dispatch"});
    const activeSessionIndex = fs.readFileSync(
      path.join(root,"migrations/0020_active_session_recency.sql"),"utf8")
      .replace(/--[^\n]*\n/g,"\n").trim();
    if(!/CREATE INDEX IF NOT EXISTS sessions_active_identity_recency\s+ON openproof\.sessions\s*\(\s*identity_id,\s*last_seen_at_ms DESC,\s*id ASC\s*\)\s*WHERE state = 0;/.test(activeSessionIndex)
       || /\b(?:DROP|TRUNCATE|DELETE|UPDATE|INSERT|CONCURRENTLY)\b/i.test(activeSessionIndex))
      issues.push({line:0,kind:"active session pagination lacks a matching partial index",
        expression:"additive identity+recency index WHERE state=0, no table rewrites"});
    // Concurrency can reorder requests after they capture timestamps. Both
    // native and compatibility SQL must preserve a monotonic idle clock.
    const legacySessions = fs.readFileSync(
      path.join(root,"src/storage/postgres/postgres.cpp"),"utf8");
    for (const [implementationName,sql] of [
      ["native",source],["compatibility",legacySessions]
    ]) {
      const current = sql.slice(
        sql.indexOf(implementationName==="native"
          ? "AsyncSessionSql::useToken(" : "PostgresSessionRepository::use("),
        sql.indexOf(implementationName==="native"
          ? "AsyncSessionSql::rotateToken(" : "PostgresSessionRepository::rotate("));
      const rotation = sql.slice(
        sql.indexOf(implementationName==="native"
          ? "AsyncSessionSql::rotateToken(" : "PostgresSessionRepository::rotate("),
        sql.indexOf(implementationName==="native"
          ? "AsyncSessionSql::revoke(" : "PostgresSessionRepository::revoke("));
      if (!current.includes("GREATEST(last_seen_at_ms,$2::bigint)")
          || !rotation.includes("GREATEST(last_seen_at_ms,$4::bigint)")) {
        issues.push({line:0,kind:implementationName+" session idle clock can regress",
          expression:"GREATEST(last_seen_at_ms, request timestamp) on use and rotate"});
      }
    }
    // An owner check before an unrestricted UPDATE is a TOCTOU security
    // bug: require ownership in the SQL mutation itself, and in the
    // follow-up state inspection that preserves NotFound privacy.
    const start = source.indexOf("AsyncSessionSql::revokeOwned(");
    const end = source.indexOf("AsyncSessionSql::revokeAll(", start);
    const body = source.slice(start, end);
    const statements = body.match(/WHERE id=\$1 AND identity_id=\$2/g) || [];
    if(start<0 || end<=start || statements.length<2
       || !/WHERE id=\$1 AND identity_id=\$2 AND state=0 RETURNING id/.test(body)
       || !/co_await connection\.query\(update/.test(body)
       || !/co_await connection\.query\(\s*query/.test(body))
      issues.push({line:0,kind:"native owned session revocation lacks atomic owner-scoped SQL",
        expression:"UPDATE id+identity_id, SELECT id+identity_id"});
    const repository = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_session_repository.cpp"),"utf8");
    const owned = repository.slice(
      repository.indexOf("CoroutinePostgresSessionRepository::revokeOwned("),
      repository.indexOf("CoroutinePostgresSessionRepository::revokeAll("));
    const service = fs.readFileSync(
      path.join(root,"src/storage/postgres/coroutine_session_service.cpp"),"utf8");
    if(!/co_await m_impl->sql\.revokeOwned\s*\(/.test(owned)
       || !/return m_repository->revokeOwned\s*\(/.test(service)
       || /revokeOwnedSession\s*\(/.test(service))
      issues.push({line:0,kind:"native owned revocation still checks then revokes across await",
        expression:"service -> repository -> atomic AsyncSessionSql::revokeOwned"});
  }
  if(relative==="src/oauth/http/http.cpp"){
    // Compatibility code may remain for offline tests, but the running
    // server must not construct the synchronous OAuth handler at all.
    const app=fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
    const legacy=fs.readFileSync(path.join(root,relative),"utf8");
    const runtime=app.slice(app.indexOf("ExitCode runGatewayServer("));
    if (/\bOAuthHttpApi\s+[\w]+\s*\{|make_(?:unique|shared)<[^>]*OAuthHttpApi>/.test(runtime))
      issues.push({line:0,kind:"synchronous OAuth handler constructed by server",expression:"OAuthHttpApi"});
    if (!/co_await service->beginAsync\(/.test(runtime) ||
        !/co_await service->completeAsync\(/.test(runtime) ||
        !/co_await sessions->issueReplacingAsync\(/.test(runtime))
      issues.push({line:0,kind:"native OAuth login incomplete",expression:"native authentication and atomic session replacement"});
    for(const route of ["/oauth/userinfo","/oauth/introspect","/oauth/revoke","/oauth/device_authorization","/oauth/device","/oauth/par","/oauth/authorize","/oauth/consent","/login","/oauth/token"]){
      if(!app.includes('nativePaths.emplace_back("'+route+'")'))
        issues.push({line:0,kind:"native OAuth token operation missing strict dispatch",expression:route});
    }
    const native=fs.readFileSync(path.join(root,"src/oauth/http/coroutine_token_read_http.cpp"),"utf8");
    if(!/m_nativeTokenReadsRequired && path=="\/login"/.test(legacy)
       || !/co_await m_login\(/.test(native)
       || !/if \(tokenRoute\(r\)\) return true/.test(native)
       || !/unsupported_grant_type/.test(native)
       || !/co_await refresh\(std::move\(r\)\)/.test(native)
       || !/co_await exchangeCode\(std::move\(r\)\)/.test(native)
       || !/co_await issueMachine\(std::move\(r\)\)/.test(native)
       || !/co_await pollDevice\(std::move\(r\)\)/.test(native))
      issues.push({line:0,kind:"OAuth native login or complete token dispatch incomplete",expression:"all grants and invalid requests handled natively"});
    if(!/m_nativeTokenReadsRequired && \(path=="\/oauth\/authorize" \|\| path=="\/oauth\/consent"\)/.test(legacy)
       || !/co_await m_par->complete\(/.test(native)
       || !/reader->completeOAuthAuthorizationAsync/.test(app))
      issues.push({line:0,kind:"OAuth browser authorization incomplete",expression:"strict authorization and consent completion"});
    if(!/m_nativeTokenReadsRequired && path=="\/oauth\/par"/.test(legacy)
       || !/co_await m_par->push\(/.test(native)
       || !/reader->pushOAuthAuthorizationAsync/.test(app))
      issues.push({line:0,kind:"OAuth PAR initiation incomplete",expression:"strict native push and JAR replay"});
    if(!/m_nativeTokenReadsRequired && \(path=="\/oauth\/device_authorization" \|\| path=="\/oauth\/device"\)/.test(legacy)
       || !/co_await m_devicePoll->decide\(/.test(native)
       || !/co_await m_devicePoll->readApproval\(/.test(native)
       || !/reader->decideOAuthDeviceAsync/.test(app)
       || !/reader->readOAuthDeviceApprovalAsync/.test(app))
      issues.push({line:0,kind:"OAuth device browser approval incomplete",expression:"strict native browser approval and atomic consent"});
    if(!/m_nativeTokenReadsRequired && \(path=="\/oauth\/device_authorization"/.test(legacy)
       || !/co_await m_devicePoll->begin\(/.test(native)
       || !/reader->beginOAuthDeviceAsync/.test(app))
      issues.push({line:0,kind:"OAuth device initiation has incomplete native retirement",expression:"strict device initiation and runtime storage binding"});
    if(!/m_nativeTokenReadsRequired && \(path=="\/oauth\/userinfo"/.test(legacy)
       || !/co_await m_revoke\(/.test(native)
       || !/reader->revokeOAuthTokenAsync/.test(app))
      issues.push({line:0,kind:"OAuth token revocation has incomplete native retirement",expression:"strict revocation and runtime storage binding"});
  }
  if(relative==="src/account/http/http.cpp"){
    const legacy=fs.readFileSync(path.join(root,relative),"utf8");
    const http=fs.readFileSync(path.join(root,"src/account/http/coroutine_session_http.cpp"),"utf8");
    const pages=fs.readFileSync(path.join(root,"src/account/http/account_pages.cpp"),"utf8");
    const federation=fs.readFileSync(path.join(root,"src/authentication/http/coroutine_federated_start_http.cpp"),"utf8");
    const app=fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
    const paths=["/account/sessions","/account/sessions/revoke","/account/recover","/account/security",
      "/account/profile","/account/connections","/account/connections/disconnect","/account/totp",
      "/account/password/upgrade","/account/signup","/account/email/verify","/account/email/change",
      "/account/email/change/verify","/account/email/resend","/account/phone","/account/phone/verify",
      "/account/password/forgot","/account/password/reset","/account/totp/start","/account/totp/complete",
      "/account/totp/disable","/account/connections/start","/account/connections/complete",
      "/account/connections/handoff","/account/connections/web3/start","/account/connections/web3/handoff",
      "/account/connections/web3/complete"];
    const strict=app.slice(app.indexOf('nativePaths.emplace_back("/account/sessions")'),
      app.indexOf("if (nativeAdminReadEnabled) {",app.indexOf('nativePaths.emplace_back("/account/sessions")')));
    const boundary=http.slice(http.indexOf("CoroutineAccountSessionAdapter::handleAsync("),
      http.indexOf("CoroutineAccountSessionAdapter::sessionList("));
    const security=http.slice(http.indexOf("CoroutineAccountSessionAdapter::securityPage("),
      http.indexOf("CoroutineAccountSessionAdapter::sessionList("));
    const confirm=http.slice(http.indexOf("CoroutineAccountSessionAdapter::passwordUpgradeConfirm("),
      http.indexOf("CoroutineAccountSessionAdapter::profileUpdate("));
    if(!/E::Unavailable/.test(legacy) || /m_accounts->|m_sessions->|m_authentication->|m_delegated->/.test(legacy)
       || /account::AccountService accountService|PostgresAccountRepository accountRepository/.test(app)
       || !/AccountHttpApi accountApi\{limiter.value\(\),fallback\}/.test(app)
       || !paths.every(route=>strict.includes('"'+route+'"'))
       || /nativeMethods\.emplace_back\("\/account\/(?!passkeys",gateway::HttpMethod::Get\))/.test(app)
       || !/co_return renderRecoveryPage\(\)/.test(boundary)
       || !/co_await securityPage\(/.test(boundary)
       || !/co_await m_authenticate\(/.test(security)
       || !/co_await m_readTotpStatus\(actor->identity\(\)\)/.test(security)
       || !/status->first!=actor->identity\(\)/.test(security)
       || !/co_return renderSecurityPage\(/.test(security)
       || !/co_await m_authenticate\(/.test(confirm) || /m_authenticateReadBearer/.test(confirm)
       || !/trustedPasswordUpgradeOrigin/.test(confirm)
       || !/co_await m_disconnect\(/.test(http) || !/co_await m_updateProfile\(/.test(http)
       || !/co_await m_authentication->issueBrowserConnectionHandoffAsync\(/.test(federation)
       || !/co_await m_authentication->consumeBrowserConnectionHandoffAsync\(/.test(federation)
       || !/m_authenticateBearer/.test(federation)
       || /m_authentication->(?:issueBrowserConnectionHandoff|consumeBrowserConnectionHandoff|beginConnection)\(/.test(federation)
       || /m_sessions->|m_accounts->|m_authentication->|co_await/.test(pages))
      issues.push({line:0,kind:"account native lifecycle, strict dispatch or legacy retirement incomplete",
        expression:"strict account paths -> native auth/storage and pure page renderers; no synchronous account service"});
  }
  if(relative==="src/authentication/http/admin.cpp"){
    // Scan both the retired ABI and the real HTTP + SQL implementations.
    // Pure command validation in administration.cpp never counts as I/O.
    const legacy=fs.readFileSync(path.join(root,relative),"utf8");
    const http=fs.readFileSync(path.join(root,"src/authentication/http/coroutine_admin_read_http.cpp"),"utf8");
    const sql=fs.readFileSync(path.join(root,"src/storage/postgres/coroutine_admin_store.cpp"),"utf8");
    const app=fs.readFileSync(path.join(root,"apps/opp/main.cpp"),"utf8");
    const runtime=app.slice(app.indexOf("ExitCode runGatewayServer("));
    const routes=runtime.slice(runtime.indexOf('for (const auto* path : {"/admin/local-members"'),
      runtime.indexOf("nativePaths.emplace_back(path);",runtime.indexOf('for (const auto* path : {"/admin/local-members"')));
    const requiredRoutes=["/admin/local-members","/admin/local-members/roles","/admin/local-members/suspend",
      "/admin/local-members/reinstate","/admin/local-members/remove","/admin/local-members/credentials/reset"];
    const mutation=sql.slice(sql.indexOf("CoroutineAdminStore::mutateAsync("));
    const write=mutation.indexOf('execute("BEGIN ISOLATION LEVEL READ COMMITTED"');
    const authorize=mutation.indexOf('std::string{ownerSql}+" FOR UPDATE OF o,i,m,r"');
    const record=mutation.indexOf("co_await appendRecords(");
    const commit=mutation.indexOf('execute("COMMIT"');
    const auth= http.indexOf("co_await m_authenticate(");
    const assurance=http.indexOf("idp::AssuranceLevel::Ial2",auth);
    const read=http.indexOf("co_await m_read(actor)",assurance);
    const mutate=http.indexOf("co_await m_mutation->mutate(");
    if(!/ErrorCode::Unavailable/.test(legacy) || /m_sessions->|m_members->|m_memberships->|m_identities->/.test(legacy)
       || /AdministrationHttpApi administrationApi|PostgresAdministrationRepository::create\(/.test(runtime)
       || !/const bool nativeAdminReadEnabled = platform\.auth\(\)\.enabled\(\)\s*\|\|/.test(runtime)
       || !/nativeAdminReadFlag && \*nativeAdminReadFlag == "0"/.test(runtime)
       || !/store->mutateAsync\(std::move\(actor\),command\)/.test(runtime)
       || !requiredRoutes.every(route=>routes.includes('"'+route+'"'))
       || !(auth>=0 && assurance>auth && read>assurance && mutate>read)
       || !/listing->actor != actor/.test(http) || !/role\.value\(\) == "owner"/.test(http)
       || /m_fallback->handle\(/.test(http)
       || !(write>=0 && authorize>write && record>authorize && commit>record)
       || !/pg_advisory_xact_lock\(7299730475761673315\)/.test(mutation)
       || !/m\.identity_id<>\$2 AND m\.state=1 AND i\.status=0/.test(mutation)
       || !/FOR UPDATE OF m,i,r/.test(mutation)
       || !/UPDATE openproof\.sessions SET state=1/.test(mutation)
       || !/pg_advisory_xact_lock\(7299730475761673314\)/.test(sql)
       || !/audit::computeAuditRecordHash/.test(sql)
       || !/INSERT INTO openproof\.security_event_outbox/.test(sql)
       || !/co_await m_impl->passwords->hashAsync/.test(mutation))
      issues.push({line:0,kind:"admin HTTP lifecycle has incomplete native authorization, persistence or retirement",
        expression:"strict native HTTP -> IAL2/owner -> atomic async mutation, audit and outbox"});
  }
  if(relative==="src/authentication/http/web3.cpp"){
    // Native session grants expose a token field rather than token().
    const nativeComplete = source.slice(
      source.indexOf("Web3AuthenticationHttpApi::completeAsync("));
    if(!/sessionCookie\s*\(\s*issued->token\.expose\s*\(/.test(nativeComplete)
       || /issued->token\(\)/.test(nativeComplete))
      issues.push({line:0,kind:"invalid native session grant access",expression:"issued->token.expose()"});
    // Disabled downstream coroutine handlers must stay disabled.
    const nativeEntry = source.slice(
      source.indexOf("Web3AuthenticationHttpApi::handleAsync("),
      source.indexOf("Web3AuthenticationHttpApi::startAsync("));
    if(!/native\s*!=\s*nullptr\s*&&\s*native->nativeEnabledFor\s*\(request\)/.test(nativeEntry))
      issues.push({line:0,kind:"missing request-specific downstream native capability guard",
        expression:"native->nativeEnabledFor(request)"});

    // Web3 must leave the listener's compatibility dispatch enabled by
    // default when no native asynchronous session service is configured.
    const interfaceSource=fs.readFileSync(
      path.join(root,"src/authentication/http/web3.cppm"),"utf8");
    if(!/nativeEnabled\s*\(\)\s*const\s*noexcept\s*override\s*\{[\s\S]*?return\s+false\s*;/.test(interfaceSource)
       || !/nativeEnabledFor\s*\(/.test(interfaceSource)
       || !/Web3AuthenticationHttpApi::nativeEnabledFor\s*\(/.test(source)
       || !/m_asyncSessions\s*!=\s*nullptr\s*&&\s*m_authentication->nativeCanonicalCompletionEnabled\s*\(\)/.test(source))
      issues.push({line:0,kind:"missing Web3 request-scoped compatibility gate",
        expression:"nativeEnabled() false; nativeEnabledFor(request) checks sessions and canonical"});
    // Require the actual trusted coordinator awaits, not merely a synthetic
    // coroutine wrapper around the synchronous HTTP handler.
    // Connection/handoff paths are intentionally fail-closed until their
    // synchronous persistence dependencies have native coroutine ports.
    for(const method of ["beginAsync","completeAsync"]){
      const call=new RegExp("\\bco_await\\s+m_authentication->"+method+"\\s*\\(");
      if(!call.test(source))
        issues.push({line:0,kind:"missing trusted Web3 coroutine flow",expression:method+"("});
    }
    const nativeIndex=source.indexOf("Web3AuthenticationHttpApi::handleAsync(");
    if(nativeIndex<0){
      issues.push({line:0,kind:"missing native Web3 HTTP entry",expression:"handleAsync("});
    }else{
      // Only inspect native entry points: compatibility handlers above this
      // boundary may continue blocking until the complete migration passes.
      const nativeSection=source.slice(nativeIndex);
      if(/\bm_fallback->handle\s*\(/.test(nativeSection))
        issues.push({line:0,kind:"blocking native HTTP fallback",expression:"m_fallback->handle("});
      for(const expression of [
        /\bm_sessions->(?:issue|authenticate|issueReplacing)\s*\(/,
        /\bm_authentication->(?:issueBrowserAuthenticationHandoff|redeemBrowserAuthenticationHandoff|publishBrowserAuthenticationHandoff|issueBrowserConnectionHandoff|consumeBrowserConnectionHandoff|updateConnectionPresentation|beginConnection|completeConnection)\s*\(/
      ]){
        if(expression.test(nativeSection))
          issues.push({line:0,kind:"legacy blocking call in native Web3 handler",expression:expression.source});
      }
      if(!/\bco_await\s+m_asyncSessions->issueAsync\s*\(/.test(nativeSection))
        issues.push({line:0,kind:"missing native session persistence",expression:"m_asyncSessions->issueAsync("});
      const capability=source.slice(source.indexOf("Web3AuthenticationHttpApi::nativeEnabledFor("),nativeIndex);
      const start=nativeSection.slice(nativeSection.indexOf("Web3AuthenticationHttpApi::startAsync("),
        nativeSection.indexOf("Web3AuthenticationHttpApi::completeAsync("));
      const complete=nativeSection.slice(nativeSection.indexOf("Web3AuthenticationHttpApi::completeAsync("));
      const link=complete.slice(complete.indexOf("if (connection) {"),complete.indexOf("co_await m_authentication->completeAsync("));
      if(!/m_asyncSessions\s*!=\s*nullptr\s*&&\s*m_authentication->nativeCanonicalCompletionEnabled\(\)/.test(capability)
          || !/m_authentication->nativeConnectionCompletionEnabled\(\)\s*&&\s*static_cast<bool>\(m_authenticate\)/.test(capability)
          || !/if\s*\(!nativeEnabledFor\(request\)\)/.test(start)
          || !/if\s*\(!nativeEnabledFor\(request\)\)/.test(complete)
          || !/co_await m_authentication->beginConnectionAsync\(/.test(start)
          || !/co_await m_authentication->consumeBrowserConnectionHandoffAsync\(/.test(start)
          || !/co_await m_authentication->completeConnectionAsync\(/.test(link)
          || !/co_return response;/.test(link)
          || /m_asyncSessions->issueAsync\(/.test(link))
        issues.push({line:0,kind:"missing fail-closed native session/connection gate",expression:"request capability, native handoff and link completion without session issuance"});
    }
  }
  return {name,file:relative,coAwaitCount:awaitCount,issues};
});
// Do not silently overlook newly added storage/provider/transport files.
// The fixed boundary matrix above verifies coroutine presence; this additional
// inventory checks *every* implementation unit for concrete synchronous I/O
// primitives, even when it was not previously named in the release gate.
const namedPaths = new Set(segments.map(([, relative]) => relative));
const uncoveredBlockingSources = [];
const globalForbidden = [
  ...forbidden,
  ["blocking cURL", /\bcurl_easy_perform\s*\(/g],
  ["blocking OpenSSL transport", /\bSSL_(?:connect|accept|read|write)\s*\(/g]
];
function auditDirectory(directory) {
  for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      auditDirectory(absolute);
      continue;
    }
    if (!/\.(?:cpp|cppm|cc|cxx|h|hpp|hxx)$/.test(entry.name)) continue;
    const relative = path.relative(root, absolute).split(path.sep).join("/");
    if (namedPaths.has(relative)) continue;
    const source = fs.readFileSync(absolute,"utf8");
    const executable = cppExecutableText(source);
    const issues = [];
    for (const [kind, regex] of globalForbidden) {
      for (const match of executable.matchAll(regex)) {
        issues.push({
          line: executable.slice(0,match.index).split("\n").length,
          kind, expression: match[0],
        });
      }
    }
    if (issues.length) uncoveredBlockingSources.push({file:relative,issues});
  }
}
auditDirectory(path.join(root,"src"));
const failures=checked.reduce((count,area)=>count+area.issues.length,0)
  + uncoveredBlockingSources.reduce((count,source)=>count+source.issues.length,0);
const report={
  status:failures===0?"STATIC_GATE_PASSED_REQUIRES_DYNAMIC_VALIDATION":"NOT_APPROVED",
  reviewRequired:true,
  releaseApproved:false,
  blockingFindings:failures,
  areas:checked,
  uncoveredBlockingSources,
};
if(process.argv.includes("--json"))console.log(JSON.stringify(report,null,2));
else{
  console.log("OpenProof end-to-end coroutine migration gate: "+report.status);
  for(const area of checked){
    console.log((area.issues.length?"FAIL":"PASS")+" "+area.name+" ["+area.file+"] co_await="+area.coAwaitCount);
    for(const issue of area.issues)console.log("  "+issue.line+" "+issue.kind+": "+issue.expression);
  }
  for (const untracked of uncoveredBlockingSources) {
    console.log("FAIL untracked blocking I/O [" + untracked.file + "]");
    for (const issue of untracked.issues) {
      console.log("  " + issue.line + " " + issue.kind + ": " + issue.expression);
    }
  }
  console.log("Release always requires full build, security regression, E2E tests, comparative baseline and latency/error-budget measurements.");
}
if(failures>0)process.exitCode=1;
