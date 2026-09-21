# OpenProof Security Invariants

Each invariant states four things:

1. **What must always be true.**
2. **How the implementation enforces it** — the mechanism, not the intention.
3. **Which test proves it.**
4. **What happens on failure** — the observable behaviour when the invariant is
   violated, because "it must not happen" is not a design.

"Enforced by" is the load-bearing field. An invariant whose only enforcement is
a sentence in this document is **not enforced**, and is marked as such.

Security invariants are enforced by implementation boundaries and regression
tests. Environment-dependent integration tests must be run with their required
dependencies enabled before a deployment is promoted.

---

## Status

| # | Invariant | Enforced by | Proven by | On failure |
|---|---|---|---|---|
| 1 | External identifiers never become canonical identity keys | Type system: `IdentityId` and `ExternalSubject` are distinct `StrongId` tags with no conversion | `static_assert` in `core_test.cpp` | Compile error |
| 2 | Authentication never implies authorization | Separate modules; `AuthorizationDecision` carries no identity | `AuthenticationAloneGrantsNothing` | Decision is `NotApplicable`, which is not a permission |
| 3 | Authorization never implies authentication | `AuthorizationDecision` has no subject or authentication field; trusted requests require broker-minted authentication | `RawProviderValuesCannotForgeAuthenticationContext` | No trusted request can be constructed from a decision or raw provider values |
| 4 | Identity linking never occurs implicitly | Link state machine; `Linked` reachable only from `Verified` | `CannotReachLinkedWithoutVerification`, `MatchingAttributesDoNotMergeIdentities` | `FailedPrecondition`; no association recorded |
| 5 | Provider protocol logic never enters the identity core | `ProviderId` is opaque; `InteractionModel` is protocol-neutral; no protocol names in SPI or core | Module graph + review | Not mechanically caught — see §Gaps |
| 6 | The gateway never owns canonical identity | Dependency direction: gateway consumes `AuthenticatedSession`; canonical records remain behind identity repositories | gateway protected-route tests and module graph | Authentication/authorization fails closed; no identity is created at the edge |
| 7 | Client input cannot inject an entitlement | `AuthorizationRequest` exposes no entitlement mutator; a trusted adapter type is required before entitlements can be populated | `UntrustedEntitlementsCannotBeInjected` | Entitlement is absent and grants nothing |
| 8 | **End-user/wallet private keys are never accepted or custodied** | No identity, proof, wallet or provider API accepts subject private-key material. The only private key accepted by the core process is the operator-controlled OIDC RS256 signing key loaded through the secret configuration boundary | Module/API review plus OIDC signer secret typing | Subject key material has no ingestion path; invalid OIDC signing material prevents startup |
| 9 | Protected operations default to deny | `evaluateProtected`, four-valued `DecisionKind` | 4 tests in `decision_test.cpp` | `Indeterminate`/`NotApplicable` deny |
| 10 | Secrets never appear in logs or errors | `Secret<T>` and provider `CredentialValue`: no formatter, stream insertion, conversion, comparison or copy | `static_assert` in `secret_test.cpp` and `provider_test.cpp`; `LoggableAsText` check in `log_test.cpp` | Compile error |
| 11 | An authentication transaction is redeemable exactly once and cannot bypass orchestration | Atomic compare-and-consume in the store; only the broker mints `VerifiedAuthentication` | `ConcurrentRedemptionYieldsExactlyOneWinner`, `CompletesOnlyThroughASingleUseBoundTransaction` | Replay is rejected before provider verification runs again |
| 12 | An external identity belongs to at most one canonical identity | `attach` refuses on conflict; never transfers | `RefusesToTransferAnAlreadyOwnedExternalIdentity` | `Conflict`; existing owner unchanged |
| 13 | **Tenant isolation cannot be bypassed** | Organization is a parameter of every `IdentityRepository` operation; cross-tenant access is inexpressible | `AnotherTenantCannotReadAnIdentity`, `CrossTenantReadIsIndistinguishableFromAbsence`, `AnotherTenantCannotChangeStatus` | Reported as absent / `NotFound` |
| 14 | **A deleted identity leaves a tombstone** | No `remove()` on the repository; retirement is a status change; `Deleted` is terminal | `DeletionIsATombstoneNotARemoval` | `FailedPrecondition` on resurrection |
| 15 | **Identity keys are globally unique** | `add` rejects a duplicate key in any organization | `DuplicateKeysAreRejectedAcrossOrganizations` | `AlreadyExists`; existing record untouched |
| 16 | **Authentication failure does not reveal which check failed** | `AUTHENTICATION_REQUIRED` and `AUTHENTICATION_FAILED` use generic messages; the broker normalizes provider errors and contains provider exceptions | `AuthenticationFailuresDoNotRevealWhichCheckFailed`, `NormalizesProviderErrorsAtBothBrokerBoundaries`, `ContainsProviderExceptionsAtBothBrokerBoundaries` | Uniform authentication failure; provider exceptions do not escape |
| 17 | **Operator-only detail never reaches a client** | `Error` has two channels; `toClientJson` serializes only the client-safe one | `ClientJsonNeverLeaksInternalDetail` | Detail omitted from envelope |
| 18 | **A nonce has exactly one textual spelling** | `fromBase64Url` rejects non-canonical trailing bits | `Base64UrlRejectsNonCanonicalTrailingBits` | `InvalidArgument` |
| 19 | **Randomness failure is never silently downgraded** | `randomBytes` returns an error; no fallback source exists | `RejectsAnImpossiblyLargeRequest` | `Internal` error; caller cannot proceed |
| 20 | **A broken internal invariant stops the process** | C++26 contracts under the `enforce` semantic | `SecureWipeContractTest` death tests | Standard contract diagnostic, then abort |
| 21 | **Identity merge is never implicit** | Merge state machine; `Applied` reachable only from `Verified` | `CannotApplyWithoutVerification`, `CannotMarkVerifiedWithoutRequiringVerificationFirst` | `FailedPrecondition`; source untouched |
| 22 | **A merge never crosses tenants** | Both identities resolved through the organization-scoped repository | `CannotMergeAcrossOrganizations` | `NotFound`; neither identity changes |
| 23 | **A merge transfers no authority** | `applyMerge` touches associations only; memberships and roles are a separate aggregate it never opens | `MovesExternalAssociationsToTheTarget` plus the absence of any membership call | Authority must be re-granted deliberately |
| 24 | **A merged identity survives as a tombstone and cannot authenticate** | `IdentityStatus::Merged` is terminal; `permitsAuthentication` denies it | `AppliesAVerifiedMergeAndRetiresTheSource`, `CannotMergeIntoAnAlreadyMergedIdentity` | `FailedPrecondition` on any further change |
| 25 | **An association cannot be taken by naming it** | `reassign` requires and checks the expected current owner | `ReassignRefusesWhenTheExpectedOwnerIsWrong` | `PermissionDenied`; ownership unchanged |
| 26 | **A removed member does not regain authority** | `remove()` drops roles; granting to a removed membership is refused | `RemovalDropsRoles` | Roles cleared; `FailedPrecondition` on re-grant |
| 27 | **A role held in one tenant does not leak into another** | Roles live on the membership, keyed by (organization, identity) | `RolesAreScopedPerOrganization` | Role simply absent in the other tenant |
| 28 | **A suspended member holds no effective role** | `hasRole` checks membership state before the role set | `SuspensionMakesRolesInertWithoutDiscardingThem` | `hasRole` returns false while retaining the grant |
| 29 | **A raw provider outcome is not trusted authentication** | `VerifiedAuthentication` has a private constructor owned by `AuthenticationService`; policy accepts only that wrapper | `RawProviderValuesCannotForgeAuthenticationContext` | Compile error / trusted request cannot be constructed |
| 30 | **A provider cannot exceed its trusted assurance cap** | Broker uses the lower of provider-declared and independent operator-configured caps, at start and completion | `RefusesRequestedAssuranceAboveTheEffectiveCap`, `RefusesAnOutcomeAboveEitherAssuranceCap` | Authentication fails |
| 31 | **A provider cannot return an outcome under another provider identity** | Broker compares outcome provider with the provider recorded in the consumed transaction | `RefusesAnOutcomeUnderAnotherProviderIdentifier` | Authentication fails |
| 32 | **Client-supplied roles and authentication state cannot enter policy input** | `AuthorizationRequest` has no public constructor, aggregate overload or mutators; its factory resolves the broker identity, tenant and membership from authoritative repositories | `RefusesAMembershipBelongingToAnotherIdentity`, `RefusesAnInactiveMembership`, `RefusesAnInactiveCanonicalIdentityFromTheRepository`, `RefusesAnInactiveOrganizationFromTheRepository` plus compile-time constructibility checks | Request construction fails |
| 33 | **Malformed security configuration never falls back to defaults** | Closed TOML schema validates section, key and exact type before extraction | `RejectsWrongTomlTypesInsteadOfSilentlyUsingDefaults`, `RejectsUnknownSectionsAndSettings` | Startup returns `InvalidArgument` |
| 34 | **A verified external subject cannot be attached to an arbitrary canonical identity at authorization time** | The broker resolves `(provider, external subject)` only through `ExternalIdentityDirectory`, embeds that canonical key in `VerifiedAuthentication`, and policy queries repositories only under that key | `RefusesAnExternalSubjectWithoutAnExplicitIdentityLink`, `RefusesToCombineAuthenticationWithAnotherIdentity` | Authentication or request construction fails closed |
| 35 | **A session bearer is never stored in plaintext** | 256-bit opaque token is returned once; repositories receive only HMAC-SHA256 digest | `IssuesAndAuthenticatesAnOpaqueSession` | Database disclosure does not reveal live bearer values |
| 36 | **Session expiry and revocation are immediate** | Repository use/rotate/revoke operations atomically check state, absolute expiry and idle expiry | session service tests and `SessionUseRotationAndRevocationAreImmediate` | Generic authentication failure |
| 37 | **Recovery codes are exactly once across nodes** | Only peppered HMAC digests persist; PostgreSQL consumes with `DELETE ... RETURNING` | `RecoveryCodeIsConsumedExactlyOnceAcrossNodes` | One winner; all replays fail uniformly |
| 38 | **Client identity headers are never trusted** | Gateway strips every incoming `x-openproof-*` header before creating context | `ReplacesClientIdentityAndRemovesCredentialsAndHopByHopHeaders` | Forged value is absent or replaced from the trusted session |
| 39 | **Trusted upstream context is tamper-evident and fresh** | HMAC binds request and identity fields plus issued-at; verifier uses constant-time compare and a bounded window | `DetectsTamperingAndExpiredContexts` | Authentication failure |
| 40 | **Ambiguous HTTP framing does not cross the edge** | Duplicate security singletons, CL+TE, controls and non-origin targets are rejected; Beast parser has hard size limits | `RejectsAbsoluteFormControlCharactersAndAmbiguousFraming`, `ParserEnforcesBodyAndHeaderLimits` | HTTP 400/413/431 |
| 41 | **Non-idempotent requests are never automatically retried** | Retry classifier admits only GET, HEAD and OPTIONS; endpoints are distinct and attempts capped at two | `RetriesOnlyIdempotentRequestsAcrossDistinctEndpoints` | Original upstream failure becomes 503 |
| 42 | **Audit history is tamper-evident and linearly ordered** | Append, sequence allocation and previous-hash HMAC occur under one atomic repository operation | audit repository tests | Chain verification fails closed |
| 43 | **Untrusted metric labels cannot cause unbounded memory growth** | Label syntax/size/count validation and a hard series-cardinality ceiling | metric registry and hardening tests | New series is rejected |
| 44 | **The plaintext listener is never exposed on a network interface by the runnable process** | `validateServerDeployment` accepts only `127.0.0.1` or `::1`; deployment must terminate TLS locally | `ServerDeploymentRequiresGatewayKeyAndLoopbackListener` | Startup fails before bind |
| 45 | **A browser session credential has one unambiguous source and never reaches an upstream** | Credential extraction accepts exactly one Bearer or `__Host-openproof-session` cookie, removes it, and rejects conflicts or duplicates | `SessionCookieIsAcceptedStrippedAndCannotConflictWithBearer`, `LogoutRejectsAmbiguousCredentials` | Generic authentication failure; no proxy call |
| 46 | **A pre-authentication exchange is short-lived, client-bound and single-use** | Separate `Secure`/`HttpOnly`/`SameSite=Strict` continuation and binding cookies feed the broker's atomic transaction consume | `LoginMfaRecoveryRotationAndLogoutAreEndToEnd`, `WrongPasswordBurnsExchangeAndClearsPreauthCookies` | Failure burns the exchange and clears both cookies |
| 47 | **A persisted TOTP seed is confidential and a time step succeeds at most once** | AES-256-GCM with identity-bound AAD protects the seed; a conditional PostgreSQL update advances the last accepted step | `PersistentLocalTotpIsEncryptedAndConsumedOnce`, `RoundTripsWithAssociatedDataAndRejectsTampering` | Tampering fails decryption; concurrent replay has one winner |
| 48 | **The public auth plane is bounded and does not reveal account/check existence** | 16 KiB strict JSON boundary, closed fields, normalized auth errors, dummy password verification and dual IP/subject throttles | auth HTTP tests and local-provider unknown-account tests | Generic 4xx/429 with no operator detail |
| 49 | **Protected runnable routes authorize from durable canonical state** | Startup requires PostgreSQL, an active configured organization and explicit route policies; policy rebuilds tenant, identity, membership and roles from repositories for every request | `AuthDeploymentRequiresDatabaseAndResolvesItsSecretReference`, `ProtectedAuthenticationRequiresExplicitClosedRoutePolicies`, PostgreSQL aggregate round-trip and gateway protected-route tests | Startup or request fails closed |
| 50 | **Initial owner authority is created once, atomically and outside the public edge** | `bootstrap-admin` has no HTTP route or secret CLI flag; a serializable PostgreSQL transaction and deployment advisory lock create every aggregate, encrypted credential, audit record and outbox event, and require zero existing organizations | `InitialAdministratorTest.*`, `InitialAdministratorBootstrapIsAtomicAuditedAndOneTime`, executable bootstrap-to-protected-route smoke test | Entire transaction rolls back; repeat returns `AlreadyExists` without revealing a TOTP seed |
| 51 | **Provider verification time is bounded by actual completion, not by a stale pre-call clock reading** | Broker consumes expiry at call start and takes a fresh upper-bound timestamp immediately after provider completion | `AllowsProviderToFinishAfterCompletionBegins`, `StillRefusesAProviderTimestampAfterCompletion` | Real providers may cross clock ticks; genuinely future timestamps still fail authentication |
| 52 | **Local-member authority and credentials are created only by an active IAL2 owner and never partially** | HTTP requires IAL2; PostgreSQL re-authorizes the actor's active `owner` role and locks authoritative tenant/identity/membership rows inside the same serializable transaction that creates the identity, explicit link, membership/roles, server-generated password, encrypted TOTP, chained audit record and outbox event; secrets are returned only after commit | `LocalMemberEnrollmentTest.*`, `AdministrationHttpApiTest.*`, `OwnerProvisioningIsAtomicAuditedAndDeniedToMembers`, executable owner-to-new-member login smoke test | Non-owner/invalid/conflicting requests roll back completely and receive no generated secret |
| 53 | **Administrative member changes cannot orphan the tenant or leave stale authority live** | PostgreSQL serializes all owner mutations, re-authorizes the actor, prevents the final active owner from losing `owner`/being suspended/being removed, and atomically revokes target sessions; removal clears roles, while credential reset rotates password/TOTP replay state and deletes recovery codes | `MemberRoleReplacementTest.*`, `MemberLifecycleChangeTest.*`, `LocalCredentialResetTest.*`, `AdministrationHttpApiTest.*`, `OwnerProvisioningIsAtomicAuditedAndDeniedToMembers`, executable full-lifecycle smoke test | The complete transaction, audit record and outbox event roll back; old sessions or credentials are invalid after a successful commit |
| 54 | **No route, role or assurance requirement is implicit or client-injectable** | Closed TOML requires at least one explicit method/path rule when auth is enabled; immutable exact-match rules require a bounded role set and IAL; policy inputs contain only broker/session authentication and PostgreSQL roles; every non-Allow denies, and rejected authenticated decisions enter the HMAC chain and outbox | `RolePolicyRuleTest.*`, `RolePolicyEngineTest.*`, `PolicyAccessControllerTest.UsesDurableRolesAssuranceAndAuditsDenials`, `ProtectedAuthenticationRequiresExplicitClosedRoutePolicies`, `RejectedAuthorizationIsChainedAndPublished`, executable policy/RBAC E2E | Invalid policy prevents startup; missing route returns 404, missing authentication 401, and membership/role/assurance failure 403 with no upstream call |
| 55 | **A product registration is not an OAuth client credential** | `Application` and `Client` are separate aggregates; clients reference applications and have independent lifecycle, scopes and redirect policy | `ApplicationRegistryTest.*`, `ClientManagementTest.*` | A client can be suspended/revoked/rotated without changing the application identity |
| 56 | **Authorization codes are bound, short-lived and single-use** | Codes persist only as keyed digests and bind client, exact redirect, PKCE challenge, identity, scopes and authentication context; repositories atomically consume before validation completes | `OAuthTokenTest.AuthorizationCodePkceAndRefreshReplayAreFailClosed` plus PostgreSQL transaction/row-lock implementation | Replay or binding mismatch fails closed and the code is not reusable |
| 57 | **All interactive OAuth clients use PKCE S256 and exact registered redirects** | Authorization requests require `code_challenge_method=S256`; client registration validates redirect authority and runtime comparison is exact | `OAuthTokenTest.*`, `ClientManagementTest.*` including hostile-authority cases | Invalid registration/request is rejected before a code is issued |
| 58 | **OAuth bearer plaintext is never durable state** | Access/refresh tokens are generated from CSPRNG material and repositories receive only HMAC digests; refresh tokens are grouped in a revocable family | `OAuthTokenTest.*` plus repository schema/review | Database disclosure does not reveal usable bearer strings |
| 59 | **Refresh-token replay revokes the token family** | Rotation consumes the current refresh token atomically; reuse is treated as replay and repository family revocation invalidates derived access/refresh state | `OAuthTokenTest.AuthorizationCodePkceAndRefreshReplayAreFailClosed` | Replay fails and tokens from the affected family become inactive |
| 60 | **OIDC subject is always the canonical OpenProof identity** | ID Token/UserInfo take `sub` only from `IdentityId` carried in redeemed/token context; provider external subjects are different strong types | OIDC module type graph and identity-platform flow tests | External provider identifiers cannot replace canonical `sub` |
| 61 | **OIDC signing keys never cross the public protocol edge** | RSA private PEM is loaded as `SecretString`; JWKS derives and emits only public modulus/exponent; ID Tokens are signed RS256 | JOSE implementation and discovery/JWKS boundary review | Invalid/weak signing key prevents OIDC startup; public endpoints expose only public JWK |
| 62 | **Trust is derived from current verified evidence, not persisted as permanent truth** | Evidence has verification/revocation/expiry state; `TrustEngine` takes one clock snapshot and computes from active weighted evidence plus validated risk signals | `TrustEvidenceTest.*` | Revoked/expired evidence is excluded on the next assessment; malformed risk input is rejected |
| 63 | **A TOTP envelope-key rotation is complete or has no durable effect** | Offline serializable transaction, deployment advisory and exclusive table locks inventory/decrypt/re-encrypt every identity-bound envelope; data and versioned journal commit together; dry runs always roll back | `PostgresIntegrationTest.TotpCredentialRekeyIsAtomicVersionedAndDryRunnable`, `AeadTest.ComparesKeyMaterialWithoutExposingIt`, real-process identity E2E | Wrong/identical/unknown keys, row conflicts and duplicate target versions roll back every row and journal entry |
| 64 | **A retired master cannot preserve live transient authority or return through stale configuration** | Password, recovery, TOTP, audit, OAuth-client and registered-passkey material is independent before rotation; an offline serializable transaction exclusively invalidates every master-derived transient row—including incomplete passkey registration—and commits exact counts, the new version and a non-secret fingerprint; startup verifies the exact journal head | `ConfigTest.LoadsAllDedicatedPersistentKeysRequiredForMasterRotation`, `ConfigTest.RejectsRotatedMasterWithoutEveryDedicatedPersistentKey`, `SecretReferenceTest.DecodesAHexadecimalFileWithoutLosingBinaryBytes`, `PostgresIntegrationTest.MasterKeyRotationAtomicallyInvalidatesOnlyDerivedState`, real-process identity E2E | Missing separation, wrong/identical/stale keys, version discontinuity and duplicate targets fail closed; dry run rolls back; committed cutover logs out all users, forces in-flight passkey registration to restart and rejects old-key startup |
| 65 | **Operational metrics are bounded, private and non-identifying** | Metrics are off by default; enabling requires a 32-byte dedicated bearer; comparison is constant-time; the public edge blocks `/metrics`; built-in HTTP metrics use a fixed method/status-class matrix and extension series have a hard ceiling | `ConfigTest.ReadsAuthenticatedMetricsConfigurationFromASecretReference`, `ConfigTest.MetricsConfigurationFailsClosed`, `MetricsHttpApiTest.*`, real-process TLS identity E2E | Missing/wrong credentials return `401`; mutation methods return `405`; malformed configuration prevents startup; raw path/identity/token values never enter exposition |
| 66 | **A login ceremony cannot be repurposed to connect an account, and a connection ceremony cannot mint a session** | The broker records the ceremony purpose and target canonical identity only in its single-use server transaction and checks the expected purpose before resolving or attaching the provider subject | `LoginAndConnectionCeremoniesCannotBeSwapped`, `ConnectionCeremonyAttachesToItsServerBoundIdentity` | Generic authentication failure; the consumed ceremony produces neither a session nor a link |
| 67 | **Self-service connection cannot transfer an external account or remove the final sign-in method** | Completion checks authoritative external-subject ownership; the directory atomically serializes ownership check, provider-filtered count and detach (PostgreSQL uses a per-identity transaction advisory lock) | `ConnectionRefusesAnAccountOwnedByAnotherIdentity`, `DisconnectRefusesTheLastSignInMethod`, `ConcurrentProtectedDetachAlwaysLeavesOneSignInMethod` | Cross-owner attach returns `Conflict`; final-method removal returns `FailedPrecondition`; existing ownership remains unchanged |
| 68 | **Native browser handoff carries no reusable session credential** | An authenticated native client receives a two-minute one-time ticket; canonical identity, provider and local return path stay in the shared authentication transaction store and are recovered only by atomic consumption | `BrowserConnectionHandoffIsBoundAndSingleUse`, `BrowserConnectionHandoffExpiresClosed` | Unknown, expired, invalid and replayed tickets fail indistinguishably; no session or bearer is placed in the browser URL |

---

## Invariants that are true but not yet mechanically enforced

Listed so their weakness is visible rather than implied.

- **#5 — provider protocol logic out of the core.** Enforced today by the module
  graph and review. A CI check asserting that `openproof_identity_core` links no
  provider target would make this rule mechanically visible in CI.
- **#6 — gateway never owns identity.** Enforced by dependency direction and the
  fact that it consumes broker-issued `AuthenticatedSession`; a CI link-graph
  assertion would make this structural rule mechanically visible.
- **#8 — subject private keys never enter the system.** The OIDC provider now
  intentionally accepts an operator-owned RS256 signing private key through the
  secret configuration boundary. The remaining invariant is specifically that
  user, wallet and external-provider private keys have no ingestion/custody API.
  A future provider must preserve that boundary.
- **Contracts guard internals, `Result` guards the perimeter.** This is the rule
  that keeps a contract from becoming a remote shutdown under `enforce`. It is
  documented in `CXX26.md` and enforced in review only.

---

## Provider-specific proof invariants

Bundled provider adapters now enforce their protocol-specific trust boundaries:
OIDC uses issuer/audience/nonce/signature checks; GitHub revalidates the immutable
account subject; WebAuthn binds RP/origin/challenge and authenticator signatures;
SIWE wallet/Farcaster proofs bind nonce/domain/chain and verify the signing wallet;
Farcaster enforces FIP-11 statement/resource syntax and rechecks current FID
custody or an active KeyRegistry type-2 auth address; LDAPS authenticates with a
search-then-bind flow; SAML pins the IdP certificate and constrains XMLDSIG; SCIM
provisioning is bearer-protected; and evidence JWT/X.509 verification consumes
durable one-time challenges. New adapters must preserve proof freshness,
provenance, replay resistance, rate limits and provider-specific revocation or
current-state checks before production enablement.

## How to add an invariant

An entry belongs here when violating it would be a **security** failure rather
than a bug. Fill all four fields. If the "Proven by" field would say "review",
say so explicitly and add it to the gaps section above — do not leave the table
looking stronger than the code.
