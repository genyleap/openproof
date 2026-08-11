# OpenProof — Security Invariants

Required by brief §59. Every invariant states four things:

1. **What must always be true.**
2. **How the implementation enforces it** — the mechanism, not the intention.
3. **Which test proves it.**
4. **What happens on failure** — the observable behaviour when the invariant is
   violated, because "it must not happen" is not a design.

"Enforced by" is the load-bearing field. An invariant whose only enforcement is
a sentence in this document is **not enforced**, and is marked as such.

Verified against the tree at 225 passing tests.

---

## Status

| # | Invariant | Enforced by | Proven by | On failure |
|---|---|---|---|---|
| 1 | External identifiers never become canonical identity keys | Type system: `IdentityId` and `ExternalSubject` are distinct `StrongId` tags with no conversion | `static_assert` in `core_test.cpp` | Compile error |
| 2 | Authentication never implies authorization | Separate modules; `AuthorizationDecision` carries no identity | `AuthenticationAloneGrantsNothing` | Decision is `NotApplicable`, which is not a permission |
| 3 | Authorization never implies authentication | `AuthorizationDecision` has no subject or authentication field; trusted requests require broker-minted authentication | `RawProviderValuesCannotForgeAuthenticationContext` | No trusted request can be constructed from a decision or raw provider values |
| 4 | Identity linking never occurs implicitly | Link state machine; `Linked` reachable only from `Verified` | `CannotReachLinkedWithoutVerification`, `MatchingAttributesDoNotMergeIdentities` | `FailedPrecondition`; no association recorded |
| 5 | Provider protocol logic never enters the identity core | `ProviderId` is opaque; `InteractionModel` is protocol-neutral; no protocol names in SPI or core | Module graph + review | Not mechanically caught — see §Gaps |
| 6 | The gateway never owns canonical identity | Dependency direction: core links no gateway | Not yet testable — no gateway exists | — |
| 7 | Client input cannot inject an entitlement | `AuthorizationRequest` exposes no entitlement mutator; a trusted adapter type is required before entitlements can be populated | `UntrustedEntitlementsCannotBeInjected` | Entitlement is absent and grants nothing |
| 8 | Private keys are never accepted or stored | No API accepts key material | Review | Not mechanically caught — see §Gaps |
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

---

## Invariants that are true but not yet mechanically enforced

Listed so their weakness is visible rather than implied.

- **#5 — provider protocol logic out of the core.** Enforced today by the module
  graph and review. A CI check asserting that `openproof_identity_core` links no
  provider target would make it mechanical. Worth adding when the first concrete
  provider lands in Phase 3.
- **#6 — gateway never owns identity.** Vacuously true: there is no gateway.
  Becomes testable in Phase 7.
- **#8 — private keys never enter the system.** True by inspection: no API
  accepts key material. There is no type-level prohibition, so a future
  signature could violate it silently. A `PrivateKeyMaterial` type that nothing
  can construct would make this mechanical.
- **Contracts guard internals, `Result` guards the perimeter.** This is the rule
  that keeps a contract from becoming a remote shutdown under `enforce`. It is
  documented in `03-CXX26.md` and enforced in review only.

---

## Invariants owed by later phases

Named now so they are designed in rather than retrofitted. Each is required by
the brief but has no subsystem to attach to yet.

| Invariant | Brief | Phase |
|---|---|---|
| Client-supplied identity headers are never trusted | §54, §59 | 7 — gateway |
| The trusted context passed upstream is tamper-evident | §54 | 7 |
| Proof freshness is policy-controlled; stale evidence is never presented as current | §14, §59 | 4 |
| Evidence is untrusted until verified; inference is never presented as fact | §61 | 4 |
| Risk evaluation failure cannot silently become authorization success | §59 | 5 |
| A trust decision is explainable, not an opaque number | §16, §62 | 5 |
| Deployment operators own their data; the protocol phones no one home | §4, §63 | 8 |

---

## How to add an invariant

An entry belongs here when violating it would be a **security** failure rather
than a bug. Fill all four fields. If the "Proven by" field would say "review",
say so explicitly and add it to the gaps section above — do not leave the table
looking stronger than the code.
