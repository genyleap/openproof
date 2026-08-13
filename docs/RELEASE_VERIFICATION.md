# OpenProof 1.0.13 Release Verification

> **1.0.13 qualification note:** the previous build reached the final `opp`
> link/runtime qualification boundary. Homebrew GCC 16.1 on Darwin exposes
> `<text_encoding>` but the installed runtime cannot link
> `std::text_encoding::environment()` either natively or through the expected
> experimental archive. OpenProof 1.0.13 removes that non-essential runtime
> dependency entirely. Protocol/JSON/log text is UTF-8 by OpenProof policy; host
> locale variables are observability metadata only.

> **GCC 16.1 account-delivery module note:** the qualified Darwin build later
> reproduced GCC's `failed to read compiled module cluster ... Bad file data`
> while the `openproof.account.delivery` primary implementation unit reloaded its
> own freshly generated CMI. The adapter now exposes only a factory from the
> primary interface and keeps its concrete implementation in a non-exported
> `:implementation` partition that never imports the primary module. The private
> partition uses module-linkage `detail` types (not anonymous-namespace/internal-
> linkage types), and the release gate enforces both constraints.
## Baseline proven on target toolchain

The pre-1.0 baseline was built by the project owner on macOS with GCC 16.1.0,
CMake/Ninja and OpenSSL 3.6.3. CTest reported 317/317 discovered tests passing.
Ten PostgreSQL integration tests were skipped because a test database was not
enabled; they were not failures.

That baseline is the regression reference for this release.

> 1.0.1 hotfix note: the user's first GCC 16.1 build of 1.0.0 exposed missing implementation-unit `<mutex>` and `<chrono>` reachability. Those classes were corrected across the new modules. This document still does not certify the C++ release until the qualified-toolchain build and CTest gates complete.
> 1.0.2 hotfix note: the next qualified GCC 16.1 build exposed `-Werror=attributes` on non-defining `friend` declarations carrying `[[nodiscard]]`. The client and OAuth digest operators now keep unannotated friend declarations, while inline/defaulted friend definitions remain unchanged.


> 1.0.3 hotfix note: the qualified GCC 16.1 build exposed that `<ranges>` does not own the ranges algorithms. All new translation units using `std::ranges::*` algorithms now directly include `<algorithm>`, and the release gate enforces this rule.

> 1.0.4 hotfix note: GCC 16.1.0 on Apple M1 was observed to ICE while synthesizing the implicit constexpr copy-assignment operator for the exported `client::Client` type in `repository.cpp`. The release now defines Client's copy/move special members out-of-line and includes a cross-module regression test.

> 1.0.5 hotfix note: GCC 16.1 then exposed a broader module-boundary failure: imported OAuth/token record destructors became spuriously deleted when repository CMIs instantiated `std::map` with those exported types, while a stale/importer path could still ICE around `Client` assignment. Repository storage is now hidden behind PImpl and pointer-backed implementation storage; durable exported record special members are defined out-of-line. The regression suite includes a separate importer that instantiates the failing standard-container shapes.

> Historical GCC 16.1 note: out-of-line `= default` was insufficient for exported module value types, and the first member-wise workaround still ICEd for the digest wrapper itself. Larger non-trivial exported records retain explicit member-wise special members, while the three 32-byte digest wrappers now follow a separate rule: local `std::array<std::byte, 32>` storage, no `openproof.security` import in the model partition, and no user-declared copy/move/destructor at all.

> Release verification now removes its dedicated build directory before configuration. Reusing CMI/BMI artifacts across source revisions is not an accepted verification path.


> 1.0.7 hotfix note: GCC 16.1 still ICEd when an out-of-line manual copy constructor for `ClientSecretDigest` accessed its private `std::array` member from the module implementation unit. The digest wrappers are intentionally trivial and fully defined in their owning module interfaces; no digest special member or byte accessor is compiled out-of-line. This removes the failing implementation-unit access path entirely.

> 1.0.10 qualification note: the target build reached the final OIDC/PostgreSQL portion of the graph and exposed two ordinary `-Werror` defects: an implementation-only OIDC import that was not present in the consuming module mapper, plus PostgreSQL `-Wshadow`/`-Wmisleading-indentation` warnings. OIDC now consumes normalized assurance/factor data through `oauth::RedeemedAuthorization`, and the identity-platform PostgreSQL adapter is statement-separated and covered by release gates for these warning classes. The release gate also cross-checks implementation-unit module imports against CMake target dependencies.

## Verification performed on the 1.0.13 source tree

- No project `.h`, `.hpp`, `.hh` or `.hxx` files are present.
- Every project module interface contains a module declaration.
- The CMake target dependency order was audited so module consumers are defined
  only after their dependencies.
- Source scans found no new TODO/FIXME/unimplemented placeholders. The only
  occurrence of the word `stub` is an existing unit-test double in a comment.
- 326 GoogleTest `TEST`/`TEST_F` declarations are present after the module-boundary
  regression coverage (the pre-1.0 baseline discovered 317 tests on the owner machine).
- JavaScript SDK tests pass under Node.js 22.16.0.
- Kotlin SDK source compiles successfully with `kotlinc` in the verification
  container.
- Swift SDK is intentionally Apple-platform-only (`iOS 17+`, `macOS 14+`) and
  uses CryptoKit. The Linux verification host does not provide CryptoKit, so an
  Apple-target Swift build is not claimed here.
- A reduced GCC modules reproduction matching the `Sha256Digest`/`ClientSecretDigest`/`std::optional` boundary was compiled separately. Storing the imported `security::Sha256Digest` alias directly reproduced a compiler ICE; spelling `std::array<std::byte, 32>` in the owning module while retaining the `Sha256Digest` public API compiled and executed successfully, including nested `std::optional` copy/move through a containing Client-like value type. This reduced test is a diagnostic aid, not a substitute for the required GCC 16.1 project build.
- A disposable GCC 14/C++23 compatibility transformation was used only as a
  parser/module smoke check. It compiled new JOSE code and exposed real
  warnings in the C++ SDK that were corrected. GCC 14 then hit module compiler
  failures/ICEs on baseline patterns, which is why the production project
  continues to require the already-verified GCC 16.1 toolchain. The disposable
  transformation is not included in this release.

For source-only auditing on a machine without GCC 16.1, the non-compiling gates can be run with:

```bash
OPENPROOF_STATIC_ONLY=1 ./scripts/verify-release.sh
```

## Required final target-toolchain gate

The verification container does not contain GCC 16.1 and therefore this document
**does not claim** that the modified C++ 1.0.13 tree has already completed the
same target-toolchain build that the owner performed for the baseline.

Run the hermetic release gate on the verified macOS toolchain before deployment:

```bash
./scripts/verify-release.sh
```

The script deletes its dedicated build directory before configuration. For a manual
CLion-equivalent run, also remove the previous module cache/build tree first:

```bash
rm -rf cmake-build-debug
cmake -S . -B cmake-build-debug -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=/opt/homebrew/Cellar/gcc/16.1.0/bin/gcc-16 \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/Cellar/gcc/16.1.0/bin/c++-16
cmake --build cmake-build-debug -j"$(sysctl -n hw.ncpu)"
ctest --test-dir cmake-build-debug --output-on-failure
```

To execute PostgreSQL integration tests as part of the release gate, provide the
test database environment expected by `tests/storage/postgres_integration_test.cpp`.
A deployment must not treat skipped database tests as proof of database behavior.


## 1.0.11 qualification delta

OIDC no longer relies on accessors added in the immediately preceding OAuth CMI. `acr` and `amr` are derived from `assurance()` and `strength()`, and the implementation imports `openproof.identity.provider` with a matching CMake dependency. This specifically prevents an incremental GCC Modules build from compiling new OIDC source against an older OAuth CMI that lacks the transient convenience accessors.
