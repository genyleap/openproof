#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    printf 'release gate: %s\n' "$1" >&2
    exit 1
}

command -v node >/dev/null 2>&1 || fail "Node.js is required for SDK and E2E release gates"
node --check "${ROOT_DIR}/scripts/load-smoke.mjs"
node --check "${ROOT_DIR}/scripts/e2e-identity-platform.mjs"
python3 "${ROOT_DIR}/scripts/verify-openapi.py"

# Credential key rotation must stay wired end to end: closed configuration,
# deployment secret mount, atomic schema journal, operator CLI and real-process E2E.
grep -q 'credential_encryption_key = "file:/run/openproof/secrets/credential-encryption.key"' \
    "${ROOT_DIR}/deploy/openproof.toml.example" \
    || fail "deployment template omits the dedicated credential-encryption key"
grep -q 'CREATE TABLE openproof.credential_key_rotations' \
    "${ROOT_DIR}/migrations/0014_credential_key_rotation.sql" \
    || fail "credential key rotation journal migration is missing"
grep -q 'rekey-totp' "${ROOT_DIR}/apps/opp/main.cpp" \
    || fail "offline TOTP rekey command is missing"
grep -q '"rekey-totp", "--config"' \
    "${ROOT_DIR}/scripts/e2e-identity-platform.mjs" \
    || fail "identity E2E does not exercise TOTP credential rekey"
grep -q 'TotpCredentialRekeyIsAtomicVersionedAndDryRunnable' \
    "${ROOT_DIR}/tests/storage/postgres_integration_test.cpp" \
    || fail "atomic PostgreSQL credential rekey regression is missing"

# Full master retirement is safe only when long-lived one-way credentials are
# independently keyed and all master-derived transient state is atomically retired.
for key in password_pepper recovery_code_pepper audit_chain_key oauth_client_secret_key; do
    grep -q "${key} = \"file:/run/openproof/secrets/" \
        "${ROOT_DIR}/deploy/openproof.toml.example" \
        || fail "deployment template omits dedicated ${key}"
done
grep -q 'CREATE TABLE openproof.master_key_rotations' \
    "${ROOT_DIR}/migrations/0015_master_key_rotation.sql" \
    || fail "master key rotation journal migration is missing"
grep -q 'ADD COLUMN passkey_registrations' \
    "${ROOT_DIR}/migrations/0016_master_rotation_passkey_ceremonies.sql" \
    || fail "master rotation does not journal passkey registration invalidation"
grep -q 'DELETE FROM openproof.passkey_registration_ceremonies' \
    "${ROOT_DIR}/src/storage/postgres/postgres.cpp" \
    || fail "master rotation leaves durable passkey ceremonies live"
grep -q 'rotate-master-key' "${ROOT_DIR}/apps/opp/main.cpp" \
    || fail "offline master key rotation command is missing"
grep -q 'materialize-persistent-keys' "${ROOT_DIR}/apps/opp/main.cpp" \
    || fail "legacy persistent-key materialization command is missing"
grep -q 'hexfile:' "${ROOT_DIR}/src/config/config.cpp" \
    || fail "binary-safe derived-key secret references are missing"
grep -q '"rotate-master-key", "--config"' \
    "${ROOT_DIR}/scripts/e2e-identity-platform.mjs" \
    || fail "identity E2E does not exercise master key retirement"
grep -q 'MasterKeyRotationAtomicallyInvalidatesOnlyDerivedState' \
    "${ROOT_DIR}/tests/storage/postgres_integration_test.cpp" \
    || fail "atomic PostgreSQL master key rotation regression is missing"
grep -q 'OPENPROOF_BUILD_COVERAGE_FUZZER' "${ROOT_DIR}/CMakeLists.txt" \
    || fail "coverage-guided fuzzer build option is missing"
grep -q 'fsanitize-coverage=trace-pc' "${ROOT_DIR}/fuzz/CMakeLists.txt" \
    || fail "boundary fuzzer lacks execution-coverage feedback"
grep -q 'currentCoverage' "${ROOT_DIR}/fuzz/boundary_fuzzer.cpp" \
    || fail "boundary fuzzer does not retain coverage-increasing inputs"
test -x "${ROOT_DIR}/scripts/qualify-fuzzing.sh" \
    || fail "fuzz qualification entrypoint is not executable"
grep -q 'rate_limit_refill_per_second' "${ROOT_DIR}/deploy/openproof.toml.example" \
    || fail "deployment template omits the tunable gateway rate-limit policy"
grep -q 'platform.gateway().rateLimitCapacity()' "${ROOT_DIR}/apps/opp/main.cpp" \
    || fail "server composition does not consume the configured rate-limit policy"

# Operational metrics must remain a private, authenticated runtime capability,
# not merely an unused registry or a publicly proxied endpoint.
grep -q 'metrics_bearer_token = "file:/run/openproof/secrets/metrics-bearer.token"' \
    "${ROOT_DIR}/deploy/openproof.toml.example" \
    || fail "deployment template omits the dedicated metrics bearer"
grep -q 'platform.operations().metricsEnabled()' "${ROOT_DIR}/apps/opp/main.cpp" \
    || fail "server composition does not wire configured runtime metrics"
grep -q 'security::constantTimeEquals' \
    "${ROOT_DIR}/src/operations/http/http.cpp" \
    || fail "metrics bearer is not compared in constant time"
grep -q 'location = /metrics' "${ROOT_DIR}/deploy/nginx-openproof.conf" \
    || fail "public Nginx template does not block the private metrics endpoint"
grep -q 'deniedMetrics.*edgeRequest("/metrics")' \
    "${ROOT_DIR}/scripts/e2e-identity-platform.mjs" \
    || fail "identity E2E does not prove unauthenticated metrics are denied"
grep -q 'openproof_http_requests_total' \
    "${ROOT_DIR}/scripts/e2e-identity-platform.mjs" \
    || fail "identity E2E does not prove runtime HTTP metrics are emitted"

# Keep the built-in operator console aligned with the administration API's
# mandatory local-member identity identifier.
grep -q "identity_id:v.identity_id,subject:v.subject" \
    "${ROOT_DIR}/src/application/http/http.cpp" \
    || fail "admin console local-member form omits identity_id"

# Production source remains modules-only.
if find "${ROOT_DIR}/src" "${ROOT_DIR}/sdk/cpp" -type f \( -name '*.h' -o -name '*.hpp' \) -print -quit | grep -q .; then
    fail "classic C/C++ header found in project-owned source"
fi

# GCC 16.1 production qualification deliberately avoids the experimental
# Contracts front-end. Internal fail-closed invariants use foundation::requireInvariant.
if grep -RInE '\bcontract_assert\b|\bpre[[:space:]]*\(|\bpost[[:space:]]*\(' \
        "${ROOT_DIR}/src" "${ROOT_DIR}/apps" "${ROOT_DIR}/sdk" \
        --include='*.cpp' --include='*.cppm' >/tmp/openproof-contract-syntax.$$; then
    cat /tmp/openproof-contract-syntax.$$ >&2
    rm -f /tmp/openproof-contract-syntax.$$
    fail "experimental contract syntax present in production source"
fi
rm -f /tmp/openproof-contract-syntax.$$
grep -q 'OPENPROOF_ENABLE_EXPERIMENTAL_CONTRACTS' \
    "${ROOT_DIR}/cmake/OpenProofCompileOptions.cmake" \
    || fail "experimental Contracts opt-in is missing"
grep -q -- '-fno-contracts' "${ROOT_DIR}/cmake/OpenProofCompileOptions.cmake" \
    || fail "production GCC profile does not explicitly disable Contracts"

# Standard-library owner headers must be local to the translation unit using them.
while IFS= read -r file; do
    if grep -Eq 'std::(scoped_lock|lock_guard|unique_lock)' "$file" \
       && ! grep -q '^#include <mutex>' "$file"; then
        fail "synchronization primitive without <mutex>: ${file}"
    fi
    if grep -Eq 'std::ranges::(all_of|any_of|none_of|sort|adjacent_find|binary_search|find|find_if|copy|transform|is_sorted)' "$file" \
       && ! grep -q '^#include <algorithm>' "$file"; then
        fail "ranges algorithm without <algorithm>: ${file}"
    fi
    if grep -Eq 'std::(make_shared|shared_ptr)' "$file" \
       && ! grep -q '^#include <memory>' "$file"; then
        fail "shared ownership primitive without <memory>: ${file}"
    fi
done < <(find "${ROOT_DIR}/src" "${ROOT_DIR}/sdk/cpp" -type f \( -name '*.cpp' -o -name '*.cppm' \) -print)

# Every module translation unit must include the owning standard-library header
# for each std type it names. Imports do not make a standard header's declarations
# locally visible, and relying on transitive visibility is especially brittle with
# GCC BMIs and clean builds.
python3 - "${ROOT_DIR}" <<'PY_MODULE_HEADERS'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
checks = (
    (re.compile(r'\bstd::vector\b'), '<vector>'),
    (re.compile(r'\bstd::optional\b'), '<optional>'),
    (re.compile(r'\bstd::string\b'), '<string>'),
    (re.compile(r'\bstd::string_view\b'), '<string_view>'),
    (re.compile(r'\bstd::(?:unique_ptr|shared_ptr|weak_ptr)\b'), '<memory>'),
    (re.compile(r'\bstd::map\b'), '<map>'),
    (re.compile(r'\bstd::unordered_map\b'), '<unordered_map>'),
    (re.compile(r'\bstd::unordered_set\b'), '<unordered_set>'),
    (re.compile(r'\bstd::set\b'), '<set>'),
    (re.compile(r'\bstd::span\b'), '<span>'),
    (re.compile(r'\bstd::array\b'), '<array>'),
    (re.compile(r'\bstd::chrono\b'), '<chrono>'),
    (re.compile(r'\bstd::function\b'), '<functional>'),
    (re.compile(r'\bstd::expected\b'), '<expected>'),
    (re.compile(r'\bstd::variant\b'), '<variant>'),
    (re.compile(r'\bstd::tuple\b'), '<tuple>'),
    (re.compile(r'\bstd::pair\b'), '<utility>'),
)

failures = []
translation_units = list(root.glob('src/**/*.cppm')) + list(root.glob('src/**/*.cpp'))
translation_units += list(root.glob('sdk/cpp/**/*.cppm')) + list(root.glob('sdk/cpp/**/*.cpp'))
for unit in translation_units:
    text = unit.read_text(encoding='utf-8')
    for pattern, header in checks:
        if pattern.search(text) and f'#include {header}' not in text:
            failures.append((unit.relative_to(root), header))

if failures:
    for unit, header in failures:
        print(f'release gate: module translation unit uses an STL type without {header}: {unit}',
              file=sys.stderr)
    raise SystemExit(1)
PY_MODULE_HEADERS

# GCC requires all imports following a named module declaration to remain contiguous.
# A declaration or preprocessor block between the module declaration and a later import
# makes clean module builds fail before semantic analysis.
python3 - "${ROOT_DIR}" <<'PY_MODULE_IMPORTS'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
module_decl = re.compile(r'^(?:export\s+)?module\s+[A-Za-z0-9_.:-]+\s*;\s*$')
import_decl = re.compile(r'^(?:export\s+)?import\s+[^;]+;\s*$')
failed = False

for unit in list(root.glob('src/**/*.cppm')) + list(root.glob('sdk/cpp/**/*.cppm')):
    lines = unit.read_text(encoding='utf-8').splitlines()
    named_module = None
    for index, raw in enumerate(lines):
        if module_decl.match(raw.strip()):
            named_module = index
            break
    if named_module is None:
        continue

    imports_started = False
    imports_closed = False
    for index in range(named_module + 1, len(lines)):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue
        if import_decl.match(stripped):
            if imports_closed:
                print(
                    f'release gate: non-contiguous post-module import: '
                    f'{unit.relative_to(root)}:{index + 1}',
                    file=sys.stderr,
                )
                failed = True
            imports_started = True
            continue
        if imports_started or stripped.startswith('#'):
            imports_closed = True
        else:
            imports_closed = True

if failed:
    raise SystemExit(1)
PY_MODULE_IMPORTS

# Darwin + GCC strict-mode Boost boundary: every target that directly consumes
# Boost headers must restore long-long detection when Boost.Config suppresses it.
python3 - "${ROOT_DIR}" <<'PY_BOOST_LONG_LONG'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
failed = False
for cmake in (root / 'src').rglob('CMakeLists.txt'):
    text = cmake.read_text(encoding='utf-8')
    if 'Boost::headers' not in text:
        continue
    targets = re.findall(r'openproof_add_module\(([^\s\)]+)', text)
    for target in targets:
        # Only require the workaround on a target block that itself mentions Boost::headers.
        start = text.find(f'openproof_add_module({target}')
        if start < 0:
            continue
        next_target = text.find('openproof_add_module(', start + 1)
        block = text[start:] if next_target < 0 else text[start:next_target]
        if 'Boost::headers' in block and f'target_compile_definitions({target} PRIVATE BOOST_HAS_LONG_LONG=1)' not in text:
            print(f'release gate: missing BOOST_HAS_LONG_LONG workaround for {cmake.relative_to(root)}:{target}', file=sys.stderr)
            failed = True
if failed:
    raise SystemExit(1)
PY_BOOST_LONG_LONG

# GCC/Darwin BMI stability guard. The build must invalidate GCC CMIs whenever
# compiler/SDK/module-cache inputs change, and the qualified Darwin profile
# serializes module compilation to avoid readers observing a concurrently
# replaced .gcm.
grep -q 'OPENPROOF_MODULE_CACHE_EPOCH' \
    "${ROOT_DIR}/cmake/OpenProofCompileOptions.cmake" \
    || fail "module-cache epoch/fingerprint invalidation is missing"
grep -q 'OPENPROOF_MODULE_BUILD_FINGERPRINT' \
    "${ROOT_DIR}/cmake/OpenProofCompileOptions.cmake" \
    || fail "module build fingerprint is missing"
grep -q 'OPENPROOF_MODULE_SOURCE_FINGERPRINT' \
    "${ROOT_DIR}/cmake/OpenProofCompileOptions.cmake" \
    || fail "module source fingerprint is missing"
grep -q 'CMAKE_CONFIGURE_DEPENDS' \
    "${ROOT_DIR}/cmake/OpenProofCompileOptions.cmake" \
    || fail "module interfaces are not configure dependencies"
grep -q 'file(SHA256.*_openproof_module_source' \
    "${ROOT_DIR}/cmake/OpenProofCompileOptions.cmake" \
    || fail "module interface content hashing is missing"
grep -q 'module_sources=${OPENPROOF_MODULE_SOURCE_FINGERPRINT}' \
    "${ROOT_DIR}/cmake/OpenProofCompileOptions.cmake" \
    || fail "module source fingerprint is not folded into the BMI fingerprint"
grep -q 'file(GLOB_RECURSE _openproof_stale_gcms' \
    "${ROOT_DIR}/cmake/OpenProofCompileOptions.cmake" \
    || fail "stale GCC BMI invalidation is missing"
grep -q 'openproof_gnu_darwin_modules=1' \
    "${ROOT_DIR}/cmake/OpenProofModule.cmake" \
    || fail "GNU/Darwin module compile pool is missing"
grep -q 'JOB_POOL_COMPILE' \
    "${ROOT_DIR}/cmake/OpenProofModule.cmake" \
    || fail "module targets are not assigned to the GNU/Darwin compile pool"

# JAR module ABI/source synchronization guard. A stale partition paired with a
# newer implementation produces misleading GCC module diagnostics and invalid BMIs.
python3 - "${ROOT_DIR}" <<'PY_JAR_SYNC'
from pathlib import Path
import sys

root = Path(sys.argv[1])
interface = (root / 'src/oauth/jar.cppm').read_text(encoding='utf-8')
implementation = (root / 'src/oauth/jar.cpp').read_text(encoding='utf-8')
required_interface = [
    'explicit ClientRequestSigningKey(std::shared_ptr<const void> state) noexcept;',
    'std::shared_ptr<const void> m_state;',
]
required_implementation = [
    'ClientRequestSigningKey::ClientRequestSigningKey(std::shared_ptr<const void> state) noexcept',
    'keyState(m_state)',
]
missing = [item for item in required_interface if item not in interface]
missing += [item for item in required_implementation if item not in implementation]
if missing:
    for item in missing:
        print(f'release gate: JAR interface/implementation mismatch: missing {item}', file=sys.stderr)
    raise SystemExit(1)
PY_JAR_SYNC

# GCC 16.1 module-stability boundary: exported high-complexity records expose
# only an opaque shared state, not vectors/optional/Instant/StrongId layouts.
python3 - "${ROOT_DIR}" <<'PY_OPAQUE'
from pathlib import Path
import sys
root = Path(sys.argv[1])
required = {
    'src/client/model.cppm': ['Client'],
    'src/oauth/model.cppm': ['AuthorizationRequest', 'AuthorizationCode'],
    'src/oauth/jar.cppm': ['ClientRequestSigningKey'],
    'src/token/model.cppm': ['TokenContext', 'AccessTokenRecord', 'RefreshTokenRecord', 'TokenClaims'],
    'src/evidence/model.cppm': ['Evidence'],
    'src/trust/model.cppm': ['TrustAssessment'],
}
failed = False
for rel, classes in required.items():
    text = (root / rel).read_text(encoding='utf-8')
    for name in classes:
        start = text.find(f'class {name} final')
        if start < 0:
            print(f'release gate: missing opaque class {rel}:{name}', file=sys.stderr)
            failed = True
            continue
        end = text.find('\n};', start)
        body = text[start:end]
        if 'std::shared_ptr<' not in body:
            print(f'release gate: heavy exported layout not opaque {rel}:{name}', file=sys.stderr)
            failed = True
if failed:
    raise SystemExit(1)
PY_OPAQUE

# Repository implementation details stay out of CMIs.
python3 - "${ROOT_DIR}" <<'PY_REPO'
from pathlib import Path
import sys
root = Path(sys.argv[1])
interfaces = [
    'src/application/repository.cppm', 'src/client/repository.cppm',
    'src/oauth/repository.cppm', 'src/token/repository.cppm',
    'src/evidence/repository.cppm', 'src/identity/profile/repository.cppm',
]
failed = False
for rel in interfaces:
    text = (root / rel).read_text(encoding='utf-8')
    if 'std::map<' in text or 'std::mutex' in text:
        print(f'release gate: repository CMI leaks storage: {rel}', file=sys.stderr)
        failed = True
    if 'struct Impl;' not in text or 'std::unique_ptr<Impl> m_impl;' not in text:
        print(f'release gate: repository PImpl missing: {rel}', file=sys.stderr)
        failed = True
if failed:
    raise SystemExit(1)
PY_REPO

# Digest wrappers must remain trivial, interface-defined strong values.
python3 - "${ROOT_DIR}" <<'PY_DIGEST'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
models = {
    'src/client/model.cppm': 'ClientSecretDigest',
    'src/oauth/model.cppm': 'CodeDigest',
    'src/token/model.cppm': 'TokenDigest',
}
failed = False
for rel, name in models.items():
    text = (root / rel).read_text(encoding='utf-8')
    start = text.find(f'class {name} final')
    end = text.find('\n};', start)
    body = text[start:end]
    if 'std::array<std::byte, 32>' not in body:
        print(f'release gate: digest storage not local array: {rel}:{name}', file=sys.stderr)
        failed = True
    if re.search(rf'~{name}\s*\(|{name}\s*\(\s*const\s+{name}', body):
        print(f'release gate: digest special member reintroduced: {rel}:{name}', file=sys.stderr)
        failed = True
if failed:
    raise SystemExit(1)
PY_DIGEST

# OIDC derives ACR/AMR from the canonical OAuth assurance/strength API and
# directly imports the provider vocabulary used for the wire mapping. The CMake
# edge is mandatory so CMake can place the provider CMI in GCC's module mapper.
grep -q '^import openproof.identity.provider;' "${ROOT_DIR}/src/oidc/service.cpp" \
    || fail "OIDC service is missing its direct identity.provider import"
grep -q 'openproof_identity_provider' "${ROOT_DIR}/src/oidc/CMakeLists.txt" \
    || fail "OIDC target is missing the identity-provider CMake dependency"
grep -q 'authorization.assurance()' "${ROOT_DIR}/src/oidc/service.cpp" \
    || fail "OIDC ACR mapping is not sourced from RedeemedAuthorization::assurance"
grep -q 'authorization.strength()' "${ROOT_DIR}/src/oidc/service.cpp" \
    || fail "OIDC AMR mapping is not sourced from RedeemedAuthorization::strength"
if grep -RInE 'assuranceName\(\)|usedKnowledgeFactor\(\)|usedPossessionFactor\(\)|usedInherenceFactor\(\)|phishingResistantAuthentication\(\)' \
        "${ROOT_DIR}/src/oauth" --include='*.cpp' --include='*.cppm' >/tmp/openproof-oauth-convenience.$$; then
    cat /tmp/openproof-oauth-convenience.$$ >&2
    rm -f /tmp/openproof-oauth-convenience.$$
    fail "transient OAuth assurance convenience API was reintroduced"
fi
rm -f /tmp/openproof-oauth-convenience.$$

if grep -qE '\bemptyResponse[[:space:]]*\(' "${ROOT_DIR}/src/application/http/http.cpp"; then
    fail "unused application HTTP emptyResponse helper was reintroduced"
fi

# Every project-module import in an implementation unit must have a matching
# target dependency. CMake's module collator can only place a BMI/CMI in the
# compiler module map when the provider target is in the dependency graph.
python3 - "${ROOT_DIR}" <<'PY_IMPORT_GRAPH'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
module_target = {}
target_dependencies = {}
file_target = {}

for cmake in root.glob('src/**/CMakeLists.txt'):
    text = cmake.read_text(encoding='utf-8')
    for match in re.finditer(r'openproof_add_module\((\w+)\s+(.*?)\n\)', text, re.S):
        target, body = match.group(1), match.group(2)
        dependencies = set()
        for key in ('LINK_PUBLIC', 'LINK_PRIVATE'):
            dep = re.search(key + r'\s+(.*?)(?=\n\s*(?:MODULES|PRIVATE_MODULES|SOURCES|LINK_PUBLIC|LINK_PRIVATE)|\Z)', body, re.S)
            if dep:
                dependencies.update(re.findall(r'\bopenproof_[A-Za-z0-9_]+\b', dep.group(1)))
        target_dependencies[target] = dependencies
        module_groups = []
        for key in ('MODULES', 'PRIVATE_MODULES'):
            modules = re.search(
                key + r'\s+(.*?)(?=\n\s*(?:MODULES|PRIVATE_MODULES|SOURCES|LINK_PUBLIC|LINK_PRIVATE)|\Z)',
                body, re.S)
            if modules:
                module_groups.append(modules.group(1))
        for group in module_groups:
            for relative in re.findall(r'([\w./-]+\.cppm)', group):
                interface = cmake.parent / relative
                if not interface.exists():
                    continue
                interface_text = interface.read_text(encoding='utf-8')
                provided = re.search(r'export\s+module\s+([\w.]+(?::[\w.]+)?)\s*;', interface_text)
                if provided:
                    module_target[provided.group(1)] = target
                file_target[interface.resolve()] = target
        for source in re.findall(r'([\w./-]+\.cpp)', body):
            file_target[(cmake.parent / source).resolve()] = target


failures = []
for source, target in file_target.items():
    if not source.exists():
        continue
    text = source.read_text(encoding='utf-8')
    for imported in re.findall(r'^import\s+(openproof\.[\w.]+)\s*;', text, re.M):
        provider = module_target.get(imported)
        if provider and provider != target and provider not in target_dependencies.get(target, set()):
            failures.append((source.relative_to(root), target, imported, provider))

if failures:
    for source, target, imported, provider in failures:
        print(f'release gate: {source}: {target} imports {imported} from {provider} without a CMake dependency', file=sys.stderr)
    raise SystemExit(1)
PY_IMPORT_GRAPH

# OAuth/client/browser hardening required by the 1.1 release candidate.
grep -q 'security::constantTimeEquals' "${ROOT_DIR}/src/client/service.cpp" \
    || fail "client-secret authentication is not constant-time"
if grep -qE 'calculated\.value\(\)[[:space:]]*==[[:space:]]*client->secretDigest' \
        "${ROOT_DIR}/src/client/service.cpp"; then
    fail "ordinary client-secret digest equality was reintroduced"
fi
grep -q 'current.expiresAt()' "${ROOT_DIR}/src/token/service.cpp" \
    || fail "refresh-token rotation can slide the family expiration"
grep -q 'consumeBound' "${ROOT_DIR}/src/oauth/service.cpp" \
    || fail "authorization code is not consumed through the bound atomic operation"
# Explicit durable consent is now part of the authorization surface. Keep
# offline_access tied to that subsystem instead of regressing to the earlier
# fail-closed placeholder behavior.
grep -q 'offline_access' "${ROOT_DIR}/src/oidc/service.cpp" \
    || fail "OIDC discovery no longer advertises consent-backed offline_access"
grep -q 'openproof_consent' "${ROOT_DIR}/src/oauth/http/CMakeLists.txt" \
    || fail "OAuth HTTP target is missing the consent module dependency"
grep -q 'm_consents->covers' "${ROOT_DIR}/src/oauth/http/http.cpp" \
    || fail "authorization endpoint no longer checks remembered consent"
grep -q 'm_consents->grant' "${ROOT_DIR}/src/oauth/http/http.cpp" \
    || fail "OAuth approval paths no longer persist explicit consent"
grep -q 'm_consents->revoke' "${ROOT_DIR}/src/oauth/http/http.cpp" \
    || fail "self-service consent revocation is missing"

grep -q '"iss", m_oidc->issuer()' "${ROOT_DIR}/src/oauth/http/http.cpp" \
    || fail "authorization response issuer binding is missing"
grep -q 'authorization_response_iss_parameter_supported' "${ROOT_DIR}/src/oidc/service.cpp" \
    || fail "OIDC discovery does not advertise authorization response issuer support"
grep -q 'returnedIssuer != m_config.issuer()' "${ROOT_DIR}/sdk/cpp/openproof_sdk.cpp" \
    || fail "C++ SDK does not validate authorization response issuer"
grep -q "returnedIssuer !== this.issuer" "${ROOT_DIR}/sdk/javascript/openproof.js" \
    || fail "JavaScript SDK does not validate authorization response issuer"
grep -q "returnedIssuer == config.issuer" "${ROOT_DIR}/sdk/swift/Sources/OpenProof/OpenProof.swift" \
    || fail "Swift SDK does not validate authorization response issuer"
grep -q "returnedIssuer == config.issuer.trimEnd('/')" \
    "${ROOT_DIR}/sdk/kotlin/src/main/kotlin/org/openproof/identity/OpenProof.kt" \
    || fail "Kotlin SDK does not validate authorization response issuer"

# Browser ambient credentials use __Host- cookies only. The prefix mechanically
# requires Secure, Path=/ and no Domain in conforming user agents.
if grep -RInE '"openproof_(session|preauth|preauth_binding|login_csrf)"' \
        "${ROOT_DIR}/src" "${ROOT_DIR}/tests" --include='*.cpp' --include='*.cppm' \
        >/tmp/openproof-old-cookies.$$; then
    cat /tmp/openproof-old-cookies.$$ >&2
    rm -f /tmp/openproof-old-cookies.$$
    fail "legacy non-Host cookie name remains"
fi
rm -f /tmp/openproof-old-cookies.$$
for cookie_name in \
    '__Host-openproof-session' \
    '__Host-openproof-preauth' \
    '__Host-openproof-preauth-binding' \
    '__Host-openproof-login-csrf'; do
    grep -Rqs -- "${cookie_name}" "${ROOT_DIR}/src" \
        || fail "required Host-only cookie is missing: ${cookie_name}"
done
grep -q '"; Path="' "${ROOT_DIR}/src/authentication/http/http.cpp" \
    || fail "authentication cookie builder lost explicit Path"
grep -q '"; Secure; HttpOnly; SameSite=Strict"' "${ROOT_DIR}/src/authentication/http/http.cpp" \
    || fail "authentication cookie security attributes regressed"
grep -q '"; Secure; HttpOnly; SameSite=Lax"' "${ROOT_DIR}/src/oauth/http/http.cpp" \
    || fail "OAuth browser cookie security attributes regressed"

# RFC 8252 native loopback behavior is an intentional compatibility/security
# invariant: loopback IP literals may vary the ephemeral port, while localhost
# and non-loopback HTTP redirect registrations are rejected.
grep -q 'sameNativeLoopbackRedirect' "${ROOT_DIR}/src/client/model.cpp" \
    || fail "native loopback redirect matching is missing"
grep -q 'host == "127.0.0.1" || host == "\[::1\]"' "${ROOT_DIR}/src/client/model.cpp" \
    || fail "native loopback redirect host restriction regressed"

# The identity-platform PostgreSQL adapter was initially generated in a compressed
# one-line style that hid -Wshadow and -Wmisleading-indentation defects. Keep the
# new adapter section statement-separated and reject the specific shadow pattern
# that failed the GCC 16.1 build.
python3 - "${ROOT_DIR}" <<'PY_POSTGRES_WARNINGS'
from pathlib import Path
import re, sys
path = Path(sys.argv[1]) / 'src/storage/postgres/postgres.cpp'
text = path.read_text(encoding='utf-8')
marker = '[[nodiscard]] foundation::Instant storedInstant'
start = text.find(marker)
if start < 0:
    print('release gate: identity-platform PostgreSQL adapter marker is missing', file=sys.stderr)
    raise SystemExit(1)
tail = text[start:]
if re.search(r';[ \t]*(?:if|for|while|return)\b', tail):
    print('release gate: compressed adjacent control-flow statements remain in identity-platform PostgreSQL adapter', file=sys.stderr)
    raise SystemExit(1)
if re.search(r'\[.*?\]\([^)]*\bvalue\b[^)]*\)', tail):
    # `value` is a common repository method parameter; lambdas must not shadow it.
    print('release gate: lambda parameter named value can shadow repository method parameters', file=sys.stderr)
    raise SystemExit(1)
PY_POSTGRES_WARNINGS

# C++26 runtime facilities must be qualified by an actual configure-time link
# probe, not just by a feature-test macro. GCC 16.1 currently supplies
# Production must not depend on std::text_encoding runtime support. The protocol
# and JSON/log wire policy is UTF-8 regardless of the host locale; locale
# variables are diagnostic metadata only.
if grep -RInE 'std::text_encoding|#include[[:space:]]*<text_encoding>|OPENPROOF_HAS_LINKABLE_TEXT_ENCODING|openproof_cxx26_runtime|stdc\+\+exp' \
        "${ROOT_DIR}/apps" "${ROOT_DIR}/src" "${ROOT_DIR}/sdk" "${ROOT_DIR}/CMakeLists.txt" \
        "${ROOT_DIR}/apps/opp/CMakeLists.txt" --include='*.cpp' --include='*.cppm' --include='*.txt' \
        >/tmp/openproof-text-encoding-runtime.$$; then
    cat /tmp/openproof-text-encoding-runtime.$$ >&2
    rm -f /tmp/openproof-text-encoding-runtime.$$
    fail "production source depends on std::text_encoding/libstdc++exp"
fi
rm -f /tmp/openproof-text-encoding-runtime.$$
[[ ! -e "${ROOT_DIR}/cmake/OpenProofCxx26Runtime.cmake" ]] \
    || fail "obsolete C++26 text-encoding runtime probe is present"
grep -q 'text_encoding_policy' "${ROOT_DIR}/apps/opp/main.cpp" \
    || fail "startup UTF-8 encoding policy field is missing"
grep -q 'locale_environment' "${ROOT_DIR}/apps/opp/main.cpp" \
    || fail "startup locale diagnostic field is missing"

# Strict-provider warning regressions that GCC 16.1 surfaced during the
# macOS qualification build. These patterns are rejected here so they cannot
# re-enter through a provider added or refactored without a clean compiler run.
python3 - "${ROOT_DIR}" <<'PY_PROVIDER_WARNINGS'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
failures: list[str] = []

for path in (root / 'src').rglob('*.cpp'):
    text = path.read_text(encoding='utf-8')
    relative = path.relative_to(root)

    if 'SSL_set_tlsext_host_name' in text:
        failures.append(f'{relative}: use SSL_ctrl with a mutable hostname instead of the OpenSSL SNI macro under -Wold-style-cast')

    if re.search(r'for\s*\(\s*(?:const\s+)?unsigned\s+char\s+\w+\s*:', text):
        failures.append(f'{relative}: unsigned-char range-for can trigger -Wsign-conversion when the range stores char')

    if re.search(r'std::ranges::find\([^\n,]+,\s*"', text):
        failures.append(f'{relative}: ranges::find with a string literal is not heterogeneously equality-comparable on the qualified libstdc++')

    if re.search(r'"[^"\n]*\\x[0-9A-Fa-f]{2}[0-9A-Fa-f]', text):
        failures.append(f'{relative}: hexadecimal string escape is followed by another hex digit and can consume too many digits')

    # Detect Implementation constructor parameters that reuse direct member
    # names such as config/clock/caFile; -Wshadow turns those into hard errors.
    for match in re.finditer(r'\bImplementation\s*\(', text):
        start = match.end()
        depth = 1
        cursor = start
        while cursor < len(text) and depth:
            if text[cursor] == '(':
                depth += 1
            elif text[cursor] == ')':
                depth -= 1
            cursor += 1
        if depth:
            continue
        parameters = text[start:cursor - 1]
        names = set(re.findall(r'\b(config|clock|caFile)\b', parameters))
        if not names:
            continue
        following = text[cursor:cursor + 1600]
        shadowed = sorted(name for name in names if re.search(rf'\b{re.escape(name)}\s*;', following))
        if shadowed:
            line = text.count('\n', 0, match.start()) + 1
            failures.append(f'{relative}:{line}: Implementation constructor shadows member(s): {", ".join(shadowed)}')

if failures:
    for failure in failures:
        print(f'release gate: {failure}', file=sys.stderr)
    raise SystemExit(1)
PY_PROVIDER_WARNINGS

# Darwin builds must select exactly one SDK before project() and Enterprise
# native dependencies must be resolved from that same root. Mixing Xcode and
# CommandLineTools SDK headers corrupts GCC module BMIs.
grep -q 'openproof_configure_darwin_sdk()' "${ROOT_DIR}/CMakeLists.txt" \
    || fail "canonical Darwin SDK initialization is missing"
grep -q 'OPENPROOF_MACOS_SDKROOT}/usr/include/libxml2' \
    "${ROOT_DIR}/src/providers/enterprise/CMakeLists.txt" \
    || fail "Enterprise libxml2 is not pinned to the canonical macOS SDK"
grep -q 'OPENPROOF_MACOS_SDKROOT}/System/Library/Frameworks/LDAP.framework' \
    "${ROOT_DIR}/src/providers/enterprise/CMakeLists.txt" \
    || fail "Enterprise LDAP framework is not pinned to the canonical macOS SDK"
grep -q '^import openproof.identity.core;' \
    "${ROOT_DIR}/src/enterprise/scim/http/http.cppm" \
    || fail "SCIM HTTP interface is missing its direct identity.core import"
grep -q 'openproof_identity_core' \
    "${ROOT_DIR}/src/enterprise/scim/http/CMakeLists.txt" \
    || fail "SCIM HTTP target is missing the identity-core CMake dependency"

# Apple exposes OpenLDAP through a deprecated framework, but OpenProof still
# needs protocol-compatible LDAP while preserving -Werror for all unrelated
# code. Every direct LDAP C API call therefore stays inside one narrow GCC
# diagnostic boundary; the rest of the Enterprise provider remains fully strict.
python3 - "${ROOT_DIR}" <<'PY_ENTERPRISE_STRICT'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
path = root / 'src/providers/enterprise/enterprise.cpp'
text = path.read_text(encoding='utf-8')

push = text.find('#pragma GCC diagnostic ignored "-Wdeprecated-declarations"')
pop = text.find('#pragma GCC diagnostic pop', push + 1)
if push < 0 or pop < 0 or pop <= push:
    print('release gate: Apple LDAP deprecation boundary is missing or malformed', file=sys.stderr)
    raise SystemExit(1)

ldap_calls = re.compile(r'\bldap_(?:unbind_ext_s|msgfree|value_free_len|memfree|initialize|set_option|sasl_bind_s|get_values_len|search_ext_s|count_entries|first_entry|get_dn)\s*\(')
for match in ldap_calls.finditer(text):
    if not (push < match.start() < pop):
        line = text.count('\n', 0, match.start()) + 1
        print(f'release gate: direct deprecated LDAP API escaped the compatibility boundary: {path.relative_to(root)}:{line}', file=sys.stderr)
        raise SystemExit(1)

for forbidden, message in (
    ('digest->bytes()', 'Enterprise SHA-256 digest incorrectly assumes a bytes() member'),
    ('BAD_CAST', 'Enterprise XML code reintroduced libxml BAD_CAST under -Wold-style-cast'),
    ('const std::time_t timestamp', 'Enterprise X509_cmp_time timestamp must remain mutable'),
):
    if forbidden in text:
        print(f'release gate: {message}', file=sys.stderr)
        raise SystemExit(1)

if 'standardBase64(digest.value())' not in text:
    print('release gate: SAML digest is not encoded from the Sha256Digest value', file=sys.stderr)
    raise SystemExit(1)
if 'foundation::toBase64Url(digest.value())' not in text:
    print('release gate: Enterprise HMAC token is not encoded from the Sha256Digest value', file=sys.stderr)
    raise SystemExit(1)
PY_ENTERPRISE_STRICT

# No unfinished production markers.
if grep -RInE '\b(TODO|FIXME|PLACEHOLDER)\b' "${ROOT_DIR}/src" "${ROOT_DIR}/sdk" \
        --include='*.cpp' --include='*.cppm' >/tmp/openproof-markers.$$; then
    cat /tmp/openproof-markers.$$ >&2
    rm -f /tmp/openproof-markers.$$
    fail "unfinished production marker found"
fi
rm -f /tmp/openproof-markers.$$

# Authentication exports an identity-provider namespace alias named `provider`.
# Inside nested authentication namespaces, an unqualified `provider::...` therefore
# resolves to openproof::authentication::provider rather than openproof::provider.
# Concrete authentication-provider integrations must use a root-qualified namespace.
PASSKEY_HTTP_INTERFACE="${ROOT_DIR}/src/authentication/http/passkey.cppm"
PASSKEY_HTTP_IMPL="${ROOT_DIR}/src/authentication/http/passkey.cpp"
grep -q '::openproof::provider::passkey::PasskeyService' "${PASSKEY_HTTP_INTERFACE}" \
    || fail "passkey HTTP interface must root-qualify openproof::provider::passkey"
grep -q 'namespace passkey = ::openproof::provider::passkey;' "${PASSKEY_HTTP_IMPL}" \
    || fail "passkey HTTP implementation alias must root-qualify openproof::provider::passkey"
grep -q '^import openproof.identity.core;$' "${PASSKEY_HTTP_IMPL}" \
    || fail "passkey HTTP implementation must import openproof.identity.core for IdentityId"
if grep -q 'json::object{{' "${PASSKEY_HTTP_IMPL}"; then
    fail "passkey HTTP JSON construction must avoid Boost.JSON initializer-list deduction"
fi
if grep -RInE '(^|[^:[:alnum:]_])provider::(passkey|web3|enterprise|github|oidc|local|farcaster|wallet|microsoft|google|apple)::' \
        "${ROOT_DIR}/src/authentication" --include='*.cpp' --include='*.cppm' \
        >/tmp/openproof-auth-provider-shadow.$$; then
    cat /tmp/openproof-auth-provider-shadow.$$ >&2
    rm -f /tmp/openproof-auth-provider-shadow.$$
    fail "authentication code contains an unqualified concrete openproof::provider namespace reference"
fi
rm -f /tmp/openproof-auth-provider-shadow.$$

# Federated HTTP interface/implementation synchronization guard.  GCC diagnostics
# can render the current source line while semantic lookup still comes from a
# stale BMI, so keep the source contract explicit in addition to source-sensitive
# BMI invalidation.
FEDERATED_HTTP_INTERFACE="${ROOT_DIR}/src/authentication/http/federated.cppm"
FEDERATED_HTTP_IMPL="${ROOT_DIR}/src/authentication/http/federated.cpp"
grep -qE 'gateway::HttpResponse[[:space:]]+providers\(\);' "${FEDERATED_HTTP_INTERFACE}" \
    || fail "federated HTTP interface must declare providers() without an unused request"
grep -qE 'FederatedAuthenticationHttpApi::providers\(\)' "${FEDERATED_HTTP_IMPL}" \
    || fail "federated HTTP implementation is out of sync with providers()"
if grep -qE 'providers\([[:space:]]*gateway::HttpRequest' "${FEDERATED_HTTP_INTERFACE}" "${FEDERATED_HTTP_IMPL}"; then
    fail "stale federated providers(HttpRequest) signature was reintroduced"
fi

# GCC module-reader regression guard for account.delivery.
# GCC has historically failed while a primary module implementation unit reloads
# its own CMI/BMI ("failed to read compiled module cluster ... Bad file data").
# Keep this adapter on a private implementation partition that never imports the
# primary module, and keep the exported surface factory-only.
DELIVERY_CMAKE="${ROOT_DIR}/src/account/delivery/CMakeLists.txt"
DELIVERY_INTERFACE="${ROOT_DIR}/src/account/delivery/delivery.cppm"
DELIVERY_IMPL="${ROOT_DIR}/src/account/delivery/delivery_impl.cppm"
[[ ! -e "${ROOT_DIR}/src/account/delivery/delivery.cpp" ]] \
    || fail "account.delivery primary-module implementation unit was reintroduced"
grep -q 'PRIVATE_MODULES' "${DELIVERY_CMAKE}" \
    || fail "account.delivery private module partition is missing from CMake"
grep -q 'delivery_impl.cppm' "${DELIVERY_CMAKE}" \
    || fail "account.delivery implementation partition is missing from CMake"
grep -q 'createWebhookVerificationDelivery' "${DELIVERY_INTERFACE}" \
    || fail "account.delivery factory-only public API is missing"
if grep -qE 'class[[:space:]]+Webhook(Config|VerificationDelivery)' "${DELIVERY_INTERFACE}"; then
    fail "account.delivery concrete webhook implementation leaked back into the primary CMI"
fi
grep -q 'module openproof.account.delivery:implementation;' "${DELIVERY_IMPL}" \
    || fail "account.delivery private implementation partition declaration is missing"
if grep -qE '^import[[:space:]]+openproof\.account\.delivery[[:space:]]*;' "${DELIVERY_IMPL}"; then
    fail "account.delivery private partition must not reload the primary module CMI"
fi
grep -q '#include <chrono>' "${DELIVERY_IMPL}" \
    || fail "account.delivery Duration operations require direct <chrono> visibility"
grep -q 'createWebhookVerificationDelivery' "${ROOT_DIR}/apps/opp/main.cpp" \
    || fail "opp composition root is not using the account.delivery factory"

# GCC module CMIs must not serialize anonymous-namespace entities.  In a .cppm,
# non-exported helpers still have module linkage when placed in a named detail
# namespace; anonymous namespaces instead give internal linkage and can make
# imported standard-library template specializations unwritable.
if grep -RInE '^[[:space:]]*namespace[[:space:]]*\{' \
        "${ROOT_DIR}/src" "${ROOT_DIR}/sdk/cpp" --include='*.cppm' \
        >/tmp/openproof-module-anon-namespace.$$; then
    cat /tmp/openproof-module-anon-namespace.$$ >&2
    rm -f /tmp/openproof-module-anon-namespace.$$
    fail "anonymous namespaces are forbidden in project module units; use a named detail namespace"
fi
rm -f /tmp/openproof-module-anon-namespace.$$

# Strict -Wunused-parameter regression guard for HTTP request handlers.  When a
# private helper does not consume the request at all, remove it from that helper
# instead of suppressing the warning.  This parser is intentionally scoped to
# by-value gateway::HttpRequest parameters, the convention used by HTTP handlers.
python3 - "${ROOT_DIR}" <<'PY_UNUSED_HTTP_REQUEST'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
failed = False
pattern = re.compile(
    r'^[^\n]*::[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*gateway::HttpRequest\s+request[^)]*\)'
    r'\s*(?:const\s*)?(?:noexcept\s*)?\{',
    re.MULTILINE,
)

for unit in (root / 'src').rglob('*.cpp'):
    text = unit.read_text(encoding='utf-8')
    for match in pattern.finditer(text):
        cursor = match.end()
        depth = 1
        while cursor < len(text) and depth:
            if text[cursor] == '{':
                depth += 1
            elif text[cursor] == '}':
                depth -= 1
            cursor += 1
        body = text[match.end():cursor - 1]
        if not re.search(r'\brequest\b', body):
            line = text.count('\n', 0, match.start()) + 1
            print(
                f'release gate: unused by-value HttpRequest parameter: '
                f'{unit.relative_to(root)}:{line}',
                file=sys.stderr,
            )
            failed = True

if failed:
    raise SystemExit(1)
PY_UNUSED_HTTP_REQUEST

TEST_COUNT="$(grep -RhoE 'TEST(_F)?\(' "${ROOT_DIR}/tests" --include='*.cpp' | wc -l | tr -d ' ')"
printf 'OpenProof static release gates passed (%s C++ tests declared).\n' "${TEST_COUNT}"

if [[ "${OPENPROOF_STATIC_ONLY:-0}" == "1" ]]; then
    exit 0
fi

BUILD_DIR="${OPENPROOF_BUILD_DIR:-${ROOT_DIR}/cmake-build-release-gate}"
C_COMPILER="${OPENPROOF_CC:-gcc-16}"
CXX_COMPILER="${OPENPROOF_CXX:-c++-16}"
GENERATOR="${OPENPROOF_GENERATOR:-Ninja}"

# CMI/BMI artifacts are compiler-stateful: a release verification is always clean.
rm -rf "${BUILD_DIR}"

if [[ "$(uname -s)" == "Darwin" ]]; then
    JOBS="$(sysctl -n hw.ncpu)"
else
    JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
fi

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" -G "${GENERATOR}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="${C_COMPILER}" \
    -DCMAKE_CXX_COMPILER="${CXX_COMPILER}" \
    -DOPENPROOF_ENABLE_EXPERIMENTAL_CONTRACTS=OFF

if [[ "$(uname -s)" == "Darwin" ]]; then
    python3 - "${BUILD_DIR}" <<'PY_DARWIN_COMPILE_DB'
from pathlib import Path
import json
import os
import re
import sys

build = Path(sys.argv[1])
cache = (build / 'CMakeCache.txt').read_text(encoding='utf-8')
match = re.search(r'^OPENPROOF_MACOS_SDKROOT:INTERNAL=(.+)$', cache, re.M)
if not match:
    print('release gate: canonical macOS SDK is missing from CMakeCache.txt', file=sys.stderr)
    raise SystemExit(1)
canonical = os.path.realpath(match.group(1))
commands = json.loads((build / 'compile_commands.json').read_text(encoding='utf-8'))
pattern = re.compile(r'(/[^\s"]*/SDKs/MacOSX[^/\s"]*\.sdk)(?:/[^\s"]*)?')
seen: set[str] = set()
for entry in commands:
    command = entry.get('command', '')
    for sdk in pattern.findall(command):
        seen.add(os.path.realpath(sdk))

foreign = sorted(sdk for sdk in seen if sdk != canonical)
if foreign:
    print('release gate: compile database mixes macOS SDK roots', file=sys.stderr)
    print(f'  canonical: {canonical}', file=sys.stderr)
    for sdk in foreign:
        print(f'  foreign  : {sdk}', file=sys.stderr)
    raise SystemExit(1)
PY_DARWIN_COMPILE_DB
fi

cmake --build "${BUILD_DIR}" -j"${JOBS}"
ctest --test-dir "${BUILD_DIR}" --output-on-failure

if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    (cd "${ROOT_DIR}/sdk/javascript" && npm test)
fi

if [[ -x "${ROOT_DIR}/sdk/kotlin/gradlew" ]]; then
    (cd "${ROOT_DIR}/sdk/kotlin" && ./gradlew --no-daemon build)
fi

if [[ "$(uname -s)" == "Darwin" ]] && command -v swift >/dev/null 2>&1; then
    swift test --package-path "${ROOT_DIR}/sdk/swift"
fi

printf 'OpenProof release gate passed.\n'
