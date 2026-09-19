#!/usr/bin/env python3
"""Dependency-free structural and endpoint-coverage gate for docs/openapi.yaml."""

from __future__ import annotations

from pathlib import Path
import re
import sys


EXPECTED: dict[str, set[str]] = {
    "/health/live": {"get"},
    "/health/ready": {"get"},
    "/metrics": {"get", "head"},
    "/account/signup": {"post"},
    "/account/email/verify": {"post"},
    "/account/email/resend": {"post"},
    "/account/email/change": {"post"},
    "/account/email/change/verify": {"post"},
    "/account/phone": {"post"},
    "/account/phone/verify": {"post"},
    "/account/password/forgot": {"post"},
    "/account/password/reset": {"post"},
    "/account/profile": {"get", "patch", "put"},
    "/account/sessions": {"get"},
    "/account/sessions/revoke": {"post"},
    "/account/connections": {"get"},
    "/account/connections/complete": {"get"},
    "/account/connections/start": {"get"},
    "/account/connections/handoff": {"get", "post"},
    "/account/connections/disconnect": {"post"},
    "/account/connections/web3/start": {"post"},
    "/account/connections/web3/complete": {"post"},
    "/account/connections/web3/handoff": {"post"},
    "/account/passkeys/options": {"post"},
    "/account/passkeys": {"get", "post"},
    "/account/passkeys/{credential_id}": {"delete"},
    "/auth/login": {"post"},
    "/auth/mfa/verify": {"post"},
    "/auth/session/rotate": {"post"},
    "/auth/logout": {"post"},
    "/auth/logout-all": {"post"},
    "/auth/recovery-codes": {"post"},
    "/auth/providers": {"get"},
    "/auth/federated/start": {"get"},
    "/auth/federated/callback": {"get", "post"},
    "/auth/passkey/options": {"post"},
    "/auth/passkey/verify": {"post"},
    "/auth/web3/start": {"post"},
    "/auth/web3/complete": {"post"},
    "/auth/web3/handoff": {"post"},
    "/auth/web3/handoff/redeem": {"post"},
    "/auth/ldap/start": {"post"},
    "/auth/ldap/complete": {"post"},
    "/.well-known/openid-configuration": {"get"},
    "/.well-known/jwks.json": {"get"},
    "/login": {"get", "post"},
    "/oauth/authorize": {"get"},
    "/oauth/consent": {"post"},
    "/oauth/consents": {"get"},
    "/oauth/consents/revoke": {"post"},
    "/oauth/par": {"post"},
    "/oauth/device_authorization": {"post"},
    "/oauth/device": {"get", "post"},
    "/oauth/token": {"post"},
    "/oauth/userinfo": {"get", "post"},
    "/oauth/revoke": {"post"},
    "/oauth/introspect": {"post"},
    "/evidence/challenge": {"post"},
    "/evidence/verify": {"post"},
    "/evidence": {"get"},
    "/trust": {"get"},
    "/admin/console": {"get"},
    "/admin/local-members": {"get", "post"},
    "/admin/local-members/roles": {"put"},
    "/admin/local-members/{action}": {"post"},
    "/admin/local-members/credentials/reset": {"post"},
    "/admin/applications": {"get", "post"},
    "/admin/applications/{action}": {"post"},
    "/admin/clients": {"get", "post"},
    "/admin/clients/{action}": {"post"},
    "/admin/clients/rotate-secret": {"post"},
    "/admin/clients/jar-key": {"get", "post", "delete"},
    "/admin/resources": {"get", "post"},
    "/admin/resources/{action}": {"post"},
    "/admin/service-identities": {"get", "post"},
    "/admin/service-identities/{action}": {"post"},
    "/scim/v2/ServiceProviderConfig": {"get"},
    "/scim/v2/ResourceTypes": {"get"},
    "/scim/v2/Schemas": {"get"},
    "/scim/v2/Users": {"get", "post"},
    "/scim/v2/Users/{id}": {"get", "put", "patch", "delete"},
    "/scim/v2/Groups": {"get", "post"},
    "/scim/v2/Groups/{id}": {"get", "put", "patch", "delete"},
}


def fail(message: str) -> None:
    print(f"openapi gate: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    contract = root / "docs" / "openapi.yaml"
    text = contract.read_text(encoding="utf-8")
    if not text.startswith("openapi: 3.1.0\n"):
        fail("contract must declare OpenAPI 3.1.0")
    if re.search(r"\{description: [^\"}\n]*,", text):
        fail("flow-style response descriptions containing commas must be quoted")

    documented: dict[str, set[str]] = {}
    operation_ids: list[str] = []
    current_path: str | None = None
    current_method: str | None = None
    for line in text.splitlines():
        path_match = re.fullmatch(r"  (/[^:]*):", line)
        if path_match:
            current_path = path_match.group(1)
            current_method = None
            documented.setdefault(current_path, set())
            continue
        method_match = re.fullmatch(r"    (get|post|put|patch|delete|head|options|trace):", line)
        if method_match and current_path is not None:
            current_method = method_match.group(1)
            documented[current_path].add(current_method)
            continue
        operation_match = re.fullmatch(r"      operationId: ([A-Za-z][A-Za-z0-9_]*)", line)
        if operation_match and current_path is not None and current_method is not None:
            operation_ids.append(operation_match.group(1))

    missing = {
        path: sorted(methods - documented.get(path, set()))
        for path, methods in EXPECTED.items()
        if methods - documented.get(path, set())
    }
    if missing:
        fail(f"implemented operations missing from contract: {missing}")
    if set(documented) != set(EXPECTED):
        unexpected = sorted(set(documented) - set(EXPECTED))
        absent = sorted(set(EXPECTED) - set(documented))
        fail(f"endpoint inventory drift (unexpected={unexpected}, absent={absent})")

    operation_count = sum(len(methods) for methods in documented.values())
    if len(operation_ids) != operation_count:
        fail(f"every operation needs an operationId ({len(operation_ids)}/{operation_count})")
    duplicates = sorted({value for value in operation_ids if operation_ids.count(value) > 1})
    if duplicates:
        fail(f"duplicate operationId values: {duplicates}")

    references = set(re.findall(r'\$ref: "(#/[^\"]+)"', text))
    component_sections: dict[str, set[str]] = {}
    section: str | None = None
    in_components = False
    for line in text.splitlines():
        if line == "components:":
            in_components = True
            continue
        if not in_components:
            continue
        section_match = re.fullmatch(r"  ([A-Za-z]+):", line)
        if section_match:
            section = section_match.group(1)
            component_sections.setdefault(section, set())
            continue
        name_match = re.fullmatch(r"    ([A-Za-z][A-Za-z0-9_]*):", line)
        if name_match and section:
            component_sections[section].add(name_match.group(1))
    unresolved = []
    for reference in references:
        parts = reference.split("/")
        if len(parts) != 4 or parts[1] != "components" \
                or parts[3] not in component_sections.get(parts[2], set()):
            unresolved.append(reference)
    if unresolved:
        fail(f"unresolved local references: {sorted(unresolved)}")

    print(f"openapi gate: {len(documented)} paths, {operation_count} operations, all covered")


if __name__ == "__main__":
    main()
