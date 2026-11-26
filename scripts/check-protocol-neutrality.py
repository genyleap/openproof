#!/usr/bin/env python3
"""Fail CI if OpenProof runtime depends on a particular customer's branding or clients."""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CUSTOMER = re.compile(r"genyleap|genycaster|genyconnect|tegra(?:-cms)?", re.IGNORECASE)
HISTORICAL = {
    "0020_genycaster_native_client.sql": "b94bd75abaf5b1afc0ea740804d04a5c7518358321df5734b3e6084d4af97fa1",
    "0021_genycaster_production_environment.sql": "7a9eef141267ace4d953cb3368ba4e8ad34ab7e31c32aa8652198fa4ee05b57a",
    "0022_tegra_cms_browser_client.sql": "529b0db2f75ae80e98c421e252e4462d5a0d6b3265d7798e0823eb9d37379015",
}

def audit() -> list[str]:
    findings: list[str] = []
    # Runtime and schema migrations are not allowed to embed publisher-specific
    # tenants, clients, URLs, UI strings, or privileges.
    for prefix in ("src", "apps"):
        for p in (ROOT / prefix).rglob("*"):
            if p.is_file() and p.suffix in {".cpp", ".cppm", ".h", ".hpp"}:
                for number, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                    if CUSTOMER.search(line):
                        findings.append(f"{p.relative_to(ROOT)}:{number}: vendor reference in runtime")
    migration_root = ROOT / "migrations"
    for p in migration_root.glob("*.sql"):
        if CUSTOMER.search(p.read_text(encoding="utf-8")):
            findings.append(f"{p.relative_to(ROOT)}: customer-specific SQL in executable migration")
    archive = migration_root / "legacy"
    for filename, checksum in HISTORICAL.items():
        file = archive / filename
        if not file.is_file():
            findings.append(f"Missing immutable archived migration: {filename}")
        elif hashlib.sha256(file.read_bytes()).hexdigest() != checksum:
            findings.append(f"Archived migration modified: {filename}")
        if (migration_root / filename).exists():
            findings.append(f"Customer seed still executable as root migration: {filename}")
    for file in archive.glob("*.sql"):
        if file.name not in HISTORICAL:
            findings.append(f"Unreviewed archived migration: {file.name}")
    engine = (ROOT / "src/storage/postgres/postgres.cpp").read_text(encoding="utf-8")
    # Scope the source contract to the actual migration implementation.
    # Runtime PostgreSQL regression tests independently exercise the invariant.
    start = engine.find("Migrator::applyDirectory(")
    end = engine.find("PostgresCredentialRekeyer::", start)
    migrator = engine[start:end] if start >= 0 and end > start else ""
    package = (ROOT / "src/storage/postgres/migration_package.cpp").read_text(encoding="utf-8")
    native = (ROOT / "src/storage/postgres/coroutine_startup.cpp").read_text(encoding="utf-8")
    contracts = (
        (package, ('existing->checksum != hex', 'load(directory / "legacy", true)', 'load(directory, false)')),
        (migrator, ('migration::loadPackage(directory)', 'existing->checksum != field(ledger.get(), row, 1)',
                    'if (migration.archived || migration.recorded) continue;', 'exec(connection, migration.sql)')),
        (native, ('migration::loadPackage(directory)', 'existing->checksum!=*row[1]',
                  'if (migration.archived || migration.recorded) continue;', 'executeMigrationScript(migration.sql')),
    )
    for implementation, required in contracts:
        positions = [implementation.find(fragment) for fragment in required]
        if -1 in positions or positions != sorted(positions):
            findings.append("Migrator lacks checksum-preserving historical SQL exclusion")
    if "SELECT 1 FROM openproof.organizations WHERE id='genyleap'" in engine:
        findings.append("Vendor tenant lookup still exists in shared migrator")
    return findings

if __name__ == "__main__":
    errors = audit()
    if errors:
        print("FAIL: protocol neutrality audit")
        for item in errors:
            print("  " + item)
        sys.exit(1)
    print("PASS: runtime and schema migrations are tenant-neutral; 3 legacy SQL checksums preserved")
