#!/usr/bin/env python3
"""Build and round-trip a development schema baseline in a private PostgreSQL cluster.

Never connect to an existing database. No external DSN is accepted.
The emitted SQL is a candidate, not a replacement for the migration ledger.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PG_BIN = Path("/usr/lib/postgresql/16/bin")
NAME = re.compile(r"[0-9]{4}_[a-zA-Z0-9_]+\.sql\Z")
PORT = "55428"


def migration_files(root: Path = ROOT) -> list[Path]:
    directory = root / "migrations"
    archive = directory / "legacy"
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("Missing executable migration directory")
    if not archive.is_dir() or archive.is_symlink():
        raise ValueError("Missing immutable legacy archive")

    # The pinned source-tag inventory is independently verified in CI.
    # Match by full filename, not numeric prefix: archived tenant seeds
    # and later schema migrations may legitimately share a prefix.
    manifest = json.loads((root / "docs" / "schema-release-inventory.json")
                          .read_text(encoding="utf-8"))
    if manifest["format"] != 1 or manifest["source"] != "git-release-tags":
        raise ValueError("Unsupported release migration inventory")
    published: dict[str, set[str]] = {}
    archived: set[str] = set()
    for relative, variants in manifest["files"].items():
        path = PurePosixPath(relative)
        if (not NAME.fullmatch(path.name) or path.parts[0] != "migrations"
                or (len(path.parts) != 2
                    and not (len(path.parts) == 3 and path.parts[1] == "legacy"))):
            raise ValueError(f"Invalid published migration path: {relative}")
        published.setdefault(path.name, set()).update(variants)
        if len(path.parts) == 3:
            archived.add(path.name)
    if not published or not archived:
        raise ValueError("Incomplete release migration inventory")
    for name, digests in published.items():
        if len(digests) != 1 or any(not re.fullmatch(r"[0-9a-f]{64}", d) for d in digests):
            raise ValueError(f"Ambiguous or invalid published checksum: {name}")

    files = sorted(directory.glob("*.sql"))
    legacy = sorted(archive.glob("*.sql"))
    if not files or len({p.name[:4] for p in files}) != len(files):
        raise ValueError("Missing or ambiguous schema migration sequence")
    for path in files + legacy:
        if not NAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            raise ValueError(f"Invalid migration artifact: {path.name}")
    if {p.name for p in legacy} != archived:
        raise ValueError("Immutable legacy archive differs from published inventory")
    active_names = {p.name for p in files}
    if active_names & archived or not (published.keys() - archived) <= active_names:
        raise ValueError("Published executable migration missing or archived seed is executable")
    for path in files + legacy:
        if path.name in published:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual not in published[path.name]:
                raise ValueError(f"Published migration checksum changed: {path.name}")
    return files

def canonical_dump(raw: bytes) -> bytes:
    # PostgreSQL security-patched pg_dump adds random psql-only guards.
    # Remove only the exact matched pair, so SQL is usable by libpq later.
    # Never blindly strip other backslash commands or SQL contents.
    lines = raw.splitlines(keepends=True)
    guards = []
    for index, line in enumerate(lines):
        match = re.fullmatch(rb"\\(restrict|unrestrict) ([A-Za-z0-9]+)\r?\n", line)
        if match:
            guards.append((index, match[1], match[2]))
        elif line.startswith(b"\\"):
            raise ValueError("Unexpected psql meta-command in schema dump")
    if guards:
        if (len(guards) != 2 or guards[0][1] != b"restrict"
                or guards[1][1] != b"unrestrict" or guards[0][2] != guards[1][2]):
            raise ValueError("Unmatched pg_dump restriction guards")
        removed = {g[0] for g in guards}
        lines = [line for index, line in enumerate(lines) if index not in removed]
    return b"".join(lines)



def runtime_baseline(raw: bytes) -> bytes:
    # The current schema is created by the migrator before restoring the
    # snapshot. Keep dump connection settings transaction-local.
    lines = canonical_dump(raw).splitlines(keepends=True)
    schema = b"CREATE SCHEMA openproof;\n"
    search = b"SELECT pg_catalog.set_config('search_path', '', false);\n"
    if lines.count(schema) != 1 or lines.count(search) != 1:
        raise ValueError("Unexpected PostgreSQL baseline prologue")
    result = []
    for line in lines:
        if line == schema:
            result.append(b"CREATE SCHEMA IF NOT EXISTS openproof;\n")
        elif line == search:
            result.append(b"SELECT pg_catalog.set_config('search_path', '', true);\n")
        elif line.startswith(b"SET "):
            result.append(b"SET LOCAL " + line[4:])
        else:
            result.append(line)
    return b"".join(result)


def write_bundle(directory: Path, sql: bytes, files: dict[str, bytes]) -> None:
    # A new destination prevents mixing a candidate with an old manifest.
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "schema.sql").write_bytes(sql)
    entries = [(hashlib.sha256(sql).hexdigest(), "schema.sql")]
    entries.extend((hashlib.sha256(data).hexdigest(), name)
                   for name, data in sorted(files.items()))
    (directory / "checksums.txt").write_text(
        "".join(f"{digest} {name}\n" for digest, name in entries),
        encoding="ascii")



def historical_layouts(root: Path, active: dict[str, bytes]) -> list[tuple[str, list[str], dict[str, str]]]:
    """Resolve each supported release to exact neutral SQL and legacy ledger evidence."""
    manifest = json.loads((root / "docs/schema-release-inventory.json").read_text())
    result = []
    for tag in sorted(manifest["releases"]):
        neutral = []
        archived = {}
        for relative, variants in sorted(manifest["files"].items()):
            matches = [digest for digest, tags in variants.items() if tag in tags]
            if not matches:
                continue
            if len(matches) != 1:
                raise ValueError(f"Ambiguous historical release path: {tag}: {relative}")
            name = PurePosixPath(relative).name
            digest = matches[0]
            if name in active:
                if hashlib.sha256(active[name]).hexdigest() != digest:
                    raise ValueError(f"Historical active checksum mismatch: {tag}: {name}")
                neutral.append(name)
            else:
                archive = root / "migrations" / "legacy" / name
                if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
                    raise ValueError(f"Historical archive checksum mismatch: {tag}: {name}")
                # Only root-level customer SQL could have been executed by
                # the old migrator. Preserve the record, never execute it.
                if len(PurePosixPath(relative).parts) == 2:
                    archived[name] = digest
        if not neutral or neutral != sorted(active)[:len(neutral)]:
            raise ValueError(f"Historical schema is not an ordered prefix: {tag}")
        result.append((tag, neutral, archived))
    return result


UPGRADE_SEED = b"""
INSERT INTO openproof.organizations(id,name,state,created_at_ms)
VALUES ('upgrade-org','Upgrade fixture',0,1770000000000);
INSERT INTO openproof.identities(id,organization_id,kind,status,created_at_ms)
VALUES ('upgrade-existing','upgrade-org',0,0,1770000000000),
       ('upgrade-missing','upgrade-org',0,0,1770000000000);
INSERT INTO openproof.memberships(organization_id,identity_id,state,invited_at_ms)
VALUES ('upgrade-org','upgrade-existing',1,1770000000000);
INSERT INTO openproof.membership_roles(organization_id,identity_id,role)
VALUES ('upgrade-org','upgrade-existing','owner');
INSERT INTO openproof.identity_profiles(identity_id,display_name,email,email_verified,
    phone_number,phone_number_verified,created_at_ms,updated_at_ms)
VALUES ('upgrade-existing','Canonical name','owner@example.invalid',true,
    '+12025550123',true,1770000000000,1770000000000);
INSERT INTO openproof.external_identities(provider,external_subject,identity_id,linked_at_ms,
    display_name,preferred_username,picture_url)
VALUES ('farcaster','fixture-existing','upgrade-existing',1770000000000,
        'Provider name','provider-existing','https://example.invalid/existing.png'),
       ('farcaster','fixture-missing','upgrade-missing',1770000000000,
        'Backfilled name','provider-missing','https://example.invalid/missing.png');
INSERT INTO openproof.sessions(id,identity_id,provider,assurance,factors,phishing_resistant,
    state,token_digest,authenticated_at_ms,issued_at_ms,last_seen_at_ms,
    absolute_expires_at_ms,idle_timeout_ms)
VALUES ('upgrade-session','upgrade-existing','farcaster',2,2,false,0,decode(repeat('ab',32),'hex'),
    1770000000000,1770000000000,1770000000001,1770003600000,600000);
"""

LEDGER_BOOTSTRAP = b"""
CREATE TABLE openproof.schema_migrations (
    version text PRIMARY KEY,
    checksum bytea NOT NULL CHECK (octet_length(checksum)=32),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp());
"""

PROFILE_CHECK = """
SELECT identity_id,display_name,preferred_username,coalesce(email,''),email_verified,
       coalesce(phone_number,''),phone_number_verified,picture_url
FROM openproof.identity_profiles ORDER BY identity_id
"""
EXPECTED_PROFILES = (
    b"upgrade-existing|Canonical name|provider-existing|owner@example.invalid|t|"
    b"+12025550123|t|https://example.invalid/existing.png\n"
    b"upgrade-missing|Backfilled name|provider-missing||f||f|https://example.invalid/missing.png\n"
)


def verify_runtime_upgrades(root, active, candidate_directory, binary, work, run, client, env):
    layouts = historical_layouts(root, active)
    schema_options = ("--schema-only", "--no-owner", "--exclude-table=openproof.schema_migrations")
    expected_schema = canonical_dump(client("pg_dump", "reference", *schema_options))
    checksums = {name: hashlib.sha256(data).hexdigest() for name, data in active.items()}
    for index, (tag, neutral, archived) in enumerate(layouts):
        db = f"historical_upgrade_{index}"
        run("createdb", "-h", str(work), "-p", PORT, "-U", "postgres", "-T", "template0", db)
        def sql(data: bytes):
            client("psql", db, "-X", "-q", "-v", "ON_ERROR_STOP=1",
                   "--single-transaction", "-f", "-", input_data=data)
        def query(statement: str) -> bytes:
            return client("psql", db, "-X", "-At", "-v", "ON_ERROR_STOP=1", "-c", statement)
        old = {}
        seeded = False
        for name in neutral:
            sql(active[name])
            old[name] = checksums[name]
            if name == "0018_profile_avatar_sources.sql":
                sql(UPGRADE_SEED)
                seeded = True
        if not seeded:
            raise ValueError(f"Fixture incompatible with {tag}")
        sql(LEDGER_BOOTSTRAP)
        old.update(archived)
        # Names and hashes are drawn from validated migration artifacts.
        for name, digest in sorted(old.items()):
            if not NAME.fullmatch(name) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Invalid historical ledger entry")
            sql(f"INSERT INTO openproof.schema_migrations(version,checksum,applied_at) "
                f"VALUES ('{name}',decode('{digest}','hex'),'2000-01-01T00:00:00Z');".encode())
        ledger_query = ("SELECT version,encode(checksum,'hex'),applied_at::text "
                        "FROM openproof.schema_migrations ORDER BY version")
        before = set(query(ledger_query).splitlines())
        test_env = dict(env)
        # The subprocess receives only the private Unix socket DSN, never the
        # ambient test/staging/production connection string.
        test_env["OPENPROOF_TEST_HISTORICAL_POSTGRES"] = (
            f"host={work} port={PORT} user=postgres dbname={db}")
        test_env["OPENPROOF_TEST_HISTORICAL_DIRECTORY"] = str(candidate_directory)
        test_env["OPENPROOF_TEST_HISTORICAL_PENDING"] = str(len(active) - len(neutral))
        test_env["OPENPROOF_TEST_HISTORICAL_ACK"] = "YES_EXCLUSIVE_DISPOSABLE_DATABASE"
        if os.environ.get("LD_LIBRARY_PATH"):
            test_env["LD_LIBRARY_PATH"] = os.environ["LD_LIBRARY_PATH"]
        subprocess.run([str(binary), "--gtest_filter=PostgresMigrationBaselineTest.HistoricalReleaseUpgrade"],
                       env=test_env, check=True, timeout=120)
        after = set(query(ledger_query).splitlines())
        if not before <= after:
            raise ValueError(f"Historical ledger timestamp or checksum changed: {tag}")
        expected = checksums | archived
        actual = dict(line.decode().split("|") for line in
                      query("SELECT version,encode(checksum,'hex') FROM openproof.schema_migrations").splitlines())
        if actual != expected:
            raise ValueError(f"Unexpected upgraded ledger: {tag}")
        if query(PROFILE_CHECK) != EXPECTED_PROFILES:
            raise ValueError(f"Historical profile or contact claims changed incorrectly: {tag}")
        if query("SELECT count(*) FROM openproof.membership_roles WHERE organization_id='upgrade-org' "
                 "AND identity_id='upgrade-existing' AND role='owner'") != b"1\n":
            raise ValueError(f"Historical membership lost: {tag}")
        if query("SELECT state,encode(token_digest,'hex'),last_seen_at_ms FROM openproof.sessions "
                 "WHERE id='upgrade-session'") != b"0|" + b"ab"*32 + b"|1770000000001\n":
            raise ValueError(f"Historical session lost or modified: {tag}")
        actual_schema = canonical_dump(client("pg_dump", db, *schema_options))
        if actual_schema != expected_schema:
            raise ValueError(f"Historical upgraded schema differs from fresh schema: {tag}")
        print(f"PASS historical upgrade {tag}: {len(neutral)} neutral, "
              f"{len(archived)} archived ledger records, {len(active)-len(neutral)} pending",
              file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true",
                        help="Write the validated development candidate SQL to stdout")
    parser.add_argument("--output-dir", type=Path,
                        help="Write the validated runtime candidate and checksum manifest")
    parser.add_argument("--runtime-upgrade-tests", type=Path,
                        help="Run historical upgrade fixtures with this built C++ test executable")
    args = parser.parse_args()
    if args.runtime_upgrade_tests is not None and args.output_dir is None:
        parser.error("--runtime-upgrade-tests requires --output-dir")
    files = migration_files()
    snapshots = {path.name: path.read_bytes() for path in files}
    # Environment inherited from CI may contain a DSN or PostgreSQL options.
    # Use a minimal environment and explicit private socket for every client.
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
           "HOME": "/tmp", "TZ": "UTC"}
    prefix = []
    if os.geteuid() == 0:
        postgres = pwd.getpwnam("postgres")
        prefix = ["/usr/sbin/runuser", "-u", "postgres", "--"]
        subprocess.run([*prefix, "/usr/bin/true"], env=env, check=True)
    else:
        postgres = None

    with tempfile.TemporaryDirectory(prefix="openproof-baseline-pg.", dir="/tmp") as tmp:
        work = Path(tmp)
        if postgres is not None:
            os.chown(work, postgres.pw_uid, postgres.pw_gid)
        data = work / "data"

        def run(binary: str, *argv: str, input_data: bytes | None = None) -> bytes:
            result = subprocess.run(
                [*prefix, str(PG_BIN / binary), *argv], env=env,
                input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=120)
            if result.returncode != 0:
                # These are local disposable commands, not arbitrary DSNs.
                # Include diagnostics for fixture failures, never secrets.
                raise RuntimeError(f"{binary} failed: {result.stderr.decode(errors='replace')}")
            return result.stdout

        def client(binary: str, database: str, *argv: str,
                   input_data: bytes | None = None) -> bytes:
            return run(binary, "-h", str(work), "-p", PORT, "-U", "postgres",
                       "-d", database, *argv, input_data=input_data)

        attempted_start = False
        try:
            run("initdb", "-D", str(data), "--no-sync", "-U", "postgres",
                "-A", "trust", "--no-instructions", "--locale=C", "--encoding=UTF8")
            attempted_start = True
            run("pg_ctl", "-D", str(data), "-l", str(work / "server.log"),
                "-o", f"-c listen_addresses= -c unix_socket_directories={work} "
                      f"-c unix_socket_permissions=0700 -p {PORT}", "-w", "start")
            for db in ("reference", "candidate"):
                run("createdb", "-h", str(work), "-p", PORT, "-U", "postgres",
                    "-T", "template0", db)
            for path in files:
                client("psql", "reference", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                       "--single-transaction", "-f", "-", input_data=snapshots[path.name])
            options = ("--schema-only", "--no-owner")
            # Keep ACLs and comments. Full database dump comparison also
            # catches unexpected schema/extension objects outside openproof.
            baseline = runtime_baseline(client("pg_dump", "reference", *options,
                                               "--schema=openproof"))
            client("psql", "candidate", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                   "--single-transaction", "-f", "-", input_data=baseline)
            for dump_options in (options, ("--data-only", "--no-owner", "--inserts")):
                left = canonical_dump(client("pg_dump", "reference", *dump_options))
                right = canonical_dump(client("pg_dump", "candidate", *dump_options))
                if left != right:
                    raise ValueError(f"Baseline round-trip mismatch: {dump_options[0]}")
            checksum = hashlib.sha256(baseline).hexdigest()
            print(f"PASS: {len(files)} migrations; schema and fresh data equivalent; "
                  f"candidate SHA-256={checksum}", file=sys.stderr)
            if args.output_dir is not None:
                write_bundle(args.output_dir, baseline, snapshots)
            if args.runtime_upgrade_tests is not None:
                verify_runtime_upgrades(ROOT, snapshots, args.output_dir.resolve().parent,
                    args.runtime_upgrade_tests.resolve(), work, run, client, env)
            if args.emit:
                sys.stdout.buffer.write(baseline)
        finally:
            if attempted_start and (data / "postmaster.pid").exists():
                # If this fails, do not remove a potentially running cluster.
                try:
                    run("pg_ctl", "-D", str(data), "-m", "immediate", "-w", "stop")
                except Exception:
                    # TemporaryDirectory would otherwise remove a live cluster.
                    # Exit without its destructor only in this exceptional case.
                    print(f"FAIL: disposable cluster stop failed: {work}", file=sys.stderr)
                    os._exit(1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"FAIL: baseline round-trip: {error}", file=sys.stderr)
        sys.exit(1)
