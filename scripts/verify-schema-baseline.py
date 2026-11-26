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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true",
                        help="Write the validated development candidate SQL to stdout")
    args = parser.parse_args()
    files = migration_files()
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
                       "--single-transaction", "-f", "-", input_data=path.read_bytes())
            options = ("--schema-only", "--no-owner")
            # Keep ACLs and comments. Full database dump comparison also
            # catches unexpected schema/extension objects outside openproof.
            baseline = canonical_dump(client("pg_dump", "reference", *options,
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
