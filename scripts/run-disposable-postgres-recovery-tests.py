#!/usr/bin/env python3
"""Run native recovery-code GTests on an isolated PostgreSQL Unix socket.

Uses a freshly initialized disposable PG 16 data directory, no TCP listener,
no production schema, and a pg_temp fixture per connection. PostgreSQL is
always stopped and the temporary data directory deleted on exit.
"""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PGBIN = Path("/usr/lib/postgresql/16/bin")
PORT = "55418"


def main() -> int:
    if not (PGBIN / "initdb").is_file() or not (PGBIN / "pg_ctl").is_file():
        raise SystemExit("PostgreSQL 16 test binaries are missing")
    if not (ROOT / "cmake-build-gcc-release/tests/openproof_postgres_async_recovery_code_tests").is_file():
        raise SystemExit("Compile the native recovery-code SQL tests before running this fixture")

    postgres = pwd.getpwnam("postgres") if os.geteuid() == 0 else None
    username = postgres.pw_name if postgres is not None else pwd.getpwuid(os.geteuid()).pw_name

    with tempfile.TemporaryDirectory(prefix="openproof-recovery-pg-", dir="/tmp") as root:
        work = Path(root)
        if postgres is not None:
            os.chown(work, postgres.pw_uid, postgres.pw_gid)

        def pg(command: list[str]) -> subprocess.CompletedProcess[str]:
            if postgres is not None:
                command = ["/usr/sbin/runuser", "-u", "postgres", "--", *command]
            result = subprocess.run(command, check=False, text=True, capture_output=True)
            if result.returncode:
                raise RuntimeError(f"Disposable PostgreSQL setup failed: {result.stderr.strip()}")
            return result

        datadir = work / "data"
        log = work / "server.log"
        started = False
        try:
            pg([str(PGBIN / "initdb"), "-D", str(datadir), "--no-sync",
                "-A", "trust", "--no-instructions"])
            pg([str(PGBIN / "pg_ctl"), "-D", str(datadir),
                "-l", str(log), "-o",
                f"-c listen_addresses= -c unix_socket_directories={work} -p {PORT}",
                "-w", "start"])
            started = True

            # Only the just-created private Unix socket is used.
            env = dict(os.environ)
            env["OPENPROOF_TEST_POSTGRES"] = (
                f"host={work} port={PORT} user={username} dbname=postgres"
            )
            result = subprocess.run(
                ["ctest", "--test-dir", str(ROOT / "cmake-build-gcc-release"),
                 "-R", r"^NativePgRecovery\.", "--output-on-failure", "-V", "-j", "1"],
                env=env, text=True, check=False,
            )
            return result.returncode
        finally:
            if started:
                pg([str(PGBIN / "pg_ctl"), "-D", str(datadir),
                    "-m", "immediate", "-w", "stop"])


if __name__ == "__main__":
    sys.exit(main())
