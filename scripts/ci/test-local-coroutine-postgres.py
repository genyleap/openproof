#!/usr/bin/env python3
"""One-off, disposable PostgreSQL 16 test runner for the local VPS.

Uses pg_virtualenv -t on localhost:55432, *never* the system PostgreSQL cluster.
pg_virtualenv destroys the temporary cluster on exit, including test data.
Requires only the previously built openproof_postgres_domain_tests target.
"""
from __future__ import annotations

import os
import pathlib
import socket
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PORT = 55432
URL = (
    "postgresql://openproof_ci:ci_disposable_only"
    "@127.0.0.1:55432/openproof_coroutine_ci"
)
ACK = "YES_EXCLUSIVE_DISPOSABLE_DATABASE"


def ensure_port_unbound() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        if probe.connect_ex(("127.0.0.1", PORT)) == 0:
            raise RuntimeError("port 55432 is occupied; refusing to touch it")


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, check=True, cwd=ROOT, env=env)


def main() -> None:
    if sys.argv[1:] == ["--inside"]:
        if os.environ.get("PGPORT") != str(PORT):
            raise RuntimeError("temporary PostgreSQL port verification failed")
        config = os.environ.get("PG_CLUSTER_CONF_ROOT", "")
        if not config.startswith("/tmp/pg_virtualenv."):
            raise RuntimeError("refusing to use non-disposable PostgreSQL")
        # Ensure the PostgreSQL server's actual data directory is temporary.
        data_dir = subprocess.check_output(
            ["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
             "-d", "postgres", "-c", "SHOW data_directory"],
            text=True,
        ).strip()
        if not data_dir.startswith("/tmp/pg_virtualenv."):
            raise RuntimeError("PostgreSQL server is NOT the temp test cluster")

        run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "postgres",
             "-c", "CREATE ROLE openproof_ci LOGIN PASSWORD 'ci_disposable_only'"])
        run(["createdb", "-O", "openproof_ci", "openproof_coroutine_ci"])

        env = os.environ.copy()
        env["OPENPROOF_TEST_POSTGRES_DOMAIN"] = URL
        env["OPENPROOF_TEST_POSTGRES_DOMAIN_ACK"] = ACK
        run(["ctest", "--test-dir", "cmake-build-gcc-release",
             "--output-on-failure", "--parallel", "1",
             "-R", "^NativePostgresDomain\\.PostgresCoroutineRealDatabaseTest\\."],
            env=env)
        return

    if sys.argv[1:]:
        raise RuntimeError("unknown command-line argument")
    if os.geteuid() != 0:
        raise RuntimeError("pg_virtualenv needs configured PostgreSQL permissions")
    ensure_port_unbound()
    env = os.environ.copy()
    env["PGPORT"] = str(PORT)
    # -t guarantees a temporary data/configuration root even as root,
    # avoiding the system-managed cluster and its production data.
    run(["/usr/bin/pg_virtualenv", "-t", sys.executable,
         str(pathlib.Path(__file__).resolve()), "--inside"], env=env)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
        print(f"Isolated PostgreSQL test did not pass: {error}", file=sys.stderr)
        sys.exit(1)
