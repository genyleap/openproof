#!/usr/bin/env python3
"""Execute the coroutine session repository against disposable Docker PostgreSQL.

Never bind a public interface, attach persistent volumes, touch an existing
container or reuse a system PostgreSQL cluster. Docker is only used because
pg_virtualenv cannot switch Unix UIDs on this remote operations host.
"""
from __future__ import annotations

import pathlib
import socket
import subprocess
import sys
import time
import os

ROOT = pathlib.Path(__file__).resolve().parents[2]
NAME = "openproof-coroutine-disposable-20261027"
PORT = 55432
URL = ("postgresql://openproof_ci:ci_disposable_only@"
       "127.0.0.1:55432/openproof_coroutine_ci")
CLUSTER = "openproof_disposable_coroutine_55432"
TEST = ROOT / "cmake-build-gcc-release/tests/openproof_postgres_domain_tests"
NATIVE_TEST = ROOT / "cmake-build-gcc-release/tests/openproof_postgres_async_tests"


def checked(argv: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=ROOT, env=env, text=True,
                          capture_output=True, check=True)


def main() -> None:
    if not TEST.is_file() or not NATIVE_TEST.is_file():
        raise RuntimeError("Compile both PostgreSQL coroutine test binaries first.")
    existing = subprocess.run(["docker", "container", "inspect", NAME],
                              capture_output=True, text=True, check=False)
    if existing.returncode == 0:
        raise RuntimeError("Test container name already exists; refusing to replace it.")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(.3)
        if probe.connect_ex(("127.0.0.1", PORT)) == 0:
            raise RuntimeError("Test port 55432 is already in use.")

    started = False
    try:
        launch = checked([
            "docker", "run", "--detach", "--rm", "--pull=never",
            "--name", NAME, "--network", "bridge",
            "--publish", "127.0.0.1:55432:5432",
            "--memory", "640m", "--cpus", "0.5", "--pids-limit", "128",
            "--tmpfs", "/var/lib/postgresql/data:rw,size=256m",
            "--env", "POSTGRES_USER=openproof_ci",
            "--env", "POSTGRES_PASSWORD=ci_disposable_only",
            "--env", "POSTGRES_DB=openproof_coroutine_ci",
            "postgres:16", "-c", "cluster_name=" + CLUSTER,
        ])
        started = True
        cid = launch.stdout.strip()
        if not cid:
            raise RuntimeError("Docker did not return a test container ID.")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            probe = subprocess.run(
                ["docker", "exec", NAME, "pg_isready", "-U", "openproof_ci",
                 "-d", "openproof_coroutine_ci"], capture_output=True,
                text=True, check=False)
            if probe.returncode == 0:
                # The container's local Unix socket may be ready before
                # Docker has published its host TCP port. Verify the exact
                # host endpoint too, before invoking any destructive test.
                externally_ready = subprocess.run(
                    ["pg_isready", "-h", "127.0.0.1", "-p", str(PORT),
                     "-U", "openproof_ci", "-d", "openproof_coroutine_ci"],
                    capture_output=True, text=True, check=False)
                if externally_ready.returncode == 0:
                    break
            time.sleep(.4)
        else:
            raise RuntimeError("Disposable PostgreSQL not reachable via host TCP.")

        env = os.environ.copy()
        env["OPENPROOF_TEST_POSTGRES"] = URL
        native = subprocess.run(
            [str(NATIVE_TEST),
             "--gtest_filter=PostgresNativeCoroutineTest.*:"
             "PostgresAsyncPoolTest.*:PostgresAsyncSessionSqlTest.*"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False)
        print(native.stdout, end="", flush=True)
        if native.stderr:
            print(native.stderr, file=sys.stderr, end="", flush=True)
        if (native.returncode != 0 or "[  SKIPPED ]" in native.stdout
                or "[  PASSED  ]" not in native.stdout):
            raise RuntimeError("Native PostgreSQL transport regressions DID NOT PASS")
        env["OPENPROOF_TEST_POSTGRES_DOMAIN"] = URL
        env["OPENPROOF_TEST_POSTGRES_DOMAIN_ACK"] = (
            "YES_EXCLUSIVE_DISPOSABLE_DATABASE")
        env["OPENPROOF_TEST_POSTGRES_DOMAIN_MODE"] = "isolated-docker-55432"
        test = subprocess.run(
            [str(TEST), "--gtest_filter="
             "PostgresCoroutineRealDatabaseTest.DomainRepositoryFullLifecycleAndIsolation"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False)
        print(test.stdout, end="", flush=True)
        if test.stderr:
            print(test.stderr, file=sys.stderr, end="", flush=True)
        if (test.returncode != 0 or "[  PASSED  ] 1 test." not in test.stdout
                or "[  SKIPPED ]" in test.stdout):
            raise RuntimeError("Full real PostgreSQL repository test DID NOT PASS")
        print("PASS: real PostgreSQL coroutine repository + legacy interoperability")
    finally:
        if started:
            cleanup = subprocess.run(
                ["docker", "rm", "--force", NAME],
                capture_output=True, text=True, check=False)
            print("Disposable database container removed: " +
                  ("yes" if cleanup.returncode == 0 else "FAILED"), flush=True)
            if cleanup.returncode != 0:
                raise RuntimeError("Could not remove disposable test container.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Isolated Docker PostgreSQL test failed: {exc}",
              file=sys.stderr, flush=True)
        sys.exit(1)
