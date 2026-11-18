#!/usr/bin/env python3
"""Execute the coroutine session repository against disposable Docker PostgreSQL.

Never bind a public interface, attach persistent volumes, touch an existing
container or reuse a system PostgreSQL cluster. Docker is only used because
pg_virtualenv cannot switch Unix UIDs on this remote operations host.
"""
from __future__ import annotations

import argparse
import pathlib
import re
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
                          capture_output=True, check=True, timeout=45)


def isolated_test_environment() -> dict[str, str]:
    # Do not pass a developer's database/libpq/GTest/loader overrides to
    # native integration binaries, even though the DSN is explicitly pinned.
    forbidden = ("PG", "GTEST_", "LD_", "DYLD_")
    forbidden_names = (
        "OPENPROOF_TEST_POSTGRES", "OPENPROOF_TEST_POSTGRES_DOMAIN",
        "OPENPROOF_TEST_POSTGRES_DOMAIN_ACK",
        "OPENPROOF_TEST_POSTGRES_DOMAIN_MODE",
        "ASAN_OPTIONS", "LSAN_OPTIONS", "TSAN_OPTIONS", "UBSAN_OPTIONS",
        "MSAN_OPTIONS", "LLVM_PROFILE_FILE", "GCOV_PREFIX",
        "GCOV_PREFIX_STRIP", "GCONV_PATH",
    )
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(forbidden) and k not in forbidden_names}
    env["PGPASSFILE"] = os.devnull
    env["PGSERVICEFILE"] = os.devnull
    return env


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=pathlib.Path,
                        default=ROOT / "cmake-build-gcc-release")
    parser.add_argument("--native-only", action="store_true",
                        help="Run native libpq and auth-transaction SQL tests, "
                             "without requiring the domain repository target")
    args = parser.parse_args()
    build = args.build_dir.resolve()
    cache = build / "CMakeCache.txt"
    if not cache.is_file() or (
        f"CMAKE_HOME_DIRECTORY:INTERNAL={ROOT}"
        not in cache.read_text(encoding="utf-8")
    ):
        raise RuntimeError("CMake build is not from this OpenProof checkout")
    native_test = build / "tests/openproof_postgres_async_tests"
    native_auth_test = build / "tests/openproof_postgres_async_auth_transaction_tests"
    domain_test = build / "tests/openproof_postgres_domain_tests"
    if not native_test.is_file() or (args.native_only and not native_auth_test.is_file()):
        raise RuntimeError("Compile both native PostgreSQL C++ test targets first")
    if not args.native_only and not domain_test.is_file():
        raise RuntimeError("Compile the PostgreSQL domain repository test target first")
    existing = subprocess.run(["docker", "container", "inspect", NAME],
                              capture_output=True, text=True, check=False,
                              timeout=10)
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
                text=True, check=False, timeout=5)
            if probe.returncode == 0:
                # The container's local Unix socket may be ready before
                # Docker has published its host TCP port. Verify the exact
                # host endpoint too, before invoking any destructive test.
                externally_ready = subprocess.run(
                    ["pg_isready", "-h", "127.0.0.1", "-p", str(PORT),
                     "-U", "openproof_ci", "-d", "openproof_coroutine_ci"],
                    capture_output=True, text=True, check=False, timeout=5)
                if externally_ready.returncode == 0:
                    break
            time.sleep(.4)
        else:
            raise RuntimeError("Disposable PostgreSQL not reachable via host TCP.")

        env = isolated_test_environment()
        env["OPENPROOF_TEST_POSTGRES"] = URL
        native = subprocess.run(
            [str(native_test),
             "--gtest_filter=PostgresNativeCoroutineTest.*:"
             "PostgresAsyncPoolTest.*:PostgresAsyncSessionSqlTest.*"],
            cwd=ROOT, env=env, text=True, capture_output=True,
            check=False, timeout=240)
        print(native.stdout, end="", flush=True)
        if native.stderr:
            print(native.stderr, file=sys.stderr, end="", flush=True)
        completed = re.search(
            r"^\[\s+PASSED\s+\]\s+(\d+) tests?\.",
            native.stdout, re.MULTILINE,
        )
        # A short, accidentally filtered run is NOT SQL acceptance.
        if (native.returncode != 0 or "[  SKIPPED ]" in native.stdout
                or completed is None or int(completed.group(1)) < 32):
            raise RuntimeError(
                "Native PostgreSQL transport acceptance requires >=32 passed, "
                "zero skipped tests")
        if args.native_only:
            auth = subprocess.run(
                [str(native_auth_test),
                 "--gtest_filter=AsyncAuthenticationTransactionSqlTest.*"],
                cwd=ROOT, env=env, text=True, capture_output=True,
                check=False, timeout=240,
            )
            print(auth.stdout, end="", flush=True)
            if auth.stderr:
                print(auth.stderr, file=sys.stderr, end="", flush=True)
            if (auth.returncode != 0 or "[  SKIPPED ]" in auth.stdout
                    or "[  PASSED  ] 4 tests." not in auth.stdout):
                raise RuntimeError(
                    "Native PostgreSQL authentication transaction tests DID NOT PASS"
                )
            print("PASS: native libpq, SQL sessions and authentication transactions")
            return

        env["OPENPROOF_TEST_POSTGRES_DOMAIN"] = URL
        env["OPENPROOF_TEST_POSTGRES_DOMAIN_ACK"] = (
            "YES_EXCLUSIVE_DISPOSABLE_DATABASE")
        env["OPENPROOF_TEST_POSTGRES_DOMAIN_MODE"] = "isolated-docker-55432"
        test = subprocess.run(
            [str(domain_test), "--gtest_filter="
             "PostgresCoroutineRealDatabaseTest.DomainRepositoryFullLifecycleAndIsolation"],
            cwd=ROOT, env=env, text=True, capture_output=True,
            check=False, timeout=240)
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
                capture_output=True, text=True, check=False, timeout=30)
            print("Disposable database container removed: " +
                  ("yes" if cleanup.returncode == 0 else "FAILED"), flush=True)
            if cleanup.returncode != 0:
                raise RuntimeError("Could not remove disposable test container.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print(f"Isolated Docker PostgreSQL test failed: {exc}",
              file=sys.stderr, flush=True)
        sys.exit(1)
