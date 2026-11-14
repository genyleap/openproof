#!/usr/bin/env python3
"""Run native recovery-code GTests on an isolated PostgreSQL Unix socket.

Uses a freshly initialized disposable PG 16 data directory, no TCP listener,
no production schema, and a pg_temp fixture per connection. PostgreSQL is
always stopped and the temporary data directory deleted on exit.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PGBIN = Path("/usr/lib/postgresql/16/bin")
PORT = "55418"


def isolated_environment() -> dict[str, str]:
    """Prevent inherited libpq, GTest and dynamic-loader settings from escaping isolation."""
    blocked = ("PG", "GTEST_", "LD_", "DYLD_", "PYTHON")
    return {key: value for key, value in os.environ.items()
            if not key.startswith(blocked)
            and key not in ("OPENPROOF_TEST_POSTGRES", "GCONV_PATH", "BASH_ENV", "ENV")}


def main() -> int:
    if not (PGBIN / "initdb").is_file() or not (PGBIN / "pg_ctl").is_file():
        raise SystemExit("PostgreSQL 16 test binaries are missing")
    if not (ROOT / "cmake-build-gcc-release/tests/openproof_postgres_async_recovery_code_tests").is_file():
        raise SystemExit("Compile the native recovery-code SQL tests before running this fixture")

    # This is an operating-system account name, never a database password.
    # A non-root caller's OS identity is resolved directly by libpq.
    must_drop_privileges = os.geteuid() == 0

    with tempfile.TemporaryDirectory(prefix="openproof-recovery-pg-", dir="/tmp") as root:
        work = Path(root)
        # The developer worktree/build may be mode 0700. Never make either
        # world-readable just to run tests as a restricted OS account.
        # Copy only the compiled test binary into this private directory.
        executable = work / "recovery-code-sql-tests"
        shutil.copyfile(
            ROOT / "cmake-build-gcc-release/tests/"
                   "openproof_postgres_async_recovery_code_tests",
            executable)
        executable.chmod(0o700)
        if must_drop_privileges:
            shutil.chown(executable, user="postgres", group="postgres")
            shutil.chown(work, user="postgres", group="postgres")

        def fixture_environment() -> dict[str, str]:
            env = isolated_environment()
            # libpq also reads ~/.pgpass and system/user service files even
            # when inherited PG* variables have been removed. Never consult
            # credentials or service definitions from the invoking account.
            env["HOME"] = str(work)
            # Keep temporary files created by libpq, PostgreSQL utilities or
            # the native test executable inside the disposable fixture.
            env["TMPDIR"] = str(work)
            env["PGPASSFILE"] = os.devnull
            env["PGSERVICEFILE"] = str(work / "no-pg-service.conf")
            env["PGSYSCONFDIR"] = str(work)
            return env

        def pg(command: list[str]) -> subprocess.CompletedProcess[str]:
            if must_drop_privileges:
                # Root-owned PostgreSQL clusters are forbidden. Abort on any
                # failed privilege drop rather than retrying as root.
                command = ["/usr/sbin/runuser", "-u", "postgres", "--", *command]
            try:
                # Bound cluster initialization, startup and teardown as well
                # as the native tests; pg_ctl -w can otherwise hang forever.
                result = subprocess.run(command, check=False, text=True,
                                        capture_output=True, timeout=30,
                                        env=fixture_environment())
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Disposable PostgreSQL setup/teardown exceeded 30 seconds") from exc
            if result.returncode:
                raise RuntimeError(f"Disposable PostgreSQL setup failed: {result.stderr.strip()}")
            return result

        datadir = work / "data"
        log = work / "server.log"
        started = False
        start_attempted = False
        test_exit_code = None
        try:
            pg([str(PGBIN / "initdb"), "-D", str(datadir), "--no-sync",
                "--auth-local=peer", "--auth-host=reject",
                "--no-instructions"])
            # pg_ctl can time out after launching postgres but before it
            # acknowledges readiness. Attempt cleanup even on that path.
            start_attempted = True
            pg([str(PGBIN / "pg_ctl"), "-D", str(datadir),
                "-l", str(log), "-o",
                f"-c listen_addresses= -c unix_socket_directories={work} -p {PORT}",
                "-w", "start"])
            started = True

            # Only the just-created private Unix socket is used.
            env = fixture_environment()
            # Do not inherit any production PGHOST/PGSERVICE/PGPASSWORD.
            # The URI contains NO credential and points only to this
            # freshly initialized, private Unix-domain socket.
            uri = f"host={work} port={PORT} dbname=postgres"
            if must_drop_privileges:
                uri += " user=postgres"
            env["OPENPROOF_TEST_POSTGRES"] = uri
            # libpq peer authentication requires that the test process
            # itself runs under the matching OS account. Running the GTest
            # binary directly avoids needing writable CTest state under the
            # root-owned build directory after dropping privileges.
            command = [str(executable)]
            if must_drop_privileges:
                command = ["/usr/sbin/runuser", "-u", "postgres", "--", *command]
            # A wedged integration test must not leave the disposable server
            # running indefinitely. The finally block still stops the cluster.
            try:
                result = subprocess.run(command, env=env, text=True,
                                        check=False, timeout=120)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("Disposable PostgreSQL tests exceeded 120 seconds") from exc
            test_exit_code = result.returncode
            return test_exit_code
        finally:
            primary_error = sys.exc_info()[1]
            if start_attempted:
                try:
                    pg([str(PGBIN / "pg_ctl"), "-D", str(datadir),
                        "-m", "immediate", "-w", "stop"])
                except RuntimeError as cleanup_error:
                    # Preserve the primary failure if native tests failed too.
                    # The cleanup failure remains visible as an exception note.
                    if primary_error is not None:
                        primary_error.add_note(f"Disposable PostgreSQL cleanup failed: {cleanup_error}")
                    elif test_exit_code is not None and test_exit_code != 0:
                        print(f"Disposable PostgreSQL cleanup failed: {cleanup_error}", file=sys.stderr)
                    elif started:
                        raise
                    # A failed startup may have left no running server.


if __name__ == "__main__":
    sys.exit(main())
