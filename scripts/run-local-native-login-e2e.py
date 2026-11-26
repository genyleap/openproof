#!/usr/bin/env python3
"""Run the existing identity HTTP E2E against a disposable local Docker DB.

No production DSN, host volume, or inherited OPENPROOF_* setting is accepted.
The database is exposed only on a Docker-assigned loopback port.
"""
import argparse
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
DATABASE = "openproof_local_e2e_pilot"


def run(*args, env=None, timeout=30):
    return subprocess.run(args, cwd=ROOT, env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout).stdout.strip()


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opp", type=Path,
                        default=ROOT / "cmake-build-gcc-release/apps/opp/opp")
    parser.add_argument("--probe-only", action="store_true",
                        help="Check isolated DB creation and cleanup, without claiming HTTP acceptance.")
    args = parser.parse_args()
    binary = args.opp.resolve()
    if not args.probe_only and not (binary.is_file() and os.access(binary, os.X_OK)):
        parser.error("Build the opp executable first, or pass --opp.")
    for command in ("docker", "node", "psql", "openssl"):
        if shutil.which(command) is None:
            parser.error(f"{command} is required")
    # Require a locally installed image; never pull implicitly on a server.
    run("docker", "image", "inspect", "postgres:16", "--format", "{{.Id}}")
    name = "openproof-local-e2e-" + uuid.uuid4().hex
    password = secrets.token_hex(24)
    docker_env = {**os.environ, "POSTGRES_PASSWORD": password}
    started = False
    try:
        # The generated name is exclusive to this invocation; no host mounts.
        run("docker", "run", "--pull", "never", "--rm", "-d",
            "--name", name, "--label", "openproof.disposable=true",
            "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64",
            "--security-opt", "no-new-privileges:true",
            "-e", "POSTGRES_USER=openproof_test", "-e", "POSTGRES_PASSWORD",
            "-e", f"POSTGRES_DB={DATABASE}", "-p", "127.0.0.1::5432",
            "postgres:16", "-c", "shared_buffers=32MB",
            "-c", "max_connections=40", env=docker_env, timeout=60)
        started = True
        for _ in range(60):
            try:
                # TCP (not the transient initdb-only Unix socket).
                run("docker", "exec", name, "pg_isready", "-h", "127.0.0.1",
                    "-U", "openproof_test", "-d", DATABASE, timeout=3)
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                time.sleep(1)
        else:
            raise RuntimeError("Disposable PostgreSQL did not become ready")
        port = run("docker", "port", name, "5432/tcp")
        match = re.fullmatch(r"127\.0\.0\.1:(\d{1,5})", port)
        if match is None or not 1 <= int(match[1]) <= 65535:
            raise RuntimeError("Disposable PostgreSQL is not exclusively loopback-bound")
        count = run("docker", "exec", name, "psql", "-XAt", "-v", "ON_ERROR_STOP=1",
                    "-U", "openproof_test", "-d", DATABASE, "-c",
                    "select count(*) from information_schema.tables "
                    "where table_schema not in ('pg_catalog','information_schema')")
        if count != "0":
            raise RuntimeError("Disposable database is not empty")
        print("PASS: PostgreSQL 16 disposable loopback database is ready and empty", flush=True)
        if args.probe_only:
            return 0

        # Do not inherit any production configuration, credentials or feature
        # switches. Preserve only the host runtime/toolchain search paths.
        env = {key: os.environ[key] for key in
               ("PATH", "HOME", "LANG", "LC_ALL", "LD_LIBRARY_PATH", "TMPDIR")
               if key in os.environ}
        env.update({
            "OPENPROOF_E2E_OPP": str(binary),
            "OPENPROOF_E2E_POSTGRES":
                f"postgresql://openproof_test:{password}@127.0.0.1:{match[1]}/{DATABASE}",
            "OPENPROOF_E2E_DATABASE_ACK": "YES_I_UNDERSTAND_THIS_DATABASE_MUST_BE_DISPOSABLE",
            "OPENPROOF_EXPERIMENTAL_NATIVE_LOCAL_LOGIN": "1",
            "OPENPROOF_EXPERIMENTAL_NATIVE_AUTH_SESSIONS": "1",
            "OPENPROOF_EXPERIMENTAL_NATIVE_RECOVERY_CODES": "1",
            "OPENPROOF_E2E_LOAD_REQUESTS": "6",
            "OPENPROOF_E2E_LOAD_CONCURRENCY": "1",
        })
        # Existing E2E handles service termination in finally. This is a
        # correctness workload, not a comparative performance benchmark.
        return subprocess.run(["node", "scripts/e2e-identity-platform.mjs"],
                              cwd=ROOT, env=env, check=False, timeout=1200).returncode
    finally:
        # Also attempt removal if docker run timed out after creating it.
        # The UUID name belongs only to this invocation.
        cleanup = subprocess.run(["docker", "rm", "-f", "-v", name],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 timeout=30, check=False)
        if started and cleanup.returncode != 0:
            raise RuntimeError("Disposable PostgreSQL cleanup could not be confirmed")
        if started:
            print("PASS: disposable PostgreSQL removed", flush=True)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    try:
        raise SystemExit(main())
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError):
        # Never print subprocess arguments or captured output containing DSNs.
        raise SystemExit("Disposable Docker E2E failed; no acceptance claimed") from None
    except KeyboardInterrupt:
        raise SystemExit(130) from None
