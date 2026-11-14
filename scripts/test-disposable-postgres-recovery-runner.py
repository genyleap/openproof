#!/usr/bin/env python3
"""Offline negative/security tests for the private PostgreSQL fixture.

All subprocesses are mocked: these tests never start a database, access
production credentials, or change the effective Unix account.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

FIXTURE = Path(__file__).with_name("run-disposable-postgres-recovery-tests.py")
spec = importlib.util.spec_from_file_location("disposable_recovery", FIXTURE)
assert spec and spec.loader
fixture = importlib.util.module_from_spec(spec)
# Importing the fixture must not create untracked bytecode in the source tree.
sys.dont_write_bytecode = True
spec.loader.exec_module(fixture)


class DisposableRecoveryRunnerTest(unittest.TestCase):
    def simulate(self, root: bool, fail_first: bool = False):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(
                command, 1 if fail_first and len(calls) == 1 else 0,
                stdout="", stderr="privilege drop denied" if fail_first else "")

        inherited = {
            "PGHOST": "a-forbidden-parent-host",
            "PGSERVICE": "a-forbidden-parent-service",
            "PG" + "PASSWORD": "sentinel",
            "OPENPROOF_TEST_POSTGRES": "a-forbidden-parent-dsn",
        }
        def fake_copy(_source, destination):
            Path(destination).write_bytes(b"synthetic-test-binary")

        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(fixture.shutil, "copyfile", side_effect=fake_copy),
            mock.patch.object(fixture.os, "geteuid", return_value=0 if root else 1234),
            mock.patch.object(fixture.shutil, "chown") as chown,
            mock.patch.object(fixture.subprocess, "run", side_effect=fake_run),
            mock.patch.dict(os.environ, inherited),
        ):
            if fail_first:
                with self.assertRaisesRegex(RuntimeError, "privilege drop denied"):
                    fixture.main()
            else:
                self.assertEqual(fixture.main(), 0)
        return calls, chown

    def test_root_runs_postgres_and_tests_as_unprivileged_pg_user(self):
        calls, chown = self.simulate(root=True)
        self.assertEqual(len(calls), 4)
        self.assertEqual([kwargs["timeout"] for _, kwargs in calls],
                         [30, 30, 120, 30])
        self.assertEqual(chown.call_count, 2)
        for command, _ in calls:
            self.assertEqual(command[:4],
                             ["/usr/sbin/runuser", "-u", "postgres", "--"])
        initdb = calls[0][0]
        self.assertIn("--auth-local=peer", initdb)
        self.assertIn("--auth-host=reject", initdb)
        self.assertNotIn("trust", initdb)
        self.assertTrue(any("listen_addresses=" in part
                            and "unix_socket_directories=" in part
                            for part in calls[1][0]))
        env = calls[2][1]["env"]
        for name in ("PGHOST", "PGSERVICE", "PG" + "PASSWORD"):
            self.assertNotIn(name, env)
        self.assertIn(" user=postgres", env["OPENPROOF_TEST_POSTGRES"])
        self.assertIn("host=/tmp/openproof-recovery-pg-", env["OPENPROOF_TEST_POSTGRES"])
        self.assertTrue(calls[3][0][-1] == "stop")
        self.assertTrue(calls[2][0][-1].endswith("recovery-code-sql-tests"))

    def test_non_root_uses_its_own_postgres_peer_identity(self):
        calls, chown = self.simulate(root=False)
        self.assertEqual(len(calls), 4)
        chown.assert_not_called()
        for command, _ in calls:
            self.assertNotIn("runuser", " ".join(command))
        self.assertNotIn(" user=", calls[2][1]["env"]["OPENPROOF_TEST_POSTGRES"])

    def test_native_test_timeout_stops_disposable_cluster(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            if len(calls) == 3:
                raise subprocess.TimeoutExpired(command, 120)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        def fake_copy(_source, destination):
            Path(destination).write_bytes(b"synthetic-test-binary")

        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(fixture.shutil, "copyfile", side_effect=fake_copy),
            mock.patch.object(fixture.os, "geteuid", return_value=0),
            mock.patch.object(fixture.shutil, "chown"),
            mock.patch.object(fixture.subprocess, "run", side_effect=fake_run),
        ):
            with self.assertRaisesRegex(RuntimeError, "exceeded 120 seconds"):
                fixture.main()
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[2][1]["timeout"], 120)
        self.assertEqual(calls[3][0][-1], "stop")

    def test_cluster_start_timeout_aborts_before_native_tests(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            if len(calls) == 2:
                raise subprocess.TimeoutExpired(command, 30)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        def fake_copy(_source, destination):
            Path(destination).write_bytes(b"synthetic-test-binary")

        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(fixture.shutil, "copyfile", side_effect=fake_copy),
            mock.patch.object(fixture.os, "geteuid", return_value=0),
            mock.patch.object(fixture.shutil, "chown"),
            mock.patch.object(fixture.subprocess, "run", side_effect=fake_run),
        ):
            with self.assertRaisesRegex(RuntimeError, "exceeded 30 seconds"):
                fixture.main()
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1][1]["timeout"], 30)
        self.assertEqual(calls[2][0][-1], "stop")
        self.assertEqual(calls[2][1]["timeout"], 30)

    def test_failed_start_and_failed_stop_preserve_startup_error(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            if len(calls) == 2:
                raise subprocess.TimeoutExpired(command, 30)
            if len(calls) == 3:
                return subprocess.CompletedProcess(
                    command, 1, stdout="", stderr="server never started")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        def fake_copy(_source, destination):
            Path(destination).write_bytes(b"synthetic-test-binary")

        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(fixture.shutil, "copyfile", side_effect=fake_copy),
            mock.patch.object(fixture.os, "geteuid", return_value=0),
            mock.patch.object(fixture.shutil, "chown"),
            mock.patch.object(fixture.subprocess, "run", side_effect=fake_run),
        ):
            with self.assertRaisesRegex(RuntimeError, "exceeded 30 seconds"):
                fixture.main()
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[-1][-1], "stop")

    def test_root_privilege_drop_failure_never_executes_gtests(self):
        calls, _ = self.simulate(root=True, fail_first=True)
        self.assertEqual(len(calls), 1)
        self.assertIn("/usr/sbin/runuser", calls[0][0])


if __name__ == "__main__":
    unittest.main()
