#!/usr/bin/env python3
"""Regression tests for baseline admission; no database is needed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "verify_schema_baseline", Path(__file__).with_name("verify-schema-baseline.py"))
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


class MigrationAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "docs").mkdir()
        (self.root / "migrations/legacy").mkdir(parents=True)
        self.old = self.root / "migrations/0001_schema.sql"
        self.seed = self.root / "migrations/legacy/0002_tenant_seed.sql"
        self.new = self.root / "migrations/0002_new_schema.sql"
        self.old.write_bytes(b"SELECT 1;\n")
        self.seed.write_bytes(b"SELECT 2;\n")
        self.new.write_bytes(b"SELECT 3;\n")
        checksum = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        self.manifest = {
            "format": 1, "source": "git-release-tags",
            "files": {
                "migrations/0001_schema.sql": {checksum(self.old): ["v1"]},
                "migrations/0002_tenant_seed.sql": {checksum(self.seed): ["v1"]},
                "migrations/legacy/0002_tenant_seed.sql": {checksum(self.seed): ["v2"]},
            },
        }
        self.write_manifest()

    def write_manifest(self):
        (self.root / "docs/schema-release-inventory.json").write_text(
            json.dumps(self.manifest), encoding="utf-8")

    def admit(self):
        return baseline.migration_files(self.root)

    def test_accepts_new_schema_with_same_numeric_prefix_as_archived_seed(self):
        self.assertEqual(self.admit(), [self.old, self.new])

    def test_rejects_changed_published_schema(self):
        self.old.write_bytes(b"SELECT 9;\n")
        with self.assertRaisesRegex(ValueError, "checksum changed"):
            self.admit()

    def test_rejects_changed_archived_seed(self):
        self.seed.write_bytes(b"SELECT 9;\n")
        with self.assertRaisesRegex(ValueError, "checksum changed"):
            self.admit()

    def test_rejects_missing_published_schema(self):
        self.old.unlink()
        with self.assertRaisesRegex(ValueError, "Published executable migration missing"):
            self.admit()

    def test_rejects_missing_archive_member(self):
        self.seed.unlink()
        with self.assertRaisesRegex(ValueError, "archive differs"):
            self.admit()

    def test_rejects_executable_seed(self):
        self.new.unlink()
        (self.old.parent / self.seed.name).write_bytes(self.seed.read_bytes())
        with self.assertRaisesRegex(ValueError, "archived seed is executable"):
            self.admit()

    def test_rejects_unknown_archived_migration(self):
        (self.seed.parent / "0003_extra.sql").write_bytes(b"SELECT 3;")
        with self.assertRaisesRegex(ValueError, "archive differs"):
            self.admit()

    def test_rejects_symlink(self):
        content = self.old.read_bytes()
        self.old.unlink()
        target = self.root / "other.sql"
        target.write_bytes(content)
        self.old.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "Invalid migration artifact"):
            self.admit()

    def test_rejects_divergent_published_checksums(self):
        self.manifest["files"]["migrations/0002_tenant_seed.sql"]["f" * 64] = ["v3"]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "Ambiguous or invalid published checksum"):
            self.admit()


if __name__ == "__main__":
    unittest.main()
