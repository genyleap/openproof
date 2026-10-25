#!/usr/bin/env python3
"""Regression tests for source-to-release migration parity checks."""

import io
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest
from unittest.mock import patch

checker = runpy.run_path(str(Path(__file__).with_name("verify-migration-artifacts.py")))


class MigrationArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "migrations"
        self.source.mkdir()
        (self.source / "0001_initial.sql").write_text("SELECT 1;\n")
        (self.source / "0002_more.sql").write_text("SELECT 2;\n")
        self.expected = checker["source_migrations"](self.source)

    def bundle(self, *, missing=(), changed=(), duplicate=(), extra=()):
        path = self.root / "bundle.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for file in sorted(self.source.iterdir()):
                if file.name in missing:
                    continue
                data = file.read_bytes()
                if file.name in changed:
                    data += b"-- changed"
                for i in range(2 if file.name in duplicate else 1):
                    target = f"./opt/openproof/migrations/{file.name}"
                    info = tarfile.TarInfo(target)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            for name in extra:
                data = b"SELECT 3;\n"
                info = tarfile.TarInfo(f"./opt/openproof/migrations/{name}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return checker["read_bundle"](path)

    def test_complete_bundle(self):
        checker["verify"]("bundle", self.expected, self.bundle())

    def test_missing_migration_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing="):
            checker["verify"]("bundle", self.expected,
                              self.bundle(missing=("0002_more.sql",)))

    def test_changed_checksum_rejected(self):
        with self.assertRaisesRegex(ValueError, "changed="):
            checker["verify"]("bundle", self.expected,
                              self.bundle(changed=("0001_initial.sql",)))

    def test_extra_migration_rejected(self):
        with self.assertRaisesRegex(ValueError, "extra="):
            checker["verify"]("bundle", self.expected,
                              self.bundle(extra=("0003_untracked.sql",)))

    def test_duplicate_migration_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate migration"):
            self.bundle(duplicate=("0002_more.sql",))

    def test_debian_tar_stream_parsed(self):
        contents = io.BytesIO()
        with tarfile.open(fileobj=contents, mode="w") as archive:
            for file in sorted(self.source.iterdir()):
                data = file.read_bytes()
                info = tarfile.TarInfo(f"./opt/openproof/migrations/{file.name}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        module_globals = checker["read_deb"].__globals__
        with patch.object(module_globals["subprocess"], "Popen") as popen:
            process = popen.return_value
            process.stdout = io.BytesIO(contents.getvalue())
            process.wait.return_value = 0
            checker["verify"]("deb", self.expected,
                              checker["read_deb"](self.root / "fixture.deb"))

    def test_legacy_archive_packaged_but_not_promoted_to_root(self):
        legacy = self.source / "legacy"
        legacy.mkdir()
        historical = legacy / "0020_historical_client.sql"
        historical.write_text("INSERT INTO customer_client VALUES ('example');\n")
        expected = checker["source_migrations"](self.source)
        bundle = self.root / "legacy-bundle.tar.gz"
        with tarfile.open(bundle, "w:gz") as archive:
            for file in sorted(self.source.rglob("*.sql")):
                relative = file.relative_to(self.source).as_posix()
                data = file.read_bytes()
                info = tarfile.TarInfo(f"./opt/openproof/migrations/{relative}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        actual = checker["read_bundle"](bundle)
        checker["verify"]("legacy archive", expected, actual)
        self.assertIn("legacy/0020_historical_client.sql", actual)
        self.assertNotIn("0020_historical_client.sql", actual)
        actual.pop("legacy/0020_historical_client.sql")
        with self.assertRaisesRegex(ValueError, "missing="):
            checker["verify"]("missing legacy checksum archive", expected, actual)

    def test_empty_source_rejected(self):
        for file in self.source.iterdir():
            file.unlink()
        with self.assertRaisesRegex(ValueError, "No source migrations"):
            checker["source_migrations"](self.source)


if __name__ == "__main__":
    unittest.main()
