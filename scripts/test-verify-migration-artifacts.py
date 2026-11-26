#!/usr/bin/env python3
"""Regression tests for source-to-release migration parity checks."""

import io
import json
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

    def release_manifest(self):
        manifest = self.root / "inventory.json"
        first = self.expected["0001_initial.sql"]
        second = self.expected["0002_more.sql"]
        manifest.write_text(json.dumps({
            "format": 1, "source": "git-release-tags",
            "releases": {"v1": {}, "v2": {}},
            "files": {
                "migrations/0001_initial.sql": {first: ["v1", "v2"]},
                "migrations/0002_more.sql": {second: ["v1"]},
                "migrations/legacy/0002_more.sql": {second: ["v2"]},
            },
        }), encoding="utf-8")
        return manifest

    def test_pinned_release_exact_path_parity(self):
        manifest = self.release_manifest()
        expected = checker["release_migrations"](manifest, "v1")
        checker["verify"]("release v1", expected, self.bundle())
        moved = checker["release_migrations"](manifest, "v2")
        self.assertIn("legacy/0002_more.sql", moved)
        self.assertNotIn("0002_more.sql", moved)
        with self.assertRaisesRegex(ValueError, "missing="):
            checker["verify"]("release v2", moved, self.bundle())

    def test_unpinned_release_rejected(self):
        with self.assertRaisesRegex(ValueError, "not pinned"):
            checker["release_migrations"](self.release_manifest(), "v3")

    def test_ambiguous_release_checksum_rejected(self):
        manifest = self.release_manifest()
        value = json.loads(manifest.read_text())
        value["files"]["migrations/0001_initial.sql"]["f" * 64] = ["v1"]
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "Ambiguous checksum"):
            checker["release_migrations"](manifest, "v1")

    def test_release_inventory_rejects_unsafe_path(self):
        manifest = self.release_manifest()
        value = json.loads(manifest.read_text())
        value["files"]["migrations/../0003_extra.sql"] = {"f" * 64: ["v1"]}
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "Invalid release migration path"):
            checker["release_migrations"](manifest, "v1")

    def test_pinned_release_empty_rejected(self):
        manifest = self.release_manifest()
        value = json.loads(manifest.read_text())
        value["files"] = {}
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "No migrations pinned"):
            checker["release_migrations"](manifest, "v1")

    def test_complete_package_digest(self):
        path = self.root / "test.deb"
        path.write_bytes(b"package bytes")
        sums = self.root / "SHA256SUMS"
        value = checker["digest"](path.read_bytes())
        sums.write_text(f"{value}  {path.name}\n")
        checker["verify_package_digest"](path, sums)
        path.write_bytes(b"tampered bytes")
        with self.assertRaisesRegex(ValueError, "Package SHA-256 mismatch"):
            checker["verify_package_digest"](path, sums)

    def test_package_digest_requires_unique_exact_filename(self):
        path = self.root / "test.deb"
        path.write_bytes(b"package bytes")
        sums = self.root / "SHA256SUMS"
        value = checker["digest"](path.read_bytes())
        for content in (
            f"{value}  other.deb\n",
            f"{value}  test.deb\n{value}  test.deb\n",
            f"{value}  ../test.deb\n",
        ):
            sums.write_text(content)
            with self.assertRaises(ValueError):
                checker["verify_package_digest"](path, sums)

    def baseline(self):
        directory = self.root / "baseline"
        directory.mkdir()
        sql = b"CREATE SCHEMA IF NOT EXISTS openproof;\n"
        (directory / "schema.sql").write_bytes(sql)
        (directory / "checksums.txt").write_text(
            f"{checker['digest'](sql)} schema.sql\n"
            + "".join(f"{value} {name}\n" for name, value in sorted(self.expected.items())))
        return directory

    def baseline_bundle(self, directory, *, omit=(), corrupt=(), extra=()):
        path = self.root / "baseline.tar.gz"
        entries = {file.name: file.read_bytes() for file in self.source.iterdir()}
        entries.update({f"baseline/{file.name}": file.read_bytes()
                        for file in directory.iterdir()})
        entries.update({name: b"unexpected" for name in extra})
        with tarfile.open(path, "w:gz") as archive:
            for name, data in entries.items():
                if name in omit:
                    continue
                if name in corrupt:
                    data += b"\nmodified"
                info = tarfile.TarInfo(f"./opt/openproof/migrations/{name}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return checker["read_bundle"](path)

    def test_baseline_package_contains_exact_sql_and_manifest(self):
        directory = self.baseline()
        expected = checker["source_migrations"](self.source, directory)
        self.assertEqual(len(expected), 4)
        checker["verify"]("baseline bundle", expected, self.baseline_bundle(directory))
        for omit, corrupt, extra in (
            (("baseline/checksums.txt",), (), ()),
            ((), ("baseline/schema.sql",), ()),
            ((), ("baseline/checksums.txt",), ()),
            ((), (), ("baseline/untracked.txt",)),
        ):
            with self.assertRaisesRegex(ValueError, "migration mismatch"):
                checker["verify"]("baseline bundle", expected,
                    self.baseline_bundle(directory, omit=omit, corrupt=corrupt, extra=extra))
        with self.assertRaisesRegex(ValueError, "extra="):
            checker["verify"]("ordinary bundle", self.expected, self.baseline_bundle(directory))

    def test_stale_baseline_manifest_rejected(self):
        directory = self.baseline()
        (self.source / "0002_more.sql").write_text("SELECT 3;\n")
        with self.assertRaisesRegex(ValueError, "exact source migration bytes"):
            checker["source_migrations"](self.source, directory)

    def test_baseline_sql_digest_must_match(self):
        directory = self.baseline()
        (directory / "schema.sql").write_text("SELECT 999;\n")
        with self.assertRaisesRegex(ValueError, "exact source migration bytes"):
            checker["source_migrations"](self.source, directory)

    def test_baseline_rejects_extra_and_symlink_artifacts(self):
        directory = self.baseline()
        extra = directory / "other.txt"
        extra.write_text("untracked")
        with self.assertRaisesRegex(ValueError, "exactly"):
            checker["source_migrations"](self.source, directory)
        extra.unlink()
        manifest = directory / "checksums.txt"
        manifest.rename(self.root / "manifest.txt")
        manifest.symlink_to(self.root / "manifest.txt")
        with self.assertRaisesRegex(ValueError, "Invalid baseline artifact"):
            checker["source_migrations"](self.source, directory)

    def test_embedded_baseline_and_explicit_baseline_are_mutually_exclusive(self):
        directory = self.baseline()
        embedded = self.source / "baseline"
        directory.rename(embedded)
        self.assertEqual(len(checker["source_migrations"](self.source)), 4)
        with self.assertRaisesRegex(ValueError, "Ambiguous baseline source"):
            checker["source_migrations"](self.source, embedded)

    def test_empty_source_rejected(self):
        for file in self.source.iterdir():
            file.unlink()
        with self.assertRaisesRegex(ValueError, "No source migrations"):
            checker["source_migrations"](self.source)


if __name__ == "__main__":
    unittest.main()
