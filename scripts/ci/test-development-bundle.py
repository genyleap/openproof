#!/usr/bin/env python3
"""Exercise archive provenance and extraction without executing a fake ELF."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "development_bundle", Path(__file__).with_name("development-bundle.py"))
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


class DevelopmentBundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "candidate.tar.gz"

    def write_archive(self, extra=()):
        with tarfile.open(self.archive, "w:gz") as out:
            entries = [
                ("./opt/openproof/bin/opp.real", b"\x7fELFfake", None),
                ("./opt/openproof/lib/libtest.so.1", b"library", None),
                ("./usr/sbin/openproof", b"must never extract", None),
                *extra,
            ]
            for name, data, link in entries:
                entry = tarfile.TarInfo(name)
                if link is not None:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = link
                    out.addfile(entry)
                else:
                    entry.size = len(data)
                    out.addfile(entry, io.BytesIO(data))

    def test_valid_archive(self):
        self.write_archive()
        bundle.record(self.archive)
        manifest = bundle.verify(self.archive)
        self.assertEqual(manifest["tree"], bundle.tree())
        self.assertEqual(manifest["classification"], "development-only")
        launcher = bundle.stage(self.archive, self.root / "stage")
        self.assertTrue(launcher.is_file())
        self.assertTrue((launcher.parent / "lib/libtest.so.1").is_file())
        self.assertFalse((launcher.parent / "usr").exists())

    def test_tamper_and_wrong_tree(self):
        self.write_archive()
        bundle.record(self.archive)
        with self.assertRaises(ValueError):
            bundle.verify(self.archive, "0" * 64)
        metadata = self.root / bundle.NAME
        manifest = json.loads(metadata.read_text())
        manifest["tree"] = "0" * 40
        metadata.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            bundle.verify(self.archive)
        bundle.record(self.archive)
        with self.archive.open("ab") as stream:
            stream.write(b"tamper")
        with self.assertRaises(ValueError):
            bundle.verify(self.archive)

    def test_path_traversal(self):
        self.write_archive([("../outside", b"bad", None)])
        with self.assertRaises(ValueError):
            bundle.stage(self.archive, self.root / "stage")
        self.assertFalse((self.root / "outside").exists())

    def test_link_and_duplicate(self):
        for index, entry in enumerate([
            ("./opt/openproof/lib/libbad.so", b"", "/etc/passwd"),
            ("./opt/openproof/bin/opp.real", b"duplicate", None),
        ]):
            self.write_archive([entry])
            with self.assertRaises(ValueError):
                bundle.stage(self.archive, self.root / f"stage{index}")


if __name__ == "__main__":
    unittest.main()
