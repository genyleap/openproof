#!/usr/bin/env python3
"""Reproducible SQL checksum inventory of explicitly pinned release Git tags.

This is source-tag evidence, not proof of the contents of published binaries.
No SQL is executed. No database or network access is required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "docs" / "schema-release-inventory.json"
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?\Z")
MIGRATION = re.compile(r"[0-9]{4}_[a-zA-Z0-9_]+\.sql\Z")


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def inventory(tags: list[str]) -> dict:
    if not tags or len(tags) != len(set(tags)) or any(not TAG.fullmatch(t) for t in tags):
        raise ValueError("Expected distinct explicit release tags")
    releases = {}
    files = {}
    hashes = {}
    for tag in sorted(tags):
        commit = git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}").decode().strip()
        releases[tag] = commit
        seen = set()
        entries = git("ls-tree", "-r", "-z", commit, "--", "migrations")
        for entry in entries.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            mode, kind, blob = metadata.decode("ascii").split()
            path = PurePosixPath(raw_path.decode("utf-8", errors="strict"))
            if path.suffix != ".sql":
                continue
            if (mode not in ("100644", "100755") or kind != "blob"
                    or len(path.parts) not in (2, 3)
                    or path.parts[0] != "migrations"
                    or (len(path.parts) == 3 and path.parts[1] != "legacy")
                    or not MIGRATION.fullmatch(path.name)):
                raise ValueError(f"Unsupported migration artifact: {tag}: {path}")
            relative = path.as_posix()
            if relative in seen:
                raise ValueError(f"Duplicate migration artifact: {tag}: {path}")
            seen.add(relative)
            if blob not in hashes:
                hashes[blob] = hashlib.sha256(git("cat-file", "blob", blob)).hexdigest()
            files.setdefault(relative, {}).setdefault(hashes[blob], []).append(tag)
        if not seen:
            raise ValueError(f"No migration SQL found in {tag}")
    return {"format": 1, "source": "git-release-tags", "releases": releases,
            "files": files}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate", nargs="+", metavar="TAG")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.generate:
        print(json.dumps(inventory(args.generate), sort_keys=True, indent=2))
        return
    recorded = json.loads(args.manifest.read_text(encoding="utf-8"))
    actual = inventory(list(recorded["releases"]))
    if actual != recorded:
        raise ValueError("Release migration inventory differs from pinned tags")
    # Report filename collisions without confusing numeric prefixes with IDs.
    by_version = {}
    for path, variants in actual["files"].items():
        by_version.setdefault(PurePosixPath(path).name, set()).update(variants)
    divergent = sorted(name for name, variants in by_version.items() if len(variants) > 1)
    if divergent:
        print("REVIEW multiple published checksums for:", ", ".join(divergent))
    print(f"PASS: {len(actual['releases'])} pinned release tags, "
          f"{len(actual['files'])} migration paths verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"FAIL: release schema inventory: {error}", file=sys.stderr)
        sys.exit(1)
