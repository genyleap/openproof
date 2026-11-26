#!/usr/bin/env python3
"""Verify that published OpenProof archives contain every source migration unchanged."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile

TARGET = ("opt", "openproof", "migrations")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_migrations(directory):
    source = {}
    for path in sorted(directory.rglob("*.sql")):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Invalid source migration: {path}")
        source[path.relative_to(directory).as_posix()] = digest(path.read_bytes())
    if not source:
        raise ValueError(f"No source migrations found under {directory}")
    return source


def release_migrations(manifest_path, tag):
    """Resolve exact paths and checksums for one independently pinned tag."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["format"] != 1 or manifest["source"] != "git-release-tags":
        raise ValueError("Unsupported release migration inventory")
    if tag not in manifest["releases"]:
        raise ValueError(f"Release tag not pinned: {tag}")
    expected = {}
    for relative, variants in manifest["files"].items():
        path = PurePosixPath(relative)
        if (path.as_posix() != relative or not path.parts
                or path.parts[0] != "migrations"
                or (len(path.parts) != 2
                    and not (len(path.parts) == 3 and path.parts[1] == "legacy"))
                or not re.fullmatch(r"[0-9]{4}_[a-zA-Z0-9_]+\.sql", path.name)):
            raise ValueError(f"Invalid release migration path: {relative}")
        selected = []
        for checksum, tags in variants.items():
            if not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise ValueError(f"Invalid release checksum: {relative}")
            if not isinstance(tags, list) or len(tags) != len(set(tags)):
                raise ValueError(f"Invalid release tag list: {relative}")
            if tag in tags:
                selected.append(checksum)
        if len(selected) > 1:
            raise ValueError(f"Ambiguous checksum for {tag}: {relative}")
        if selected:
            expected[PurePosixPath(*path.parts[1:]).as_posix()] = selected[0]
    if not expected:
        raise ValueError(f"No migrations pinned for {tag}")
    return expected


def archive_migrations(archive):
    found = {}
    for member in archive:
        parts = PurePosixPath(member.name).parts
        if parts and parts[0] == ".":
            parts = parts[1:]
        if len(parts) <= len(TARGET) or parts[:len(TARGET)] != TARGET:
            continue
        relative = PurePosixPath(*parts[len(TARGET):]).as_posix()
        if not relative.endswith(".sql"):
            continue
        if relative in found:
            raise ValueError(f"Duplicate migration in archive: {relative}")
        if not member.isfile():
            raise ValueError(f"Migration is not a regular file: {relative}")
        file_obj = archive.extractfile(member)
        if file_obj is None:
            raise ValueError(f"Cannot read migration: {relative}")
        with file_obj:
            found[relative] = digest(file_obj.read())
    return found


def read_bundle(path):
    with tarfile.open(path, "r:gz") as archive:
        return archive_migrations(archive)


def read_deb(path):
    process = subprocess.Popen(
        ["dpkg-deb", "--fsys-tarfile", os.fspath(path)],
        stdout=subprocess.PIPE,
    )
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|*") as archive:
            result = archive_migrations(archive)
        if process.wait() != 0:
            raise ValueError(f"dpkg-deb failed: {path}")
        return result
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()


def verify_package_digest(path, sums_path):
    """Check the complete package against its exact published filename."""
    matches = []
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\\\\]+)", line)
        if not match:
            raise ValueError("Invalid published SHA256SUMS entry")
        if match[2] == path.name:
            matches.append(match[1])
    if len(matches) != 1:
        raise ValueError(f"Expected one published digest for {path.name}")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != matches[0]:
        raise ValueError(f"Package SHA-256 mismatch: {path.name}")
    print(f"PASS package SHA-256: {path.name}")


def verify(label, expected, actual):
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    changed = sorted(name for name in expected.keys() & actual.keys()
                     if expected[name] != actual[name])
    if missing or extra or changed:
        raise ValueError(
            f"{label} migration mismatch: missing={missing}, "
            f"extra={extra}, changed={changed}"
        )
    print(f"PASS {label}: {len(expected)} migration files and SHA-256 checksums match")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source", type=Path)
    mode.add_argument("--release-tag", help="Compare with an exact pinned release tag")
    parser.add_argument("--manifest", type=Path,
                        default=Path(__file__).resolve().parent.parent / "docs/schema-release-inventory.json")
    parser.add_argument("--sha256sums", type=Path,
                        help="Published SHA256SUMS (required in release-tag mode)")
    parser.add_argument("--deb", type=Path)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    if args.deb is None and args.bundle is None:
        parser.error("At least one of --deb or --bundle is required")
    if args.release_tag is not None and args.sha256sums is None:
        parser.error("--release-tag requires --sha256sums")
    if args.sha256sums is not None:
        for package in (args.deb, args.bundle):
            if package is not None:
                verify_package_digest(package, args.sha256sums)
    expected = (source_migrations(args.source) if args.source is not None
                else release_migrations(args.manifest, args.release_tag))
    if args.deb is not None:
        verify("Debian package", expected, read_deb(args.deb))
    if args.bundle is not None:
        verify("Linux bundle", expected, read_bundle(args.bundle))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(f"FAIL migration artifact verification: {error}", file=sys.stderr)
        sys.exit(1)
