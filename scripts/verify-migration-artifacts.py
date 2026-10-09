#!/usr/bin/env python3
"""Verify that published OpenProof archives contain every source migration unchanged."""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
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
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--deb", type=Path)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    if args.deb is None and args.bundle is None:
        parser.error("At least one of --deb or --bundle is required")
    expected = source_migrations(args.source)
    if args.deb is not None:
        verify("Debian package", expected, read_deb(args.deb))
    if args.bundle is not None:
        verify("Linux bundle", expected, read_bundle(args.bundle))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tarfile.TarError) as error:
        print(f"FAIL migration artifact verification: {error}", file=sys.stderr)
        sys.exit(1)
