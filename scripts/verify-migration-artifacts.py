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


BASELINE_FILES = ("schema.sql", "checksums.txt")


def baseline_artifacts(directory, source):
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("Invalid baseline directory")
    if {path.name for path in directory.iterdir()} != set(BASELINE_FILES):
        raise ValueError("Baseline must contain exactly schema.sql and checksums.txt")
    contents = {}
    for name in BASELINE_FILES:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Invalid baseline artifact: {name}")
        contents[name] = path.read_bytes()
        if not contents[name] or b"\0" in contents[name]:
            raise ValueError(f"Empty or invalid baseline artifact: {name}")
    expected = f"{digest(contents['schema.sql'])} schema.sql\n"
    active = sorted(name for name in source if "/" not in name)
    if not active:
        raise ValueError("Baseline must cover numbered source migrations")
    expected += "".join(f"{source[name]} {name}\n" for name in active)
    if contents["checksums.txt"] != expected.encode("ascii"):
        raise ValueError("Baseline manifest does not cover exact source migration bytes")
    return {f"baseline/{name}": digest(data) for name, data in contents.items()}


def source_migrations(directory, baseline_directory=None):
    source = {}
    for path in sorted(directory.rglob("*.sql")):
        relative = path.relative_to(directory).as_posix()
        if relative.startswith("baseline/"):
            continue
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Invalid source migration: {path}")
        source[relative] = digest(path.read_bytes())
    if not source:
        raise ValueError(f"No source migrations found under {directory}")
    embedded = directory / "baseline"
    if embedded.exists() or embedded.is_symlink():
        if baseline_directory is not None:
            raise ValueError("Ambiguous baseline source")
        baseline_directory = embedded
    if baseline_directory is not None:
        source.update(baseline_artifacts(baseline_directory, source))
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
        if relative == "baseline" and member.isdir():
            continue
        if not relative.endswith(".sql") and not relative.startswith("baseline/") and relative != "baseline":
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
    parser.add_argument("--baseline-directory", type=Path,
                        help="Explicit validated baseline directory for source-mode package checks")
    parser.add_argument("--check-source", action="store_true",
                        help="Validate source and baseline bytes without a built package")
    parser.add_argument("--deb", type=Path)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    if args.baseline_directory is not None and args.source is None:
        parser.error("--baseline-directory requires --source")
    if args.check_source and (args.source is None or args.deb or args.bundle or args.sha256sums):
        parser.error("--check-source requires source mode without packages")
    if args.deb is None and args.bundle is None and not args.check_source:
        parser.error("At least one of --deb or --bundle is required")
    if args.release_tag is not None and args.sha256sums is None:
        parser.error("--release-tag requires --sha256sums")
    if args.sha256sums is not None:
        for package in (args.deb, args.bundle):
            if package is not None:
                verify_package_digest(package, args.sha256sums)
    expected = (source_migrations(args.source, args.baseline_directory) if args.source is not None
                else release_migrations(args.manifest, args.release_tag))
    if args.check_source:
        print(f"PASS source migration artifacts: {len(expected)} checksums verified")
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
