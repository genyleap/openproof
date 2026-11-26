#!/usr/bin/env python3
"""Record a tested bundle or run its ELF in an isolated disposable E2E.

Only consume artifacts retrieved from the trusted repository's Actions run.
The manifest binds the bundle to the checkout tree; it is not a signature.
Never install the archive, extract its installer, or use the system's live DB.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
NAME = "development-bundle.json"
MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 512


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def tree():
    return git("rev-parse", "HEAD^{tree}")


def digest(bundle):
    if not bundle.is_file() or bundle.is_symlink() or not 0 < bundle.stat().st_size <= MAX_BYTES:
        raise ValueError("Invalid bundle size or file type")
    with bundle.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def record(bundle):
    manifest = {
        "format": 1, "commit": git("rev-parse", "HEAD"), "tree": tree(),
        "bundle": bundle.name, "sha256": digest(bundle),
        "bytes": bundle.stat().st_size, "architecture": "amd64",
        "classification": "development-only",
    }
    (bundle.parent / NAME).write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print("PASS: recorded tested development bundle provenance")


def verify(bundle, expected_digest=None):
    manifest_path = bundle.parent / NAME
    if not manifest_path.is_file() or manifest_path.is_symlink() or manifest_path.stat().st_size > 4096:
        raise ValueError("Missing or invalid provenance manifest")
    m = json.loads(manifest_path.read_text())
    if (m.get("format") != 1 or m.get("tree") != tree()
            or m.get("bundle") != bundle.name or m.get("architecture") != "amd64"
            or m.get("classification") != "development-only"
            or not re.fullmatch("[0-9a-f]{40}", m.get("commit", ""))
            or m.get("bytes") != bundle.stat().st_size or m.get("sha256") != digest(bundle)
            or (expected_digest is not None and expected_digest != m.get("sha256"))):
        raise ValueError("Bundle provenance, source tree or digest mismatch")
    return m


def stage(bundle, root):
    """Extract only the real executable and flat regular runtime libraries."""
    selected = set()
    size = 0
    with tarfile.open(bundle, "r:gz") as archive:
        for index, member in enumerate(archive):
            if index >= MAX_FILES:
                raise ValueError("Archive exceeds member limit")
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Unsafe archive path")
            parts = path.parts
            if parts == ("opt", "openproof", "bin", "opp.real"):
                target = root / "opp.real"
            elif len(parts) == 4 and parts[:3] == ("opt", "openproof", "lib"):
                if not re.fullmatch(r"[A-Za-z0-9_+.-]+\.so(?:\.[A-Za-z0-9_+.-]+)?", parts[3]):
                    raise ValueError("Unexpected runtime library filename")
                target = root / "lib" / parts[3]
            else:
                continue
            if not member.isfile() or member.issym() or member.islnk() or target in selected:
                raise ValueError("Nonregular or duplicate runtime entry")
            size += member.size
            if member.size <= 0 or size > MAX_BYTES:
                raise ValueError("Runtime size limit exceeded")
            selected.add(target)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open("xb") as dest:
                shutil.copyfileobj(source, dest, length=1024 * 1024)
            target.chmod(0o700 if target.name == "opp.real" else 0o600)
    if root / "opp.real" not in selected or not (root / "lib").is_dir():
        raise ValueError("Incomplete runtime closure")
    with (root / "opp.real").open("rb") as binary:
        if binary.read(4) != b"\x7fELF":
            raise ValueError("Expected ELF executable")
    launcher = root / "opp"
    launcher.write_text('#!/bin/sh\nset -eu\nHERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\n'
                        'unset LD_PRELOAD LD_AUDIT\n'
                        'export LD_LIBRARY_PATH="$HERE/lib"\n'
                        'exec "$HERE/opp.real" "$@"\n')
    launcher.chmod(0o700)
    return launcher


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("record", "verify", "e2e"))
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--sha256", help="Optional independently trusted bundle digest")
    args = parser.parse_args()
    bundle = args.bundle.absolute()
    if args.mode == "record":
        record(bundle)
        return 0
    if args.mode == "e2e" and git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Tracked source tree must be clean before execution")
    verify(bundle, args.sha256)
    with tempfile.TemporaryDirectory(prefix="openproof-dev-bundle-") as folder:
        launcher = stage(bundle, Path(folder))
        print("PASS: verified source tree, archive digest and isolated runtime closure", flush=True)
        if args.mode == "verify":
            return 0
        # Existing wrapper supplies only test credentials and removes its DB.
        return subprocess.run(["python3", "-B", str(ROOT / "scripts/run-local-native-login-e2e.py"),
                               "--opp", str(launcher)], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        raise SystemExit("Development bundle verification/execution failed; no release approval") from None
