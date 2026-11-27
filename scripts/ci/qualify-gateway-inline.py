#!/usr/bin/env python3
"""Compile the real Gateway implementation units with narrower inlining flags.

Run only after the ordinary Release Gateway target has built. Reuse its
read-only C++ module inputs; never replace its object files or executable.
A successful object compile is evidence only, not link, security or
performance qualification. Keep the existing build workaround unchanged.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time

UNITS = ("http_coroutine.cpp", "http.cpp", "http_proxy.cpp")
VARIANTS = {
    "narrow": ("-fno-inline-functions-called-once",),
    "normal": (),
}


def candidate_command(entry, build, unit, output, flags):
    directory = Path(entry["directory"]).resolve()
    if directory != build:
        raise ValueError("unexpected compilation working directory")
    source = Path(entry["file"])
    if source.name != unit or source.parent.name != "gateway":
        raise ValueError("unexpected compilation source")
    args = shlex.split(entry["command"])
    for required in ("-fno-inline", "-Werror", "-O2", "-std=c++26", "-c", "-o"):
        if args.count(required) != 1:
            raise ValueError("missing or ambiguous required option: " + required)
    if any(a.startswith(("-Wno-error", "-Wno-mismatched-new-delete", "@"))
           for a in args):
        raise ValueError("unqualified compiler invocation")
    # The CMake-generated implementation unit mapper only imports modules.
    # Keep its existing BMI paths, never run the dependency scanner or write
    # any object/dependency files into the qualified build tree.
    mappers = [a.split("=", 1)[1] for a in args
               if a.startswith("-fmodule-mapper=")]
    if len(mappers) != 1 or not (directory / mappers[0]).is_file():
        raise ValueError("missing built C++ module mapper")
    if any(a in ("-MF", "-MT", "-MQ", "-fmodule-only", "-E", "-S")
           or a.startswith(("-fdeps-file=", "-fdeps-target=", "-fmodule-output="))
           for a in args):
        raise ValueError("unsupported compilation side-output options")
    object_index = args.index("-o") + 1
    original = (directory / args[object_index]).resolve()
    if not original.is_relative_to(build) or not original.is_file():
        raise ValueError("ordinary Gateway object has not built")
    args[object_index] = str(output)
    args = [a for a in args
            if a not in ("-MD", "-MMD", "-MP", "-fdeps-format=p1689r5")]
    index = args.index("-fno-inline")
    args[index:index + 1] = flags
    return args


def run_compiler(command, build, timeout):
    # GCC drives cc1plus and assembler subprocesses. Killing only the driver
    # can leave a compiler holding the capture pipes or consuming the runner
    # budget. The diagnostic owns a separate process group per invocation.
    with subprocess.Popen(command, cwd=build, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, errors="replace",
                          start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 300:
        parser.error("per-unit timeout must be within 1..300 seconds")
    build = args.build.resolve()
    database = json.loads((build / "compile_commands.json").read_text())
    report = {"schema": 1, "units": {}, "qualified": False,
              "caveat": "Object compilation only; no runtime or release qualification."}
    with tempfile.TemporaryDirectory(prefix="openproof-gateway-inline-") as tmp:
        for unit in UNITS:
            entries = [e for e in database if Path(e["file"]).name == unit
                       and Path(e["file"]).parent.name == "gateway"
                       and "openproof_gateway_http.dir" in e["command"]]
            if len(entries) != 1:
                raise ValueError("missing or ambiguous Gateway command for " + unit)
            entry = entries[0]
            report["units"][unit] = {}
            for name, flags in VARIANTS.items():
                output = Path(tmp) / (unit + "." + name + ".o")
                command = candidate_command(entry, build, unit, output, flags)
                started = time.monotonic()
                try:
                    result = run_compiler(command, build, args.timeout)
                    row = {"exitCode": result.returncode,
                           "objectBytes": output.stat().st_size if output.exists() else None,
                           "stderr": result.stderr[-16000:]}
                except subprocess.TimeoutExpired:
                    row = {"exitCode": None, "objectBytes": None, "timedOut": True}
                row["elapsedSeconds"] = round(time.monotonic() - started, 3)
                row["compiled"] = row["exitCode"] == 0 and bool(row["objectBytes"])
                report["units"][unit][name] = row
                # Preserve partial evidence if a subsequent compiler times out.
                args.output.write_text(json.dumps(report, indent=2) + "\n")
                print(unit, name, "compiled" if row["compiled"] else "not compiled",
                      row["elapsedSeconds"], "seconds", flush=True)
                if row.get("stderr") and not row["compiled"]:
                    print(row["stderr"], flush=True)
                output.unlink(missing_ok=True)
    print(report["caveat"], flush=True)


if __name__ == "__main__":
    main()
