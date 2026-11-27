#!/usr/bin/env python3
"""Diagnostic only: matched, sequential Asio awaitable microbenchmark.

No protocol endpoints, database, credentials, production flags or release
acceptance decisions are touched. Compile diagnostics remain fatal for each
variant; a failed compilation never becomes a measured result.
"""
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import tempfile

SOURCE = r'''#include <boost/version.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <stdexcept>

static_assert(BOOST_VERSION == 108800);
namespace asio = boost::asio;
using U64 = std::uint64_t;
asio::awaitable<U64> leaf(U64 x) { co_return x ^ (x >> 7U); }
asio::awaitable<U64> stage1(U64 x) { co_return (co_await leaf(x)) + 13U; }
asio::awaitable<U64> stage2(U64 x) { co_return (co_await stage1(x)) ^ 29U; }
asio::awaitable<U64> stage3(U64 x) { co_return (co_await stage2(x)) + 37U; }
asio::awaitable<U64> run(U64 count, U64 seed) {
    U64 result = seed;
    for (U64 i = 0; i < count; ++i) result = co_await stage3(result + i);
    co_return result;
}
int main() {
    constexpr U64 count = 250000U, seed = 97U;
    asio::io_context io;
    auto warm = asio::co_spawn(io, run(10000U, seed), asio::use_future);
    io.run(); static_cast<void>(warm.get()); io.restart();
    const auto start = std::chrono::steady_clock::now();
    const auto cpu = std::clock();
    auto future = asio::co_spawn(io, run(count, seed), asio::use_future);
    io.run();
    const auto result = future.get();
    const auto wallMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
    const auto cpuMs = 1000.0 * static_cast<double>(std::clock() - cpu) / CLOCKS_PER_SEC;
    U64 expected = seed;
    for (U64 i = 0; i < count; ++i) {
        const U64 v = expected + i;
        expected = (((v ^ (v >> 7U)) + 13U) ^ 29U) + 37U;
    }
    if (result != expected) throw std::runtime_error("checksum mismatch");
    std::cout << "{\"count\":" << count << ",\"checksum\":" << result
              << ",\"wallMs\":" << wallMs << ",\"cpuMs\":" << cpuMs << "}\n";
}
'''

def main():
    gcc = Path(os.environ["OPENPROOF_GCC_ROOT"]) / "bin" / "g++"
    boost = Path.home() / ".cache/openproof/boost-1.88.0/install/include"
    version = subprocess.check_output([str(gcc), "-dumpfullversion"], text=True).strip()
    if version != "16.2.0":
        raise RuntimeError("Unqualified probe compiler: " + version)
    variants = {"normal": [], "noinline": ["-fno-inline"],
                "narrow": ["-fno-inline-functions-called-once"],
                "limited-no-early": ["-fno-inline-small-functions",
                                     "-fno-inline-functions-called-once",
                                     "-fno-early-inlining"]}
    common = ["-std=c++26", "-O2", "-g0", "-DNDEBUG", "-Wall", "-Wextra",
              "-Wpedantic", "-Werror", "-fstack-protector-strong", "-fno-common",
              "-D_FORTIFY_SOURCE=2", "-DBOOST_HAS_LONG_LONG=1",
              "-DBOOST_ASIO_DISABLE_THREAD_KEYWORD_EXTENSION=1",
              "-isystem", str(boost), "-pthread"]
    report = {"compiler": version, "boost": "1.88.0", "compile": {},
              "trials": [], "summary": {}, "caveat": "Synthetic diagnostic only"}
    with tempfile.TemporaryDirectory(prefix="openproof-inline-probe-") as work:
        root = Path(work)
        source = root / "probe.cpp"
        source.write_text(SOURCE)
        for name, flags in variants.items():
            result = subprocess.run([str(gcc), *common, *flags, str(source),
                                     "-o", str(root / name)],
                                    capture_output=True, text=True, timeout=120)
            report["compile"][name] = {"exitCode": result.returncode,
                                       "stderr": result.stderr[-12000:]}
            print("Compile", name, "exit", result.returncode, flush=True)
            if result.returncode:
                print(result.stderr[-12000:], flush=True)
        if report["compile"]["noinline"]["exitCode"]:
            raise RuntimeError("Existing workaround did not compile the probe")
        available = [v for v in variants if report["compile"][v]["exitCode"] == 0]
        for trial in range(5):
            row = {}
            order = available if trial % 2 == 0 else list(reversed(available))
            for name in order:
                result = subprocess.run([str(root / name)], check=True,
                                        capture_output=True, text=True, timeout=30)
                data = json.loads(result.stdout)
                assert data["count"] == 250000
                assert all(math.isfinite(data[k]) and data[k] > 0
                           for k in ("wallMs", "cpuMs"))
                row[name] = data
            assert len({r["checksum"] for r in row.values()}) == 1
            report["trials"].append(row)
            print(json.dumps({"trial": trial + 1, **row}), flush=True)
        for name in available:
            if name == "noinline":
                continue
            report["summary"][name] = {
                key: {"median": statistics.median(r[name][key] for r in report["trials"]),
                      "noinlineMedian": statistics.median(r["noinline"][key] for r in report["trials"]),
                      "pairedRatio": statistics.median(r[name][key] / r["noinline"][key]
                                                       for r in report["trials"])}
                for key in ("wallMs", "cpuMs")}
    print(json.dumps(report["summary"], indent=2), flush=True)
    Path("asio-inline-probe.json").write_text(json.dumps(report, indent=2) + "\n")
    print("NOT APPROVED: no inference about network throughput or production qualification.")

if __name__ == "__main__":
    main()
