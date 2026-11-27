#!/usr/bin/env python3
"""Regression for isolated real-TU compiler command construction."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "qualify_gateway_inline", Path(__file__).with_name("qualify-gateway-inline.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class QualificationTest(unittest.TestCase):
    def test_preserve_hardening_and_redirect_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            build = Path(tmp).resolve()
            (build / "unit.o").touch()
            (build / "unit.modmap").touch()
            entry = {"directory": str(build), "file": "/src/gateway/http.cpp",
                     "command": "g++ -O2 -std=c++26 -Werror -fstack-protector-strong "
                     "-fno-inline -fmodules-ts -fmodule-mapper=unit.modmap "
                     "-MD -fdeps-format=p1689r5 -o unit.o -c /src/gateway/http.cpp"}
            output = build / "isolated.o"
            result = probe.candidate_command(entry, build, "http.cpp", output,
                                             probe.VARIANTS["narrow"])
            self.assertIn("-fno-inline-functions-called-once", result)
            self.assertNotIn("-fno-inline", result)
            self.assertIn("-Werror", result)
            self.assertIn("-fstack-protector-strong", result)
            self.assertIn("-fmodule-mapper=unit.modmap", result)
            self.assertEqual(result[result.index("-o") + 1], str(output))
            self.assertNotIn("-MD", result)
            self.assertNotIn("-fdeps-format=p1689r5", result)
            self.assertTrue((build / "unit.o").is_file())
            for invalid in ("-Wno-error=mismatched-new-delete", "-MF bad.d",
                            "-fmodule-only", "@opaque.rsp"):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ValueError):
                        probe.candidate_command(
                            {**entry, "command": entry["command"] + " " + invalid},
                            build, "http.cpp", output, ())
            with self.assertRaises(ValueError):
                probe.candidate_command(
                    {**entry, "command": entry["command"].replace("-Werror", "")},
                    build, "http.cpp", output, ())


if __name__ == "__main__":
    unittest.main()
