"""Tests for the narrow queries (--routine, --signal), file-located control
errors, and deterministic report output."""

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from m740recon import command, control
from m740recon.tests import fixtures


class _Cli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.rom = os.path.join(self.dir, "rom.bin")
        with open(self.rom, "wb") as f:
            f.write(fixtures.signals_image())
        self.ctl = os.path.join(self.dir, "fw.m740")
        with open(self.ctl, "w") as f:
            f.write(fixtures.SIGNALS_CONTROL)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr, sys.argv
        sys.stdout, sys.stderr = out, err
        sys.argv = ["m740recon", "-c", self.ctl] + list(args) + [self.rom]
        code = 0
        try:
            command.main()
        except SystemExit as e:
            code = e.code
        finally:
            sys.stdout, sys.stderr, sys.argv = old
        return code, out.getvalue(), err.getvalue()


class RoutineQueryTests(_Cli):
    def test_by_name(self):
        code, out, _ = self.run_cli("--routine", "reset")
        self.assertEqual(code, 0)
        lines = out.strip().splitlines()
        self.assertEqual(lines[0], "reset:")
        self.assertTrue(lines[-1].lstrip().startswith("rts"))
        self.assertIn("PE: branch if paper present", out)
        self.assertNotIn(".area", out)                  # body only

    def test_by_address_matches_name(self):
        self.assertEqual(self.run_cli("--routine", "0xffc0")[1],
                         self.run_cli("--routine", "reset")[1])

    def test_unknown_routine(self):
        code, out, err = self.run_cli("--routine", "nosuch")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("Unknown routine 'nosuch'", err)

    def test_address_not_a_routine_entry(self):
        code, _, err = self.run_cli("--routine", "0xffc2")
        self.assertEqual(code, 2)


class SignalQueryTests(_Cli):
    def test_one_signal(self):
        code, out, _ = self.run_cli("--signal", "EE_CS")
        self.assertEqual(code, 0)
        self.assertIn("EE_CS (P1.0)", out)
        self.assertIn("0xffc0", out)
        self.assertNotIn("PE (P0.6)", out)
        self.assertIn("; device M50734, 1 signals, 2 accesses", out)

    def test_one_signal_lint_only_for_it(self):
        _, out, _ = self.run_cli("--signal", "EE_SK")
        self.assertIn("EE_SK (P1.1): never read or written", out)
        self.assertNotIn("PE (P0.6):", out)

    def test_unknown_signal_lists_declared(self):
        code, out, err = self.run_cli("--signal", "NOPE")
        self.assertEqual(code, 2)
        self.assertIn("Unknown signal 'NOPE'; declared: PE, STB", err)


class LintOnStderrTests(_Cli):
    def test_listing_run_prints_lint_to_stderr(self):
        code, out, err = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn("m740recon: lint: EE_SK (P1.1): never read or written",
                      err)
        self.assertNotIn("lint", out)


class ControlErrorLocationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _load_error(self, text, name="fw.m740"):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            f.write(text)
        with self.assertRaises(control.ControlError) as ctx:
            control.load(path)
        return path, str(ctx.exception)

    def test_parse_error_names_file_and_line(self):
        path, msg = self._load_error("device M50734\nentry nothex\n")
        self.assertTrue(msg.startswith(path + ": line 2"), msg)

    def test_signal_error_names_file_and_line(self):
        path, msg = self._load_error("device M50734\n\npin P0.9 X\n")
        self.assertTrue(msg.startswith(path + ": line 3"), msg)

    def test_resolution_error_names_file_and_line(self):
        path = os.path.join(self.dir, "fw.m740")
        with open(path, "w") as f:
            f.write("device M50734\npin PX.1 A\n")
        cf = control.load(path)
        with self.assertRaises(control.ControlError) as ctx:
            command.build_signal_map(cf, "M50734")
        self.assertTrue(str(ctx.exception).startswith(path + ": line 2"))

    def test_parse_text_errors_keep_line_only(self):
        with self.assertRaises(control.ControlError) as ctx:
            control.parse("entry nothex\n")
        self.assertTrue(str(ctx.exception).startswith("line 1"))


class DeterminismTests(_Cli):
    def _run_with_seed(self, seed, *args):
        env = dict(os.environ, PYTHONHASHSEED=str(seed))
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(os.path.dirname(here))
        res = subprocess.run(
            [sys.executable, "-m", "m740recon.command", "-c", self.ctl]
            + list(args) + [self.rom],
            cwd=root, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout, res.stderr

    def test_reports_identical_across_hash_seeds(self):
        for args in (["-j"], ["--signals"], ["--suggest"], ["-g"], []):
            a = self._run_with_seed(1, *args)
            b = self._run_with_seed(2, *args)
            self.assertEqual(a, b, args)


if __name__ == "__main__":
    unittest.main()
