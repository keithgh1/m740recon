"""Tests for the signal sections of the report model, the --signals text
report, and the call-graph signal line."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest

from m740recon import access, command, control, report, signals
from m740recon.tests import fixtures


def _build(control_text=fixtures.SIGNALS_CONTROL):
    cf = control.parse(control_text)
    rom = fixtures.signals_image()
    start = 0x10000 - len(rom)
    memory, symtab = command.build_disassembly(
        rom, "M50734", start, **command.control_args(cf, bytearray(rom)))
    smap = command.build_signal_map(cf, "M50734")
    accs = access.classify(memory, smap)
    return memory, symtab, start, len(rom), smap, accs


def _model(with_signals=True):
    memory, symtab, start, n, smap, accs = _build()
    if not with_signals:
        return report.build_model(memory, symtab, start, n, "M50734")
    return report.build_model(memory, symtab, start, n, "M50734",
                              signal_map=smap, accesses=accs)


class SignalModelTests(unittest.TestCase):
    def setUp(self):
        self.model = _model()
        self.sigs = {s["name"]: s for s in self.model["signals"]}

    def test_all_declared_signals_present_in_order(self):
        self.assertEqual([s["name"] for s in self.model["signals"]],
                         ["PE", "STB", "EE_CS", "EE_SK", "CR_PHASE",
                          "asf_installed", "pe_detect_off"])

    def test_signal_header_fields(self):
        pe = self.sigs["PE"]
        self.assertEqual(pe["location"], "P0.6")
        self.assertEqual(pe["address"], "0x00f6")
        self.assertEqual(pe["bits"], [6, 6])
        self.assertEqual(pe["direction"], "in")
        self.assertEqual((pe["high"], pe["low"]), ("paper end", "paper present"))
        self.assertEqual(pe["source"], "firmware")
        self.assertEqual(self.sigs["EE_CS"]["group"], "eeprom")
        self.assertEqual(self.sigs["CR_PHASE"]["bits"], [0, 3])

    def test_accesses(self):
        cs = self.sigs["EE_CS"]["accesses"]
        self.assertEqual([(a["site"], a["kind"], a["level"]) for a in cs],
                         [("0xffc0", "set", 1), ("0xffc2", "clear", 0)])
        self.assertEqual({a["routine"] for a in cs}, {"reset"})
        self.assertEqual(cs[0]["confidence"], "exact")
        self.assertEqual(self.sigs["CR_PHASE"]["accesses"][0]["bit"], 2)
        self.assertEqual(self.sigs["EE_SK"]["accesses"], [])

    def test_groups_and_meta(self):
        self.assertEqual(self.model["groups"],
                         [{"name": "eeprom", "description": "serial EEPROM",
                           "members": ["EE_CS", "EE_SK"]}])
        self.assertEqual(self.model["meta"]["signal_count"], 7)
        self.assertEqual(self.model["meta"]["signal_access_count"], 9)

    def test_routine_summary(self):
        reset = next(r for r in self.model["routines"] if r["name"] == "reset")
        self.assertIn({"name": "PE", "kinds": ["test"]}, reset["signals"])
        self.assertIn({"name": "EE_CS", "kinds": ["clear", "set"]},
                      reset["signals"])

    def test_json_round_trips(self):
        doc = json.loads(report.to_json(self.model))
        self.assertEqual(doc["meta"]["format"], "m740recon-report/1")
        self.assertEqual(len(doc["signals"]), 7)

    def test_deterministic(self):
        self.assertEqual(report.to_json(_model()), report.to_json(self.model))


class NoSignalsModelTests(unittest.TestCase):
    def test_no_signal_keys_without_signals(self):
        model = _model(with_signals=False)
        self.assertNotIn("signals", model)
        self.assertNotIn("groups", model)
        self.assertNotIn("signal_count", model["meta"])
        self.assertTrue(all("signals" not in r for r in model["routines"]))

    def test_empty_signal_map_is_identical(self):
        memory, symtab, start, n, _, _ = _build()
        a = report.build_model(memory, symtab, start, n, "M50734")
        b = report.build_model(memory, symtab, start, n, "M50734",
                               signal_map=signals.SignalMap(), accesses=[])
        self.assertEqual(report.to_json(a), report.to_json(b))
        self.assertEqual(report.format_call_graph(a), report.format_call_graph(b))


class SignalTextReportTests(unittest.TestCase):
    def setUp(self):
        self.text = report.format_signals(_model())
        self.lines = self.text.splitlines()

    def test_header(self):
        self.assertEqual(self.lines[0], "; m740recon signal report")
        self.assertEqual(self.lines[1], "; device M50734, 7 signals, 9 accesses")

    def test_group_first_then_ungrouped(self):
        g = self.lines.index("[group eeprom] serial EEPROM")
        u = self.lines.index("[ungrouped]")
        cs = next(i for i, l in enumerate(self.lines) if l.startswith("EE_CS "))
        pe = next(i for i, l in enumerate(self.lines) if l.startswith("PE "))
        self.assertTrue(g < cs < u < pe)

    def test_signal_title_and_access_lines(self):
        self.assertIn("PE (P0.6)  in, high = paper end, low = paper present"
                      "   [source: firmware]", self.lines)
        self.assertIn("  reset     0xffc4  test       PE: branch if paper present",
                      self.lines)

    def test_never_accessed(self):
        i = self.lines.index("; 1 signal(s) never accessed:")
        self.assertEqual(self.lines[i + 1], ";   EE_SK (P1.1)")
        self.assertIn("  (never accessed)", self.lines)


class CallGraphSignalLineTests(unittest.TestCase):
    def test_signal_line_only_with_signals(self):
        with_sigs = report.format_call_graph(_model())
        without = report.format_call_graph(_model(with_signals=False))
        self.assertIn("    signals: CR_PHASE(set), EE_CS(clear,set), PE(test)",
                      with_sigs)
        self.assertNotIn("signals:", without)


class CliSignalsTests(unittest.TestCase):
    def test_cli_signals_flag(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        rom = os.path.join(d, "rom.bin")
        with open(rom, "wb") as f:
            f.write(fixtures.signals_image())
        ctl = os.path.join(d, "fw.m740")
        with open(ctl, "w") as f:
            f.write(fixtures.SIGNALS_CONTROL)
        buf = io.StringIO()
        old_out, old_argv = sys.stdout, sys.argv
        sys.stdout = buf
        sys.argv = ["m740recon", "-c", ctl, "--signals", rom]
        try:
            command.main()
        finally:
            sys.stdout, sys.argv = old_out, old_argv
        model = _model()
        memory, _, _, _, smap, accs = _build()
        model["lint"] = [{"rule": r, "text": t} for r, t in
                         command.signal_lint(memory, smap, accs, "M50734")]
        self.assertEqual(buf.getvalue(), report.format_signals(model))
        self.assertIn("; lint: ", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
