"""Tests for zero-configuration port discovery and --suggest."""

import io
import os
import shutil
import sys
import tempfile
import unittest

from m740recon import access, command, control, discover, report
from m740recon.tests import asmchain, fixtures


def _cli(*args, control_text=None, device="M50734"):
    d = tempfile.mkdtemp()
    try:
        rom = os.path.join(d, "rom.bin")
        with open(rom, "wb") as f:
            f.write(fixtures.signals_image())
        argv = ["m740recon", "-m", device]
        if control_text is not None:
            ctl = os.path.join(d, "fw.m740")
            with open(ctl, "w") as f:
                f.write(control_text)
            argv += ["-c", ctl]
        buf = io.StringIO()
        old_out, old_argv = sys.stdout, sys.argv
        sys.stdout = buf
        sys.argv = argv + list(args) + [rom]
        try:
            command.main()
        finally:
            sys.stdout, sys.argv = old_out, old_argv
        return buf.getvalue()
    finally:
        shutil.rmtree(d, True)


class PortRegisterTests(unittest.TestCase):
    def test_m50734_ports_from_metadata(self):
        self.assertTrue(discover.has_metadata("M50734"))
        self.assertEqual(discover.port_registers("M50734"),
                         [("P0", 0xf6), ("P1", 0xf3), ("P2", 0xf0), ("P3", 0xee),
                          ("P4", 0xeb)])

    def test_heuristic_without_metadata(self):
        self.assertFalse(discover.has_metadata("M37450"))
        names = [n for n, _ in discover.port_registers("M37450")]
        self.assertEqual(names[:2], ["P0", "P1"])
        self.assertTrue(all(n[1:].isdigit() for n in names))

    def test_m3886_ports(self):
        names = [n for n, _ in discover.port_registers("M3886")]
        self.assertEqual(names[:3], ["P0", "P1", "P2"])
        self.assertNotIn("P0D", names)

    def test_raw_map_names_and_locations(self):
        smap = discover.raw_signal_map("M50734")
        self.assertEqual(len(smap), 40)
        sig = smap.by_name["P0_6"]
        self.assertEqual((sig.address, sig.lo, sig.loc, sig.source),
                         (0xf6, 6, "P0.6", "guess"))
        self.assertEqual(smap.by_name["P4_3"].loc, "P4.3")   # SFR named P4IN


class DiscoveryReportTests(unittest.TestCase):
    def setUp(self):
        self.text = _cli("--signals")
        self.rows = [l for l in self.text.splitlines() if l[:1] == "P"]

    def test_header_names_port_source(self):
        self.assertIn("no signals declared", self.text)
        self.assertIn("ports from device metadata: P0 P1 P2 P3 P4", self.text)

    def test_heuristic_header_without_metadata(self):
        text = _cli("--signals", device="M37450")
        self.assertIn("named P<digit>", text)

    def test_touched_bits_and_directions(self):
        got = [(l.split()[0], l.split()[1]) for l in self.rows]
        self.assertEqual(got, [("P0.4", "out?"), ("P0.6", "in?"),
                               ("P1.0", "out?"), ("P2.2", "out?")])

    def test_counts_and_routine(self):
        pe = next(l for l in self.rows if l.startswith("P0.6"))
        self.assertIn("2 test", pe)
        self.assertTrue(pe.rstrip().endswith("lab_ffc0"))    # reset handler
        cs = next(l for l in self.rows if l.startswith("P1.0"))
        self.assertIn("1 set, 1 clear", cs)

    def test_ram_bits_not_reported(self):
        self.assertNotIn("0x52", self.text)


class SuggestTests(unittest.TestCase):
    def test_suggest_lines(self):
        out = _cli("--suggest")
        pins = [l for l in out.splitlines() if l.startswith("pin ")]
        self.assertEqual(len(pins), 4)
        self.assertTrue(pins[1].startswith("pin P0.6   P0_6   in    source=guess"))
        self.assertIn("direction inferred from use", pins[1])

    def test_suggest_round_trips_into_annotations(self):
        out = _cli("--suggest")
        cf = control.parse("device M50734\n" + out)
        listing = asmchain.disasm_text(fixtures.signals_image(),
                                       device="M50734", control=cf)
        self.assertIn("P0_6?: branch if clear", listing)
        self.assertIn("P1_0? = 1", listing)

    def test_suggest_skips_declared_bits(self):
        out = _cli("--suggest", control_text=fixtures.SIGNALS_CONTROL)
        pins = [l for l in out.splitlines() if l.startswith("pin ")]
        self.assertEqual(pins, [])
        self.assertIn("# 4 touched bit(s) already declared", out)
        # what remains can be appended to the source control file
        control.parse(fixtures.SIGNALS_CONTROL + out)

    def test_signals_with_declarations_is_not_discovery(self):
        out = _cli("--signals", control_text=fixtures.SIGNALS_CONTROL)
        self.assertTrue(out.startswith("; m740recon signal report"))


if __name__ == "__main__":
    unittest.main()
