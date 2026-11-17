"""Tests for port-mode decoding and the board lint."""

import unittest

from m740recon import access, command, control
from m740recon.devices import Devices

P1, P1DIR = 0xf3, 0xf4

CODE = [
    0xa9, 0x03,          # 8000 lda #0x03
    0x85, P1DIR,         # 8002 sta P1DIR      P1.0-1 out, rest in
    0x4f, P1DIR,         # 8004 seb 2,P1DIR    P1.2 out
    0x0f, P1,            # 8006 seb 0,P1       CS = 1
    0x27, P1, 0x00,      # 8008 bbs 1,P1,+0    SK tested only
    0x8f, P1,            # 800b seb 4,P1       DO (declared in) written
    0xaf, P1,            # 800d seb 5,P1       P1.5 undeclared
    0x60,                # 800f rts
]

CONTROL = (
    "pin P1.0 CS out\n"
    "pin P1.1 SK out\n"
    "pin P1.2 DI in\n"
    "pin P1.4 DO in\n"
    "pin P1.6 SPARE out\n"
    "bit 0x40.0 F\n"
)


def _image():
    rom = bytearray(0x10000)
    rom[0x8000:0x8000 + len(CODE)] = bytes(CODE)
    for v in range(0xFFF4, 0x10000, 2):
        rom[v], rom[v + 1] = 0x00, 0x80
    return bytes(rom)


def _run(device="M50734"):
    rom = _image()
    cf = control.parse(CONTROL)
    memory, _ = command.build_disassembly(rom, device, 0)
    smap = command.build_signal_map(cf, device)
    accs = command.signal_accesses(memory, smap, device)
    return memory, smap, accs, command.signal_lint(memory, smap, accs, device)


class PortModeTests(unittest.TestCase):
    def setUp(self):
        self.memory, self.smap, self.accs, _ = _run()

    def test_shadows_from_metadata(self):
        shadows = access.port_shadows(Devices["M50734"]["ports"])
        self.assertEqual(shadows[0xf7], (0xf6, "direction", 1))
        self.assertEqual(shadows[0xf5], (0xf6, "function", 1))
        self.assertNotIn(0xf2, shadows)          # input latch is not config
        self.assertEqual(access.port_shadows(None), {})

    def test_direction_store_decoded(self):
        cfg = [(a.signal.name, a.level) for a in self.accs
               if a.address == 0x8002 and a.kind == "direction"]
        self.assertEqual(cfg, [("CS", 1), ("SK", 1), ("DI", 0), ("DO", 0),
                               ("SPARE", 0)])

    def test_direction_bit_decoded(self):
        cfg = [(a.signal.name, a.level, a.confidence, a.scope)
               for a in self.accs if a.address == 0x8004]
        self.assertEqual(cfg, [("DI", 1, "exact", "bit")])

    def test_annotation_text(self):
        notes = access.annotations(self.accs)
        self.assertEqual(notes[0x8002], "outputs CS, SK; inputs DI, DO, SPARE")
        self.assertEqual(notes[0x8004], "outputs DI")

    def test_no_metadata_no_config(self):
        _, _, accs, _ = _run("M37450")
        self.assertFalse([a for a in accs
                          if a.kind in ("direction", "function")])


class LintTests(unittest.TestCase):
    def setUp(self):
        self.findings = _run()[3]
        self.by_rule = {}
        for rule, text in self.findings:
            self.by_rule.setdefault(rule, []).append(text)

    def test_direction_contradictions(self):
        self.assertEqual(sorted(self.by_rule["direction"]), [
            "DI (P1.2): declared in, but the firmware makes it an output "
            "at 0x8004",
            "SPARE (P1.6): declared out, but the firmware makes it an input "
            "at 0x8002",
        ])

    def test_unused(self):
        self.assertEqual(self.by_rule["unused"], [
            "DI (P1.2): never read or written by the firmware",
            "SPARE (P1.6): never read or written by the firmware",
            "F (0x40.0): never read or written by the firmware",
        ])

    def test_out_only_read(self):
        self.assertEqual(self.by_rule["out-read"], [
            "SK (P1.1): declared out, but only ever read or tested"])

    def test_input_written(self):
        self.assertEqual(self.by_rule["in-written"], [
            "DO (P1.4): declared in, but written at 0x800b"])

    def test_undeclared_port_bit(self):
        self.assertEqual(self.by_rule["undeclared"], [
            "P1.5: singled out at 1 site(s) (0x800d) but no signal is "
            "declared"])

    def test_device_without_metadata(self):
        findings = _run("M37450")[3]
        self.assertFalse([f for f in findings if f[0] == "direction"])

    def test_no_signals_no_lint(self):
        rom = _image()
        memory, _ = command.build_disassembly(rom, "M50734", 0)
        smap = command.build_signal_map(control.parse("device M50734\n"),
                                        "M50734")
        self.assertEqual(command.signal_lint(memory, smap, [], "M50734"), [])


if __name__ == "__main__":
    unittest.main()
