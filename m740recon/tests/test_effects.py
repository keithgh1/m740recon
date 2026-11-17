"""Tests for routine effect summaries, call-site annotations, reach and
name suggestions (effects.py and the report sections built on it)."""

import unittest

from m740recon import access, command, control, effects, report
from m740recon.tests import asmchain

P1 = 0xf3
CONTROL = (
    "device M50734\n"
    "pin P1.0 CS out active=high\n"
    "pin P1.1 SK out\n"
    "pin P1.4 DO in\n"
    "group bus CS SK DO \"serial bus\"\n"
)


def _image():
    rom = bytearray(0x10000)

    def put(addr, data):
        rom[addr:addr + len(data)] = bytes(data)

    put(0x8000, [0x20, 0x00, 0x90,      # jsr cs_on       (leaf)
                 0x20, 0x10, 0x90,      # jsr sk_pulse    (leaf, delay loop)
                 0x20, 0x20, 0x90,      # jsr wrapper     (calls cs_on)
                 0x20, 0x30, 0x90,      # jsr skipper     (forward branch)
                 0x20, 0x40, 0x90,      # jsr longone     (too long)
                 0x20, 0x50, 0x90,      # jsr tester      (tests a pin)
                 0x20, 0x60, 0x90,      # jsr named       (labelled leaf)
                 0xb2, 0x10])           # jmp [0x10]      (computed)
    put(0x9000, [0x0f, P1, 0x60])                       # seb 0,P1 ; rts
    put(0x9010, [0x2f, P1, 0xa2, 0x05, 0xca, 0xd0, 0xfd,
                 0x3f, P1, 0x60])                       # seb 1 ; loop ; clb 1
    put(0x9020, [0x20, 0x00, 0x90, 0x60])               # jsr cs_on ; rts
    put(0x9030, [0xf0, 0x02, 0x0f, P1, 0x1f, P1, 0x60]) # beq +2 ; seb ; clb
    put(0x9040, [0xea] * 8 + [0x0f, P1, 0x60])          # 8 nops ; seb ; rts
    put(0x9050, [0x87, P1, 0x00, 0x0f, P1, 0x60])       # bbs 4,P1 ; seb ; rts
    put(0x9060, [0x1f, P1, 0x60])                       # clb 0,P1 ; rts
    for v in range(0xFFF4, 0x10000, 2):
        rom[v], rom[v + 1] = 0x00, 0x80
    return bytes(rom)


def _build(extra_control=""):
    rom = _image()
    cf = control.parse(CONTROL + extra_control)
    memory, symtab = command.build_disassembly(
        rom, "M50734", 0, **command.control_args(cf, bytearray(rom)))
    smap = command.build_signal_map(cf, "M50734")
    accs = access.classify(memory, smap)
    return memory, symtab, smap, accs


class LeafSummaryTests(unittest.TestCase):
    def setUp(self):
        self.memory, _, _, self.accs = _build()
        self.summaries = effects.leaf_summaries(self.memory, self.accs)

    def test_qualifying_leaves(self):
        self.assertEqual(sorted(self.summaries), [0x9000, 0x9010, 0x9060])

    def test_effects_in_order(self):
        self.assertEqual([a.text for a in self.summaries[0x9010]],
                         ["SK = 1", "SK = 0"])

    def test_non_leaves_excluded(self):
        for addr in (0x9020, 0x9030, 0x9040, 0x9050):
            self.assertNotIn(addr, self.summaries)

    def test_call_site_annotations(self):
        notes = access.listing_annotations(self.memory, self.accs)
        self.assertEqual(notes[0x8000], "-> CS = 1 (asserted)")
        self.assertEqual(notes[0x8003], "-> SK = 1; SK = 0")
        self.assertEqual(notes[0x9020], "-> CS = 1 (asserted)")
        self.assertNotIn(0x8006, notes)        # call to the non-leaf wrapper
        self.assertNotIn(0x8009, notes)

    def test_suggested_names(self):
        self.assertEqual(effects.suggested_name(self.summaries[0x9000]),
                         "cs_set")
        self.assertEqual(effects.suggested_name(self.summaries[0x9010]),
                         "sk_pulse")


class ReachTests(unittest.TestCase):
    def test_reach_over_call_graph(self):
        routines = [
            {"name": "a", "called_by": [{"name": "b"}]},
            {"name": "b", "called_by": [{"name": "c"}, {"name": "b"}]},
            {"name": "c", "called_by": []},
            {"name": "d", "called_by": [{"name": "c"}]},
        ]
        self.assertEqual(effects.reach(routines, {"S": {"a"}}),
                         {"S": ["b", "c"]})


class ReportSectionTests(unittest.TestCase):
    def setUp(self):
        memory, symtab, smap, accs = _build('label 0x9060 cs_off_named\n')
        self.model = report.build_model(memory, symtab, 0, 0x10000, "M50734",
                                        signal_map=smap, accesses=accs)
        self.routines = {r["name"]: r for r in self.model["routines"]}
        self.sigs = {s["name"]: s for s in self.model["signals"]}
        self.text = report.format_signals(self.model)

    def test_routine_effect_and_suggestion(self):
        r = self.routines["sub_9000"]
        self.assertEqual(r["effect"], ["CS = 1 (asserted)"])
        self.assertEqual(r["suggested_name"], "cs_set")
        self.assertEqual(r["group_primitive"], "bus")

    def test_named_routine_gets_no_suggestion(self):
        r = self.routines["cs_off_named"]
        self.assertEqual(r["effect"], ["CS = 0 (not asserted)"])
        self.assertNotIn("suggested_name", r)

    def test_written_by_and_reach(self):
        cs = self.sigs["CS"]
        self.assertEqual(cs["written_by"],
                         ["cs_off_named", "sub_9000", "sub_9030", "sub_9040",
                          "sub_9050"])
        self.assertIn("sub_9020", cs["reached_from"])
        self.assertNotIn("written_by", self.sigs["DO"])

    def test_text_sections(self):
        self.assertIn("; 3 leaf routine(s) with fixed signal effects",
                      self.text)
        self.assertIn(";   sub_9010             -> SK = 1; SK = 0   "
                      "[suggested name: sk_pulse]", self.text)
        self.assertIn("; routines touching only group bus:", self.text)
        self.assertIn("lower bound", self.text)
        self.assertIn("  reached from ", self.text)


class ListingTests(unittest.TestCase):
    @asmchain.requires_as740
    def test_call_site_annotations_reassemble(self):
        rom = _image()
        top = rom[0x8000:]
        cf = control.parse(CONTROL)
        listing = asmchain.assert_reassembles(top, device="M50734", control=cf)
        self.assertIn("-> SK = 1; SK = 0", listing)


if __name__ == "__main__":
    unittest.main()
