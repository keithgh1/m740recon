"""Tests for declared pointers, second address spaces and read/write-split
signals (Phase 8)."""

import unittest

from m740recon import access, command, control, report
from m740recon.tests import asmchain

CONTROL = (
    "device M50734\n"
    'pointer 0xae 0x4000 space=dme "external register base"\n'
    "pointer 0x50 0x0300\n"
    "bit 0x4000.7   RDY  space=dme access=read high=\"byte waiting\"\n"
    "bit 0x4000.0-7 DATA space=dme access=write\n"
    "bit 0x4002.0 EN  space=dme access=write\n"
    "bit 0x4002.2 ACK space=dme access=write\n"
    "bit 0x4003.0 L0  space=dme access=write\n"
    "bit 0x0300.1 LATCH\n"
)


def _image():
    rom = bytearray(0x10000)

    def put(addr, data):
        rom[addr:addr + len(data)] = bytes(data)

    calls = [0x8100, 0x8110, 0x8120, 0x8130, 0x8140, 0x8144, 0x8150, 0x8160,
             0x8170, 0x8180, 0x8188]
    code = []
    for c in calls:
        code += [0x20, c & 0xff, c >> 8]
    code += [0x60]
    put(0x8000, code)
    # A: DME on, Y=0, read reg0, test bit 7
    put(0x8100, [0xaf, 0xf5, 0xa0, 0x00, 0xb1, 0xae, 0xe3, 0x00, 0x60])
    # B: enable unknown, Y=2, RMW set bit 2 of reg2
    put(0x8110, [0xa0, 0x02, 0xb1, 0xae, 0x4b, 0x91, 0xae, 0x60])
    # C: DME off, Y=0, store through the pointer
    put(0x8120, [0xbf, 0xf5, 0xa0, 0x00, 0x91, 0xae, 0x60])
    # D: DME on, Y from memory (unknown), store
    put(0x8130, [0xaf, 0xf5, 0xa4, 0x10, 0x91, 0xae, 0x60])
    # R1 @8140: ldy #2 ; bra J      R2 @8144: ldy #3 ; J @8146: read
    put(0x8140, [0xa0, 0x02, 0x80, 0x02,
                 0xa0, 0x03,
                 0xaf, 0xf5, 0xb1, 0xae, 0x60])
    # F: DME on, [zp,x] does not reach the dme space
    put(0x8150, [0xaf, 0xf5, 0xa2, 0x00, 0xa1, 0xae, 0x60])
    # G: program-space pointer, masked read of LATCH
    put(0x8160, [0xa0, 0x00, 0xb1, 0x50, 0x29, 0x02, 0x60])
    # H: absolute 0x4000 is program space
    put(0x8170, [0xad, 0x00, 0x40, 0x60])
    # K: ldy #2 ; bra J2 ...  J2 @8188 is also called directly
    put(0x8180, [0xa0, 0x02, 0x80, 0x04, 0xea, 0xea, 0xea, 0xea,
                 0xaf, 0xf5, 0xb1, 0xae, 0x60])
    for v in range(0xFFF4, 0x10000, 2):
        rom[v], rom[v + 1] = 0x00, 0x80
    return bytes(rom)


def _run(device="M50734", text=CONTROL):
    rom = _image()
    cf = control.parse(text)
    memory, symtab = command.build_disassembly(rom, device, 0)
    smap = command.build_signal_map(cf, device)
    sites = []
    accs = command.signal_accesses(memory, smap, device, sites)
    return memory, symtab, smap, accs, {s.site: s for s in sites}


class ParseTests(unittest.TestCase):
    def test_pointer_and_options(self):
        cf = control.parse(CONTROL)
        p = cf.pointers[0]
        self.assertEqual((p.addr, p.target, p.space, p.comment),
                         (0xae, 0x4000, "dme", "external register base"))
        rdy = cf.signals[0]
        self.assertEqual((rdy.space, rdy.access), ("dme", "read"))

    def _bad(self, text, fragment):
        with self.assertRaises(control.ControlError) as ctx:
            control.parse(text)
        self.assertIn(fragment, str(ctx.exception))

    def test_pointer_errors(self):
        self._bad("pointer 0x100 0x4000\n", "zero-page")
        self._bad("pointer 0xae\n", "pointer ADDR TARGET")
        self._bad("pointer 0xae 0x10000\n", "out of range")
        self._bad("pointer 0xae nope\n", "bad pointer target")
        self._bad("pointer 0xae 0x4000 speed=1\n", "unknown pointer option")
        self._bad("pointer 0xae 0x4000 space=9x\n", "bad space name")

    def test_bit_option_errors(self):
        self._bad("bit 0x40.1 A access=both\n", "access= must be")
        self._bad("bit 0x40.1 A space=1\n", "bad space name")
        self._bad("pin P0.1 A space=dme\n", "unknown pin option")

    def test_map_errors(self):
        def bad(text, fragment):
            with self.assertRaises(control.ControlError) as ctx:
                command.build_signal_map(control.parse(text), "M50734")
            self.assertIn(fragment, str(ctx.exception))
        bad("pointer 0xae 0x4000\npointer 0xae 0x5000\n", "already declared")
        bad("pointer nolabel 0x4000\n", "not a known zero-page label")
        bad("bit 0x40.1 A access=read\nbit 0x40.1 B\n", "overlaps A")
        bad("bit 0x4000.1 A space=dme\nbit 0x4000.1 B space=dme\n", "overlaps")

    def test_access_split_and_space_separation(self):
        smap = command.build_signal_map(control.parse(
            "bit 0x40.1 R access=read\nbit 0x40.1 W access=write\n"
            "bit 0x4000.0 P\nbit 0x4000.0 D space=dme\n"), "M50734")
        self.assertEqual(smap.at(0x40, 1, op="read").name, "R")
        self.assertEqual(smap.at(0x40, 1, op="write").name, "W")
        self.assertEqual(smap.at(0x4000, 0).name, "P")
        self.assertEqual(smap.at(0x4000, 0, "dme").name, "D")
        self.assertEqual(smap.by_name["D"].loc, "dme:0x4000.0")

    def test_label_pointer(self):
        smap = command.build_signal_map(control.parse(
            "label 0xae ga_ptr\npointer ga_ptr 0x4000\n"), "M50734")
        self.assertIn(0xae, smap.pointers)


class PointerResolutionTests(unittest.TestCase):
    def setUp(self):
        _, _, _, self.accs, self.sites = _run()
        self.notes = None

    def facts(self, site):
        return [(a.signal.name, a.kind, a.level, a.confidence)
                for a in self.accs if a.address == site]

    def test_enabled_read_and_bit_test(self):
        ps = self.sites[0x8104]
        self.assertEqual((ps.state, ps.locs, ps.op),
                         ("on", [("dme", 0x4000)], "read"))
        self.assertEqual(self.facts(0x8106), [("RDY", "test", 1, "derived")])
        self.assertEqual(self.facts(0x8104), [])     # refined by the test

    def test_unknown_enable_is_assumed(self):
        ps = self.sites[0x8115]
        self.assertEqual(ps.state, "assumed")
        self.assertEqual(self.facts(0x8115), [("ACK", "set", 1, "assumed")])

    def test_disabled_space_goes_to_program_space(self):
        ps = self.sites[0x8124]
        self.assertEqual((ps.state, ps.locs), ("off", [(None, 0x4000)]))
        self.assertEqual(self.facts(0x8124), [])

    def test_unknown_index(self):
        ps = self.sites[0x8134]
        self.assertEqual((ps.locs, ps.index), (None, None))

    def test_y_set_carried_into_shared_access(self):
        ps = self.sites[0x8148]
        self.assertEqual(ps.locs, [("dme", 0x4002), ("dme", 0x4003)])
        self.assertEqual(ps.index, [2, 3])

    def test_no_y_set_into_call_target(self):
        ps = self.sites[0x818a]
        self.assertIsNone(ps.locs)

    def test_indirect_x_does_not_reach_space(self):
        ps = self.sites[0x8154]
        self.assertEqual((ps.state, ps.locs), ("mode", [(None, 0x4000)]))

    def test_program_space_pointer(self):
        ps = self.sites[0x8162]
        self.assertEqual((ps.state, ps.locs), ("program", [(None, 0x0300)]))
        self.assertEqual(self.facts(0x8164), [("LATCH", "read", None,
                                               "derived")])

    def test_absolute_never_reaches_space(self):
        self.assertEqual(self.facts(0x8170), [])

    def test_device_without_space_metadata(self):
        _, _, _, _, sites = _run(device="M3886",
                                 text=CONTROL.replace("M50734", "M3886"))
        self.assertEqual(sites[0x8104].state, "declared")
        self.assertEqual(sites[0x8154].state, "declared")


class AnnotationTests(unittest.TestCase):
    def setUp(self):
        memory, _, _, accs, sites = _run()
        self.notes = access.listing_annotations(memory, accs,
                                                list(sites.values()))

    def test_tags(self):
        self.assertEqual(self.notes[0x8104], "[dme:0x4000] reads")
        self.assertEqual(self.notes[0x8115], "[dme:0x4002?] ACK = 1")
        self.assertEqual(self.notes[0x8124],
                         "[0x4000, dme off: program space] writes")
        self.assertEqual(self.notes[0x8134],
                         "[dme:0x4000+Y, Y unknown] writes")
        self.assertEqual(self.notes[0x8148],
                         "[dme:0x4002|0x4003 Y=2,3] reads")
        self.assertEqual(self.notes[0x8154],
                         "[0x4000, mode does not reach dme: program space] "
                         "reads")

    @asmchain.requires_as740
    def test_reassembles_with_pointer_annotations(self):
        rom = _image()
        cf = control.parse(CONTROL)
        listing = asmchain.assert_reassembles(rom[0x8000:], device="M50734",
                                              control=cf)
        self.assertIn("[dme:0x4002|0x4003 Y=2,3]", listing)


class ReportTests(unittest.TestCase):
    def setUp(self):
        memory, symtab, smap, accs, sites = _run()
        self.model = report.build_model(memory, symtab, 0, 0x10000, "M50734",
                                        signal_map=smap, accesses=accs,
                                        pointer_sites=list(sites.values()))

    def test_pointer_section(self):
        ptrs = {p["address"]: p for p in self.model["pointers"]}
        ga = ptrs["0xae"]
        self.assertEqual((ga["target"], ga["space"]), ("0x4000", "dme"))
        states = {a["site"]: a["state"] for a in ga["accesses"]}
        self.assertEqual(states["0x8124"], "off")
        self.assertEqual(states["0x8148"], "on")
        self.assertEqual(ptrs["0x50"]["space"], None)

    def test_text_summary(self):
        text = report.format_signals(self.model)
        self.assertIn("; pointer 0xae -> dme:0x4000  external register base",
                      text)
        self.assertIn("index unknown at: 0x8134, 0x818a", text)
        self.assertIn("to the program space at: 0x8124, 0x8154", text)

    def test_signal_locations_show_space(self):
        sigs = {s["name"]: s for s in self.model["signals"]}
        self.assertEqual(sigs["ACK"]["location"], "dme:0x4002.2")


if __name__ == "__main__":
    unittest.main()
