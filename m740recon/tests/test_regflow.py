"""Tests for whole-register and masked signal accesses (regflow.py)."""

import unittest

from m740recon import access, command, control
from m740recon.tests import asmchain

CONTROL = (
    "device M50734\n"
    "pin P1.0 CS out active=high\n"
    "pin P1.1 SK out\n"
    "pin P1.4 DO in\n"
    "pin P2.0-3 PH out\n"
    "pin P3.3-7 BTN in active=low\n"
    "bit 0x0300.0 EXT\n"
)

P1, P2, P3 = 0xf3, 0xf0, 0xee


def _image(code, extra=None):
    """64K M50734 image: `code` at 0x8000, every vector -> 0x8000."""
    rom = bytearray(0x10000)
    rom[0x8000:0x8000 + len(code)] = bytes(code)
    for addr, data in (extra or {}).items():
        rom[addr:addr + len(data)] = bytes(data)
    for v in range(0xFFF4, 0x10000, 2):
        rom[v], rom[v + 1] = 0x00, 0x80
    return bytes(rom)


def _accesses(code, extra=None):
    rom = _image(code, extra)
    cf = control.parse(CONTROL)
    memory, _ = command.build_disassembly(rom, "M50734", 0)
    smap = command.build_signal_map(cf, "M50734")
    return [a for a in access.classify(memory, smap)], memory, smap


def _facts(code, extra=None):
    accs, _, _ = _accesses(code, extra)
    return [(a.address, a.signal.name, a.kind, a.level, a.scope)
            for a in accs]


class WriteTests(unittest.TestCase):
    def test_ldm_is_exact_write_skipping_inputs(self):
        accs, _, _ = _accesses([0x3c, 0x03, P1, 0x60])   # ldm #0x03,P1
        self.assertEqual([(a.signal.name, a.kind, a.level, a.confidence)
                          for a in accs],
                         [("CS", "write", 1, "exact"),
                          ("SK", "write", 1, "exact")])

    def test_constant_store(self):
        self.assertEqual(_facts([0xa9, 0x05,           # lda #0x05
                                 0x85, P1,             # sta P1
                                 0x60]),
                         [(0x8002, "CS", "write", 1, "register"),
                          (0x8002, "SK", "write", 0, "register")])

    def test_field_write_value(self):
        self.assertEqual(_facts([0xa9, 0x96, 0x85, P2, 0x60]),
                         [(0x8002, "PH", "write", 6, "register")])

    def test_stx_with_known_x(self):
        self.assertEqual(_facts([0xa2, 0x02, 0x86, P1, 0x60]),
                         [(0x8002, "CS", "write", 0, "register"),
                          (0x8002, "SK", "write", 1, "register")])

    def test_unknown_value_store(self):
        self.assertEqual(_facts([0xa5, 0x50, 0x85, P1, 0x60]),
                         [(0x8002, "CS", "write", None, "register"),
                          (0x8002, "SK", "write", None, "register")])

    def test_absolute_address_signal(self):
        self.assertEqual(_facts([0xa9, 0x01, 0x8d, 0x00, 0x03, 0x60]),
                         [(0x8002, "EXT", "write", 1, "register")])


class ReadModifyWriteTests(unittest.TestCase):
    def test_ora_sets_one_bit(self):
        self.assertEqual(_facts([0xa5, P1, 0x09, 0x01, 0x85, P1, 0x60]),
                         [(0x8004, "CS", "set", 1, "mask")])

    def test_and_clears_one_bit(self):
        self.assertEqual(_facts([0xa5, P1, 0x29, 0xfe, 0x85, P1, 0x60]),
                         [(0x8004, "CS", "clear", 0, "mask")])

    def test_eor_toggles(self):
        self.assertEqual(_facts([0xa5, P1, 0x49, 0x02, 0x85, P1, 0x60]),
                         [(0x8004, "SK", "toggle", None, "mask")])

    def test_field_cleared_by_mask(self):
        self.assertEqual(_facts([0xa5, P2, 0x29, 0xf0, 0x85, P2, 0x60]),
                         [(0x8004, "PH", "write", 0, "mask")])

    def test_store_to_other_register_is_plain_copy(self):
        # lda P1 ; ora #1 ; sta P2: P2's bits are partly unknown
        self.assertEqual(_facts([0xa5, P1, 0x09, 0x01, 0x85, P2, 0x60]),
                         [(0x8000, "CS", "read", None, "register"),
                          (0x8000, "SK", "read", None, "register"),
                          (0x8000, "DO", "read", None, "register"),
                          (0x8004, "PH", "write", None, "register")])


class ReadTests(unittest.TestCase):
    def test_masked_read_attributed_at_mask(self):
        self.assertEqual(_facts([0xa5, P3, 0x29, 0xf8, 0x60]),
                         [(0x8002, "BTN", "read", None, "mask")])

    def test_accumulator_bit_test_after_load(self):
        self.assertEqual(_facts([0xa5, P1, 0x83, 0x00, 0x60]),  # bbs 4,a,+0
                         [(0x8002, "DO", "test", 1, "bit")])

    def test_inverted_bit_test(self):
        # lda P1 ; eor #0x10 ; bbs 4,a  -> branch when DO is 0
        self.assertEqual(_facts([0xa5, P1, 0x49, 0x10, 0x83, 0x00, 0x60]),
                         [(0x8004, "DO", "test", 0, "bit")])

    def test_unrefined_load_reads_everything(self):
        self.assertEqual(_facts([0xa5, P1, 0x85, 0x50, 0x60]),
                         [(0x8000, "CS", "read", None, "register"),
                          (0x8000, "SK", "read", None, "register"),
                          (0x8000, "DO", "read", None, "register")])

    def test_compare_and_tst_read(self):
        facts = _facts([0xc5, P1, 0x64, P1, 0x60])          # cmp P1 ; tst P1
        self.assertEqual({(a, k) for a, _, k, _, _ in facts},
                         {(0x8000, "read"), (0x8002, "read")})

    def test_absolute_masked_read(self):
        self.assertEqual(_facts([0xad, 0x00, 0x03, 0x29, 0x01, 0x60]),
                         [(0x8003, "EXT", "read", None, "mask")])


class OtherWriteTests(unittest.TestCase):
    def test_com_toggles_and_inc_writes_unknown(self):
        facts = _facts([0x44, P1, 0xe6, P1, 0x60])
        self.assertEqual([(a, n, k) for a, n, k, _, _ in facts],
                         [(0x8000, "CS", "toggle"), (0x8000, "SK", "toggle"),
                          (0x8002, "CS", "write"), (0x8002, "SK", "write")])


class SoundnessTests(unittest.TestCase):
    def test_call_between_load_and_mask(self):
        # lda P3 ; jsr 0x9000 ; and #0xf8 ; rts   (callee: rts)
        facts = _facts([0xa5, P3, 0x20, 0x00, 0x90, 0x29, 0xf8, 0x60],
                       extra={0x9000: [0x60]})
        self.assertEqual([(a, k, s) for a, _, k, _, s in facts],
                         [(0x8000, "read", "register")])

    def test_block_leader_between_load_and_store(self):
        # lda P1 ; ora #1 ; bra +0 ; [leader] sta P1 ; rts
        facts = _facts([0xa5, P1, 0x09, 0x01, 0x80, 0x00, 0x85, P1, 0x60])
        kinds = [(a, n, k, lvl) for a, n, k, lvl, _ in facts]
        self.assertIn((0x8006, "CS", "write", None), kinds)
        self.assertNotIn((0x8006, "CS", "set", 1), kinds)

    def test_branch_target_inside_sequence(self):
        # lda P1 ; ora #1 ; sta P1 where 0x8002 is also a branch target
        code = [0xa5, P1,          # 8000 lda P1
                0x09, 0x01,        # 8002 ora #1   <- target of 800a
                0x85, P1,          # 8004 sta P1
                0x80, 0x02,        # 8006 bra 800a
                0x00, 0x00,
                0xd0, 0xf6,        # 800a bne 8002
                0x60]
        facts = _facts(code)
        self.assertNotIn((0x8004, "CS", "set", 1, "mask"), facts)

    def test_t_flag_stops_tracking(self):
        # set ; lda P3 ; and #0xf8 ; sta P1 ; clt ; rts
        facts = _facts([0x32, 0xa5, P3, 0x29, 0xf8, 0x85, P1, 0x12, 0x60])
        self.assertIn((0x8001, "BTN", "read", None, "register"), facts)
        self.assertNotIn((0x8003, "BTN", "read", None, "mask"), facts)
        self.assertIn((0x8005, "CS", "write", None, "register"), facts)

    def test_no_signals_no_accesses(self):
        rom = _image([0xa9, 0x05, 0x85, P1, 0x60])
        memory, _ = command.build_disassembly(rom, "M50734", 0)
        smap = command.build_signal_map(control.parse("device M50734\n"),
                                        "M50734")
        self.assertEqual(access.classify(memory, smap), [])


class AnnotationGroupingTests(unittest.TestCase):
    def test_reads_and_unknown_writes_collapse(self):
        accs, _, _ = _accesses([0xa5, P1, 0x85, 0x50,      # read all of P1
                                0xa5, 0x50, 0x85, P1,      # unknown store
                                0x60])
        notes = access.annotations(accs)
        self.assertEqual(notes[0x8000], "reads CS, SK, DO")
        self.assertEqual(notes[0x8006], "writes CS, SK (value unknown)")

    def test_known_writes_listed(self):
        accs, _, _ = _accesses([0xa9, 0x01, 0x85, P1, 0x60])
        self.assertEqual(access.annotations(accs)[0x8002],
                         "CS = 1 (asserted); SK = 0")

    @asmchain.requires_as740
    def test_reassembles_with_register_annotations(self):
        rom = _image([0xa5, P3, 0x29, 0xf8, 0xa9, 0x05, 0x85, P1,
                      0xa5, P1, 0x09, 0x01, 0x85, P1, 0x60])
        top = rom[0x8000:]
        cf = control.parse(CONTROL)
        asmchain.assert_reassembles(top, device="M50734", control=cf)


if __name__ == "__main__":
    unittest.main()
