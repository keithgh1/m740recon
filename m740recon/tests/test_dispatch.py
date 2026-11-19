"""Tests for proven dispatch tables (dispatch.py) as decoded by
build_disassembly's default run.  All images are synthetic."""

import unittest

from m740recon import command, control
from m740recon.tests import asmchain


def _search_image(handlers=((0x41, 0x9000), (0x42, 0x9010), (0x0D, 0x9020)),
                  table=0x8100):
    """A dispatcher that hands a [key, lo, hi] table to a search routine,
    then jumps through the pointer the search leaves in $60/$61."""
    rom = bytearray(b"\xff" * 0x10000)
    rom[0x8000:0x800e] = bytes([
        0x3C, table & 0xFF, 0x60,          # ldm #lo,$60
        0x3C, table >> 8, 0x61,            # ldm #hi,$61
        0x20, 0x00, 0x88,                  # jsr search ($8800)
        0x90, 0x01,                        # bcc +1 (found: skip the clc)
        0x18,                              # clc
        0xB2, 0x60,                        # jmp [$60]
    ])
    rom[0x8800] = 0x60                     # search: rts (behaviour irrelevant)
    a = table
    for key, h in handlers:
        rom[a:a + 3] = bytes([key, h & 0xFF, h >> 8])
        a += 3
    rom[a] = 0x00                          # terminator key
    for n, (_, h) in enumerate(handlers):
        if 0x8000 <= h:
            rom[h:h + 3] = bytes([0xA9, n, 0x60])      # lda #n ; rts
    rom[0xFFFE], rom[0xFFFF] = 0x00, 0x80
    return bytes(rom)


def _loop_image():
    """ldx #0 / L: txa / asl / tay / lda T,y / sta $40 / lda T+1,y /
    sta $41 / jsr [$40] / inx / cpx #3 / bcc L / rts, T = 3 pointers."""
    rom = bytearray(b"\xff" * 0x10000)
    code = [0xA2, 0x00,                    # 8000 ldx #0
            0x8A, 0x0A, 0xA8,              # 8002 L: txa / asl a / tay
            0xB9, 0x00, 0x81,              # 8005 lda $8100,y
            0x85, 0x40,                    # sta $40
            0xB9, 0x01, 0x81,              # lda $8101,y
            0x85, 0x41,                    # sta $41
            0x02, 0x40,                    # jsr [$40]
            0xE8, 0xE0, 0x03,              # inx / cpx #3
            0x90, 0x00,                    # bcc L (patched below)
            0x60]                          # rts
    rom[0x8000:0x8000 + len(code)] = bytes(code)
    bcc = 0x8000 + code.index(0x90)
    rom[bcc + 1] = (0x8002 - (bcc + 2)) & 0xFF
    for n, h in enumerate((0x9000, 0x9010, 0x9020)):
        rom[0x8100 + 2 * n:0x8102 + 2 * n] = bytes([h & 0xFF, h >> 8])
        rom[h:h + 3] = bytes([0xA9, n, 0x60])
    rom[0xFFFE], rom[0xFFFF] = 0x00, 0x80
    return bytes(rom)


def _names(symtab):
    return {a: s.name for a, s in symtab.items() if not s.weak}


class SearchTableTests(unittest.TestCase):
    def test_handlers_decoded_and_named_from_keys(self):
        mem, sym = command.build_disassembly(_search_image(), "M50734", 0)
        for h in (0x9000, 0x9010, 0x9020):
            self.assertTrue(mem.is_instruction_start(h), hex(h))
        names = _names(sym)
        self.assertEqual(names[0x9000], "tbl_8100_A")
        self.assertEqual(names[0x9010], "tbl_8100_B")
        self.assertEqual(names[0x9020], "tbl_8100_CR")
        self.assertTrue(mem.is_vector_start(0x8101))           # pointers as .word
        self.assertTrue(mem.is_data(0x8100))                   # keys as data
        [found] = mem.dispatch_tables
        self.assertEqual((found.kind, found.site, found.records), ("search", 0x800C, 3))

    def test_off_switch(self):
        mem, _ = command.build_disassembly(_search_image(), "M50734", 0, proven=False)
        self.assertFalse(mem.is_instruction_start(0x9000))
        self.assertEqual(mem.dispatch_tables, [])

    def test_user_names_win(self):
        cf = control.parse("label 0x9010 my_handler\n")
        img = _search_image()
        mem, sym = command.build_disassembly(img, "M50734", 0, **command.control_args(cf, img))
        self.assertEqual(_names(sym)[0x9010], "my_handler")
        self.assertEqual(_names(sym)[0x9000], "tbl_8100_A")

    def test_targets_in_a_missing_rom_are_allowed_but_not_traced(self):
        # two handlers here, one in a ROM that was not given (0x5000)
        img = _search_image(handlers=((0x41, 0x9000), (0x42, 0x5000), (0x43, 0x9010)))
        mem, _ = command.build_disassembly(img[0x8000:], "M50734", 0x8000)
        self.assertTrue(mem.is_instruction_start(0x9000))
        self.assertTrue(mem.is_vector_start(0x8104))           # the external pointer
        self.assertFalse(mem.is_instruction_start(0x5000))

    def test_mostly_external_tables_are_rejected(self):
        img = _search_image(handlers=((0x41, 0x5000), (0x42, 0x5100), (0x43, 0x9010)))
        mem, _ = command.build_disassembly(img[0x8000:], "M50734", 0x8000)
        self.assertEqual(mem.dispatch_tables, [])

    @asmchain.requires_as740
    def test_reassembles(self):
        asmchain.assert_reassembles(_search_image(), device="M50734", start_address=0)


class LoopTableTests(unittest.TestCase):
    def test_counted_loop_gives_exact_table(self):
        mem, sym = command.build_disassembly(_loop_image(), "M50734", 0)
        for h in (0x9000, 0x9010, 0x9020):
            self.assertTrue(mem.is_instruction_start(h), hex(h))
        [found] = mem.dispatch_tables
        self.assertEqual((found.kind, found.records, found.table.stride), ("loop", 3, 2))
        self.assertFalse(mem.is_vector_start(0x8106))          # no 4th entry
        self.assertEqual(_names(sym)[0x9010], "tbl_8100_1")

    @asmchain.requires_as740
    def test_reassembles(self):
        asmchain.assert_reassembles(_loop_image(), device="M50734", start_address=0)


if __name__ == "__main__":
    unittest.main()
