"""Tests for auto jump-table discovery (--auto-tables)."""

import unittest

from m740dasm import command
from m740dasm.tests import asmchain


def _image():
    """A dispatcher that loads a pointer from a [lo,hi] table indexed by X and
    jumps through it; the handlers are reachable only via the table."""
    rom = bytearray(0x10000)
    rom[0x8000:0x800c] = bytes([
        0xBD, 0x00, 0x81,   # lda 0x8100,x   (table low byte)
        0x85, 0x10,         # sta 0x10
        0xBD, 0x01, 0x81,   # lda 0x8101,x   (table high byte)
        0x85, 0x11,         # sta 0x11
        0xB2, 0x10,         # jmp [0x10]
    ])
    rom[0x8100:0x8106] = bytes([0x00, 0x90,    # -> 0x9000
                                0x10, 0x90,    # -> 0x9010
                                0x00, 0x00])   # null: stops enumeration
    rom[0x9000:0x9003] = bytes([0xA9, 0x01, 0x60])   # handler 0: lda #0x01 ; rts
    rom[0x9010:0x9013] = bytes([0xA9, 0x02, 0x60])   # handler 1: lda #0x02 ; rts
    rom[0xFFFE], rom[0xFFFF] = 0x00, 0x80
    return bytes(rom)


class AutoTableTests(unittest.TestCase):
    def test_handlers_not_found_with_plain_analyze(self):
        # value tracking alone can't resolve a table-indexed jmp [zp]
        text = asmchain.disasm_text(_image(), "M50734", 0, analyze=True)
        self.assertNotIn("lda #0x01", text)
        self.assertNotIn("lda #0x02", text)

    def test_handlers_found_with_auto_tables(self):
        text = asmchain.disasm_text(_image(), "M50734", 0, discover_tables=True)
        self.assertIn("lda #0x01", text)        # both handlers decoded
        self.assertIn("lda #0x02", text)
        self.assertIn(".word lab_9000", text)   # table entries rendered as pointers
        self.assertIn(".word lab_9010", text)

    @asmchain.requires_as740
    def test_auto_tables_reassembles(self):
        asmchain.assert_reassembles(_image(), device="M50734", start_address=0,
                                    discover_tables=True)

    def test_auto_tables_only_adds_code(self):
        image = _image()
        base, _ = command.build_disassembly(image, "M50734", 0)
        disc, _ = command.build_disassembly(image, "M50734", 0,
                                            discover_tables=True)
        base_starts = {a for a, _ in base.iter_instructions()}
        disc_starts = {a for a, _ in disc.iter_instructions()}
        self.assertTrue(base_starts < disc_starts)


if __name__ == "__main__":
    unittest.main()
