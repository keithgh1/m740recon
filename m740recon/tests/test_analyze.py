"""Tests for the value-tracking analyzer (the --analyze smart tracer)."""

import unittest

from m740recon import command
from m740recon.tests import asmchain, fixtures


def _img_reset(addr):
    rom = bytearray(0x10000)
    rom[0xFFFE] = addr & 0xFF
    rom[0xFFFF] = (addr >> 8) & 0xFF
    return rom


class JmpZpConstantTests(unittest.TestCase):
    def test_not_found_without_analyze(self):
        text = asmchain.disasm_text(fixtures.computed_jump_image(), "M50734", 0)
        self.assertNotIn("lda #0x42", text)

    def test_found_with_analyze(self):
        text = asmchain.disasm_text(fixtures.computed_jump_image(), "M50734", 0,
                                    analyze=True)
        self.assertIn("lda #0x42", text)       # handler decoded as code


class JmpAbsRomPointerTests(unittest.TestCase):
    def _image(self):
        rom = _img_reset(0x8000)
        rom[0x8000:0x8003] = bytes([0x6C, 0x10, 0x80])   # jmp [0x8010]
        rom[0x8010:0x8012] = bytes([0x00, 0x90])          # pointer -> 0x9000 (ROM)
        rom[0x9000:0x9003] = bytes([0xA9, 0x01, 0x60])    # lda #0x01 ; rts
        return bytes(rom)

    def test_found_with_analyze(self):
        text = asmchain.disasm_text(self._image(), "M50734", 0, analyze=True)
        self.assertIn("lda #0x01", text)

    def test_ram_pointer_not_trusted(self):
        # jmp through a pointer in RAM must NOT be resolved from the static image
        rom = _img_reset(0x8000)
        rom[0x8000:0x8003] = bytes([0x6C, 0x10, 0x00])   # jmp [0x0010]  (RAM)
        rom[0x9000:0x9003] = bytes([0xA9, 0x07, 0x60])
        # load at 0x8000 so readonly defaults to [0x8000, 0x10000): 0x0010 excluded
        text = asmchain.disasm_text(bytes(rom[0x8000:]), "M50734", 0x8000,
                                    analyze=True)
        self.assertNotIn("lda #0x07", text)


class SoundnessTests(unittest.TestCase):
    def test_analyze_only_adds_code(self):
        """Analysis may only turn unknown bytes into code; it must never remove
        or relocate an instruction the baseline already decoded."""
        image = fixtures.computed_jump_image()
        base, _ = command.build_disassembly(image, "M50734", 0, analyze=False)
        ana, _ = command.build_disassembly(image, "M50734", 0, analyze=True)
        base_starts = {a for a, _ in base.iter_instructions()}
        ana_starts = {a for a, _ in ana.iter_instructions()}
        self.assertTrue(base_starts < ana_starts)   # strictly more (handler found)
        ana_by_addr = dict(ana.iter_instructions())
        for addr, inst in base.iter_instructions():
            self.assertEqual(bytes(inst.all_bytes),
                             bytes(ana_by_addr[addr].all_bytes))


if __name__ == "__main__":
    unittest.main()
