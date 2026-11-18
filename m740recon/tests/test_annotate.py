"""Tests for annotations (annotate.py) and several ROM files on the command
line.  Synthetic images."""

import io
import os
import shutil
import sys
import tempfile
import unittest

from m740recon import annotate, command
from m740recon.devices import Devices
from m740recon.tests import test_detect


def _lcd_image():
    rom = bytearray(b"\xff" * 0x10000)
    code = []
    for cmd in (0x38, 0x0C, 0x06, 0x01):
        code += [0xA9, cmd, 0x8D, 0x00, 0x42]        # lda #cmd / sta $4200
    code += [0xAD, 0x00, 0x03, 0x8D, 0x00, 0x03,     # lda $0300 / sta $0300 (RAM)
             0xAD, 0x01, 0x03, 0x8D, 0x01, 0x03,     # lda $0301 / sta $0301
             0xAD, 0x00, 0x41,                       # lda $4100 (input)
             0x60]
    rom[0x8000:0x8000 + len(code)] = bytes(code)
    rom[0xFFFE], rom[0xFFFF] = 0x00, 0x80
    return bytes(rom)


def _glyphs(n):
    """n bytes of dot-matrix-like columns: shapes changing a dot or two per
    column, with blank columns between characters."""
    shapes = [0x00, 0x00, 0x10, 0x18, 0x1C, 0x18, 0x10, 0x00,      # a wedge
              0x00, 0x00, 0x08, 0x08, 0x0C, 0x08, 0x08, 0x00]      # a bar
    return bytes(shapes[i % len(shapes)] for i in range(n))


class MemoryMapTests(unittest.TestCase):
    def test_ram_inputs_outputs_and_lcd(self):
        mem, _ = command.build_disassembly(_lcd_image(), "M50734", 0)
        regions, lcd = annotate.memory_map(mem, 0x8000, 0x10000)
        kinds = {r.start: r.kind for r in regions}
        self.assertEqual(kinds[0x0300], "ram")
        self.assertEqual(kinds[0x4100], "in")
        self.assertEqual(kinds[0x4200], "out")
        self.assertEqual(lcd, [(0x4200, [0x01, 0x06, 0x0C, 0x38])])


class FontTests(unittest.TestCase):
    def test_glyph_block_found_and_code_excluded(self):
        rom = bytearray(_lcd_image())
        rom[0x9000:0x9C00] = _glyphs(0xC00)
        mem, _ = command.build_disassembly(bytes(rom), "M50734", 0)
        regions = annotate.fonts(mem, 0x8000, 0x10000)
        self.assertEqual(len(regions), 1)
        self.assertLessEqual(regions[0].start, 0x9000)
        self.assertGreaterEqual(regions[0].end, 0x9B00)
        # nothing claimed where code was traced
        self.assertTrue(all(r.start >= 0x8100 for r in regions))


class TextTests(unittest.TestCase):
    def _texts(self, blobs):
        rom = bytearray(_lcd_image())
        at = 0xA000
        for b in blobs:
            rom[at:at + len(b)] = b
            at += len(b) + 4
        mem, _ = command.build_disassembly(bytes(rom), "M50734", 0)
        return [r.note for r in annotate.text(mem, 0x8000, 0x10000)]

    def test_words_are_text(self):
        self.assertEqual(self._texts([b"VER 1.34 TEST PRINT"]), ["VER 1.34 TEST PRINT"])

    def test_tables_and_noise_are_not(self):
        self.assertEqual(self._texts([b"LMNOPQRS", b"qivodUSl{", b"(8HXhx"]), [])

    def test_vectors_are_never_text(self):
        rom = bytearray(_lcd_image())
        rom[0xFFF4:0xFFFE] = b"PFPeIWP_P0"            # printable vector words
        mem, _ = command.build_disassembly(bytes(rom), "M50734", 0)
        self.assertFalse([r for r in annotate.text(mem, 0x8000, 0x10000) if r.end > 0xFFF4])


def _cli(args, files):
    d = tempfile.mkdtemp()
    try:
        paths = []
        for name, data in files:
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(data)
            paths.append(p)
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr, sys.argv
        sys.stdout, sys.stderr, sys.argv = out, err, ["m740recon"] + list(args) + paths
        code = 0
        try:
            command.main()
        except SystemExit as e:
            code = e.code
        finally:
            sys.stdout, sys.stderr, sys.argv = old
        return code, out.getvalue(), err.getvalue()
    finally:
        shutil.rmtree(d, True)


class MultiFileTests(unittest.TestCase):
    def _halves(self):
        vt = Devices["M50734"]["vector_table"]
        low, _ = test_detect._program(0x4000, 0x4000)
        high, _ = test_detect._program(0xC000, 0x4000, vectors={v: 0xC000 for v in vt})
        return low, high

    def test_two_files_placed_by_their_code(self):
        low, high = self._halves()
        code, out, err = _cli(["-m", "M50734"], [("low.bin", low), ("high.bin", high)])
        self.assertEqual(code, 0, err)
        self.assertIn("; file    low.bin at 0x4000-0x7fff", out)
        self.assertIn("; file    high.bin at 0xc000-0xffff", out)
        self.assertIn(".org 0x4000", out)

    def test_overlapping_files_stop_with_segment_lines(self):
        low, high = self._halves()
        code, out, err = _cli(["-m", "M50734"], [("a.bin", high), ("b.bin", high)])
        self.assertEqual(code, 2)
        self.assertIn("overlaps", err)
        self.assertIn("segment NAME", err)

    def test_suggest_offers_a_segment_per_file(self):
        low, high = self._halves()
        code, out, err = _cli(["-m", "M50734", "--suggest"], [("low.bin", low), ("high.bin", high)])
        self.assertIn("# segment rom1 0x4000 0x08000", out)
        self.assertIn("# segment rom2 0xc000 0x10000", out)


if __name__ == "__main__":
    unittest.main()
