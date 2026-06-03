"""Tests for cross-reference annotations and inline comments."""

import unittest

from m740dasm import control
from m740dasm.tests import asmchain


def _image():
    rom = bytearray(0x10000)
    # reset @ 0x8000: call 0x9000 twice, then rts
    rom[0x8000:0x8007] = bytes([0x20, 0x00, 0x90,    # jsr 0x9000
                                0x20, 0x00, 0x90,    # jsr 0x9000
                                0x60])               # rts
    rom[0x9000] = 0x60                                # sub @ 0x9000: rts
    rom[0xFFFE], rom[0xFFFF] = 0x00, 0x80
    return bytes(rom)


class XrefTests(unittest.TestCase):
    def test_no_xrefs_by_default(self):
        text = asmchain.disasm_text(_image(), "M50734", 0)
        self.assertNotIn("; xref:", text)

    def test_xrefs_listed_for_called_routine(self):
        text = asmchain.disasm_text(_image(), "M50734", 0, show_xrefs=True)
        self.assertIn("sub_9000:", text)
        self.assertIn("; xref:", text)
        # both call sites (0x8000 region) are referenced
        xref_lines = [l for l in text.splitlines() if "; xref:" in l]
        self.assertTrue(any("0x8003" in l for l in xref_lines),
                        "expected the second call site in an xref line")


class CommentTests(unittest.TestCase):
    def test_label_and_comment_rendered(self):
        cf = control.parse(
            'label 0x9000 myrtn "does a thing"\n'
            'comment 0x8000 "entry point"\n')
        text = asmchain.disasm_text(_image(), "M50734", 0, control=cf)
        self.assertIn("myrtn:", text)
        self.assertIn(";does a thing", text)      # label comment
        self.assertIn(";entry point", text)       # comment directive

    def test_no_comments_without_control(self):
        text = asmchain.disasm_text(_image(), "M50734", 0)
        self.assertNotIn("does a thing", text)


if __name__ == "__main__":
    unittest.main()
