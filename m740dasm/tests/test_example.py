"""Tests for the worked control-file example.

Two complementary guards keep docs/example.m740 from rotting:

  * test_matches_golden freezes the listing produced by every listing-affecting
    directive (label, entry, comment, range text/word/addr, addrtable) on the
    compact example_control_image fixture, so an incidental change to directive
    output shows up in review.  It uses a small top-loaded image -- the realistic
    docs/example.m740 uses `segment`, which would emit ~64K of filler (segment
    mode walks from 0x0000); segment image-building is covered by test_control.

  * test_example_doc_parses loads the shipped docs/example.m740 itself and checks
    its structure, so the documentation file cannot drift into invalid syntax or
    silently lose the directives it claims to demonstrate.

Regenerate the golden intentionally with:
    python -m m740dasm.tests.test_example --update
"""

import os
import sys
import unittest

from m740dasm import control
from m740dasm.tests import asmchain, fixtures

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden", "example_listing.asm")
DOC = os.path.join(HERE, "..", "..", "docs", "example.m740")


def _produce():
    cf = control.parse(fixtures.EXAMPLE_CONTROL)
    return asmchain.disasm_text(fixtures.example_control_image(),
                                device="M50734", start_address=0xffd0,
                                control=cf)


class ExampleGoldenTests(unittest.TestCase):
    def test_matches_golden(self):
        self.assertTrue(os.path.exists(GOLDEN), "golden missing; run --update")
        with open(GOLDEN, "r", newline="\n") as f:
            golden = f.read()
        self.assertEqual(_produce().splitlines(), golden.splitlines())


class ExampleDocTests(unittest.TestCase):
    """Structural guard on the shipped docs/example.m740."""

    def setUp(self):
        self.assertTrue(os.path.exists(DOC), "docs/example.m740 missing")
        self.cf = control.load(DOC)        # raises ControlError on bad syntax

    def test_device_and_segments(self):
        self.assertEqual(self.cf.device, "M3886")
        # the file demonstrates a memory map; the ROM must be file-backed
        self.assertEqual(len(self.cf.segments), 2)
        self.assertTrue(any(s.kind == "file" for s in self.cf.segments))

    def test_entry_points_named(self):
        self.assertIn(0xab00, self.cf.entry_points)
        self.assertIn(0x9c80, self.cf.entry_points)

    def test_all_range_kinds_shown(self):
        kinds = {kind for _, _, kind in self.cf.ranges}
        self.assertEqual(kinds, {"text", "word", "addr"})

    def test_addrtable_and_comments(self):
        self.assertEqual(len(self.cf.addr_tables), 1)
        self.assertEqual(self.cf.addr_tables[0].label_prefix, "cmd_")
        # the hardware-wiring note on Port P2 is the point of the comment directive
        self.assertIn(0x0004, self.cf.comments)


def _update():
    os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
    with open(GOLDEN, "w", newline="\n") as f:
        f.write(_produce())
    print("wrote", GOLDEN)


if __name__ == "__main__":
    if "--update" in sys.argv:
        _update()
    else:
        unittest.main()
