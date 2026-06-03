"""End-to-end reassembly tests using the real as740 + aslink.

These enforce m740dasm's defining guarantee directly with the actual assembler:
the listing must assemble bit-for-bit back to the input image.  as740/aslink
are NOT distributed with m740dasm, so by default these tests SKIP when the
toolchain is absent (the suite still passes, and the pure-Python structural
round-trip in test_roundtrip keeps re-encoding verified).  Set
M740_REQUIRE_AS740=1 to make a missing toolchain a hard failure instead.

All inputs are the repository's own testprog.asm or synthetic fixtures; no
external ROM image is required.
"""

import os
import unittest

from m740dasm import control
from m740dasm.tests import asmchain, fixtures

HERE = os.path.dirname(os.path.abspath(__file__))
TESTPROG = os.path.join(HERE, "end_to_end", "testprog.asm")


class EndToEndReassemblyTests(unittest.TestCase):
    @unittest.skipUnless(asmchain.REQUIRE_AS740,
                         "informational; set M740_REQUIRE_AS740=1 to enforce")
    def test_as740_toolchain_installed(self):
        self.assertTrue(
            asmchain.tools_available(),
            "as740/aslink must be installed and on PATH (or in ~/bin). "
            "Build them from the ASxxxx source if needed.")

    @asmchain.requires_as740
    def test_testprog_roundtrips(self):
        """Every opcode (testprog.asm) survives disassemble -> reassemble."""
        with open(TESTPROG) as f:
            asm = f.read()
        image = asmchain.assemble(asm, org=0x8000, size=0x8000)
        asmchain.assert_reassembles(image, device="M3886", start_address=0x8000)

    @asmchain.requires_as740
    def test_zeropage_image_roundtrips(self):
        """A RAM-inclusive image (start 0x0000, zero-page refs) reassembles --
        exercises the direct-page equate path."""
        asmchain.assert_reassembles(fixtures.zeropage_image(), device="M50734",
                                    start_address=0)

    @asmchain.requires_as740
    def test_addrtable_image_roundtrips(self):
        """An image with a decoded dispatch table reassembles bit-for-bit."""
        cf = control.parse(fixtures.DISPATCH_CONTROL)
        asmchain.assert_reassembles(fixtures.dispatch_image(), device="M50734",
                                    start_address=0, control=cf)

    @asmchain.requires_as740
    def test_analyze_image_roundtrips(self):
        """Analysis-discovered code reassembles bit-for-bit."""
        asmchain.assert_reassembles(fixtures.computed_jump_image(),
                                    device="M50734", start_address=0,
                                    analyze=True)

    @asmchain.requires_as740
    def test_typed_ranges_roundtrip(self):
        """.word and .ascii/.byte typed regions reassemble bit-for-bit."""
        img = bytearray(0x10000)
        img[0x8000:0x8002] = bytes([0xEA, 0x60])            # reset: nop ; rts
        img[0x8100:0x8104] = bytes([0x34, 0x12, 0x78, 0x56])  # word table
        img[0x8200:0x8208] = b"Hello!\x00\x01"               # text + non-printable
        img[0xFFFE], img[0xFFFF] = 0x00, 0x80
        cf = control.parse("range 0x8100 0x8104 word\n"
                           "range 0x8200 0x8208 text\n")
        asmchain.assert_reassembles(bytes(img), device="M50734",
                                    start_address=0, control=cf)


if __name__ == "__main__":
    unittest.main()
