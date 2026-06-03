"""Fast structural reassembly-fidelity checks (no external assembler, no ROM).

Complements the as740 end-to-end tests with an in-process proof that the
classification tiles the address space exactly and that decoded instruction
bytes match the image.  Runs in milliseconds, so it can gate every change.
"""

import unittest

from m740dasm import command, control
from m740dasm.tests import fixtures
from m740dasm.tests.reassemble import assert_roundtrip


class RoundTripTests(unittest.TestCase):
    def test_zeropage_image(self):
        image = fixtures.zeropage_image()
        memory, _ = command.build_disassembly(image, "M50734", 0)
        assert_roundtrip(memory, image)

    def test_dispatch_image(self):
        image = fixtures.dispatch_image()
        cf = control.parse(fixtures.DISPATCH_CONTROL)
        kwargs = command.control_args(cf, image)
        memory, _ = command.build_disassembly(image, "M50734", 0, **kwargs)
        assert_roundtrip(memory, image)

    def test_analyze_image(self):
        image = fixtures.computed_jump_image()
        memory, _ = command.build_disassembly(image, "M50734", 0, analyze=True)
        assert_roundtrip(memory, image)


if __name__ == "__main__":
    unittest.main()
