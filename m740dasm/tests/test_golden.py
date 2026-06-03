"""Output-stability (golden) test on a synthetic image.

Freezes the listing for a fixed synthetic image so that incidental changes to
the tool's output become visible in review.  Regenerate intentionally with:
    python -m m740dasm.tests.test_golden --update
"""

import os
import sys
import unittest

from m740dasm.tests import asmchain, fixtures

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden", "zeropage.asm")


def _produce():
    return asmchain.disasm_text(fixtures.zeropage_image(), device="M50734",
                                start_address=0)


class GoldenListingTests(unittest.TestCase):
    def test_matches_golden(self):
        self.assertTrue(os.path.exists(GOLDEN), "golden missing; run --update")
        with open(GOLDEN, "r", newline="\n") as f:
            golden = f.read()
        self.assertEqual(_produce().splitlines(), golden.splitlines())


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
