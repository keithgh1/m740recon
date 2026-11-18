"""Tests for the --suggest draft control file (suggest.py).  Synthetic images."""

import io
import os
import shutil
import sys
import tempfile
import unittest

from m740recon import command, control
from m740recon.tests import test_dispatch, test_infer


def _image():
    """A search-routine table (proven) plus an uncalled routine after an rts
    (inferred), in one 32 KiB image at 0x8000."""
    rom = bytearray(test_dispatch._search_image())
    gap = test_infer._image()
    rom[0x8400:0x8430] = gap[0x8000:0x8030]
    # the gap image's routines were assembled for 0x8000; relocate the calls
    for at in (0x8401, 0x8404, 0x8424, 0x8427):
        rom[at + 1] = 0x84
    rom[0x8020:0x8023] = bytes([0x20, 0x00, 0x84])     # reach the gap code's caller
    return bytes(rom[0x8000:])


def _cli(args, data, control_text=None):
    d = tempfile.mkdtemp()
    try:
        rom = os.path.join(d, "rom.bin")
        with open(rom, "wb") as f:
            f.write(data)
        argv = ["m740recon"] + list(args)
        if control_text is not None:
            ctl = os.path.join(d, "fw.m740")
            with open(ctl, "w") as f:
                f.write(control_text)
            argv += ["-c", ctl]
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr, sys.argv
        sys.stdout, sys.stderr, sys.argv = out, err, argv + [rom]
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


def _live(text):
    return [l for l in text.splitlines() if l and not l.startswith("#")]


class DraftTests(unittest.TestCase):
    def test_draft_parses_and_has_every_section(self):
        code, out, err = _cli(["--suggest"], _image())
        self.assertEqual(code, 0)
        control.parse(out)                      # always a valid control file
        # only a reset vector here, so the device pick is low and written
        # commented out for review
        [dev] = [l for l in out.splitlines() if l.lstrip("# ").startswith("device ")]
        self.assertIn("# conf=", dev)
        tables = [l for l in _live(out) if l.startswith("addrtable 0x8100")]
        self.assertEqual(len(tables), 1)
        self.assertIn("conf=proven", tables[0])
        self.assertIn("# segment rom 0x8000 0x10000", out)    # offered, not imposed

    def test_named_device_is_not_repeated(self):
        code, out, err = _cli(["-m", "M50734", "--suggest"], _image())
        self.assertFalse([l for l in _live(out) if l.startswith("device")])

    def test_pins_scope_is_the_old_output(self):
        code, out, err = _cli(["-m", "M50734", "--suggest=pins"], _image())
        self.assertTrue(out.startswith("# m740recon --suggest: one pin line"))
        self.assertNotIn("addrtable", out)

    def test_bad_scope_is_rejected(self):
        code, out, err = _cli(["--suggest=everything"], _image())
        self.assertEqual(code, 1)
        self.assertIn("scope", err)

    def test_merge_mode_adds_nothing_already_said(self):
        code, first, err = _cli(["-m", "M50734", "--suggest"], _image())
        code, again, err = _cli(["--suggest"], _image(), control_text="device M50734\n" + first)
        self.assertEqual([l for l in _live(again) if not l.startswith("pin")], [])
        control.parse("device M50734\n" + first + again)

    def test_no_evidence_search_on_non_740_images(self):
        # nothing here fits a 740 device (vector area erased): no inferred
        # entries, and a note why
        import random
        rnd = random.Random(740)
        data = bytes(rnd.getrandbits(8) for _ in range(0x8000 - 64)) + b"\xff" * 64
        code, out, err = _cli(["--suggest"], data)
        self.assertFalse([l for l in _live(out) if l.startswith("entry")])
        self.assertIn("does not look like 740 code", err)

    def test_draft_as_control_file_keeps_the_names(self):
        code, draft, err = _cli(["-m", "M50734", "--suggest"], _image())
        code, listing, err = _cli([], _image(), control_text="device M50734\n" + draft)
        self.assertIn("tbl_8100_A:", listing)


if __name__ == "__main__":
    unittest.main()
