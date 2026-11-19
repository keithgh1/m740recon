"""Tests for the inferred tier (infer.py, --advanced).  Synthetic images."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest

from m740recon import command, infer
from m740recon.tests import asmchain


def _image(extra=b"", table=None):
    """Reset calls two routines.  Right after the second routine's rts sits a
    routine nothing calls, which calls both known routines (a gap entry).
    Optionally a pointer table at 0x8200 pointing at further routines that
    each start right after an rts."""
    rom = bytearray(b"\xff" * 0x10000)
    rom[0x8000:0x8007] = bytes([0x20, 0x10, 0x80,    # jsr $8010
                                0x20, 0x20, 0x80,    # jsr $8020
                                0x60])               # rts
    rom[0x8010:0x8013] = bytes([0xA9, 0x01, 0x60])   # lda #1 / rts
    rom[0x8020:0x8023] = bytes([0xA9, 0x02, 0x60])   # lda #2 / rts
    # the uncalled routine at 0x8023, after the rts at 0x8022
    rom[0x8023:0x802a] = bytes([0x20, 0x10, 0x80,    # jsr $8010
                                0x20, 0x20, 0x80,    # jsr $8020
                                0x60])
    if table:
        for n, target in enumerate(table):
            rom[0x8200 + 2 * n:0x8202 + 2 * n] = bytes([target & 0xFF, target >> 8])
            rom[target - 1] = 0x60                       # a routine ends just before
            rom[target:target + 3] = bytes([0xA9, n, 0x60])
    rom[0x8030:0x8030 + len(extra)] = extra
    rom[0xFFFE], rom[0xFFFF] = 0x00, 0x80
    return bytes(rom)


def _run(img, **kw):
    return infer.run(command.build_disassembly, img, "M50734", 0, 0x8000, 0x10000, **kw)


class GapTests(unittest.TestCase):
    def test_uncalled_routine_after_rts_is_found(self):
        img = _image()
        plain, _ = command.build_disassembly(img, "M50734", 0)
        self.assertFalse(plain.is_instruction_start(0x8023))
        mem, sym, kept, dropped = _run(img)
        self.assertTrue(mem.is_instruction_start(0x8023))
        [d] = [d for d in kept if d.address == 0x8023]
        self.assertEqual((d.source, d.confidence), ("gap", "medium"))
        self.assertIn("calls 2 known routines", d.reason)


class TableTests(unittest.TestCase):
    TARGETS = (0x8301, 0x8311, 0x8321, 0x8331)

    def test_pointer_table_targets_found_but_not_typed(self):
        img = _image(table=self.TARGETS)
        mem, sym, kept, dropped = _run(img)
        for t in self.TARGETS:
            self.assertTrue(mem.is_instruction_start(t), hex(t))
        self.assertTrue(any(d.source == "table@0x8200" for d in kept))
        # inferred entries never type bytes: the table stays plain data
        self.assertFalse(mem.is_vector_start(0x8200))


class ContradictionTests(unittest.TestCase):
    def test_entry_jumping_into_an_instruction_is_dropped(self):
        img = bytearray(_image())
        # after the known rts at 0x8012 (lda #1 / rts): a fake "routine" that
        # calls both known routines and then jumps into the middle of the
        # 2-byte lda at 0x8020
        img[0x8013:0x801a] = bytes([0x20, 0x10, 0x80, 0x20, 0x20, 0x80,
                                    0x4C])
        img[0x801a:0x801c] = bytes([0x21, 0x80])        # jmp $8021 (mid lda)
        mem, sym, kept, dropped = _run(bytes(img))
        # rejected while exploring, before it could become an entry
        self.assertNotIn(0x8013, [d.address for d in kept])
        self.assertFalse(mem.is_instruction_start(0x8013))

    def test_indirect_jump_through_an_sfr_is_dropped(self):
        from m740recon.devices import Devices
        sfr = min(s.address for s in Devices["M50734"]["symbol_table"]
                  if s.address < 0x100 and not s.weak)
        img = bytearray(_image())
        # the gap routine calls both known routines (so it is accepted), then
        # jumps through an SFR, which real code does not do
        img[0x8023:0x802b] = bytes([0x20, 0x10, 0x80, 0x20, 0x20, 0x80,
                                    0x02, sfr])                 # jsr [sfr]
        img[0x802b] = 0x60
        mem, sym, kept, dropped = _run(bytes(img))
        self.assertIn(0x8023, dropped)
        self.assertIn("SFR", dropped[0x8023][0])
        self.assertNotIn(0x8023, [d.address for d in kept])
        self.assertFalse(mem.is_instruction_start(0x8023))


def _cli(args, data):
    d = tempfile.mkdtemp()
    try:
        p = os.path.join(d, "rom.bin")
        with open(p, "wb") as f:
            f.write(data)
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr, sys.argv
        sys.stdout, sys.stderr, sys.argv = out, err, ["m740recon"] + list(args) + [p]
        try:
            command.main()
        finally:
            sys.stdout, sys.stderr, sys.argv = old
        return out.getvalue()
    finally:
        shutil.rmtree(d, True)


class CliTests(unittest.TestCase):
    def test_advanced_marks_inferred_entries(self):
        img = _image()[0x8000:]
        out = _cli(["-m", "M50734", "-A"], img)
        self.assertIn("; advanced 1 entries inferred (0 from tables, 1 from gaps)", out)
        self.assertIn(";inferred (medium): follows the routine end at 0x8022", out)

    def test_plain_run_infers_nothing(self):
        out = _cli(["-m", "M50734"], _image()[0x8000:])
        self.assertNotIn("inferred", out)

    def test_auto_tables_and_analyze_are_accepted(self):
        img = _image()[0x8000:]
        self.assertIn("; advanced", _cli(["-m", "M50734", "--auto-tables"], img))
        self.assertNotIn("; advanced", _cli(["-m", "M50734", "-a"], img))

    def test_json_lists_inferred_entries(self):
        model = json.loads(_cli(["-m", "M50734", "-A", "-j"], _image()[0x8000:]))
        self.assertEqual(model["detection"]["inferred"][0]["address"], "0x8023")

    @asmchain.requires_as740
    def test_advanced_listing_reassembles(self):
        img = _image(table=TableTests.TARGETS)[0x8000:]
        out = _cli(["-m", "M50734", "-A"], img)
        self.assertEqual(asmchain.assemble(out, 0x8000, len(img)), img)


if __name__ == "__main__":
    unittest.main()
