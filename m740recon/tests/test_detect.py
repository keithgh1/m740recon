"""Tests for load-address, bank and device detection (detect.py) and the CLI
behaviour built on it.  All images are synthetic."""

import io
import os
import random
import shutil
import sys
import tempfile
import unittest

from m740recon import command, detect
from m740recon.devices import Devices
from m740recon.tests import asmchain


def _program(base, size, routines=40, vectors=None, sfr_writes=(), calls=()):
    """A small program assembled for `base`: a main loop that calls every
    routine twice, routines of uneven length ending in rts, and the given
    vector words at the vector addresses (absolute)."""
    img = bytearray(b"\xff" * size)
    # routines start after the main code; sizes vary so no shifted base
    # lines up as well as the true one
    main_len = routines * 2 * 3 + 3 * len(calls) + 2 * len(sfr_writes) + 2
    pc = main_len
    starts = []
    pad = random.Random(740)
    for i in range(routines):
        starts.append(base + pc)
        body = [0xA9, i & 0xFF] + [0xEA] * pad.randint(0, 9) + [0x85, 0x40, 0x60]
        img[pc:pc + len(body)] = bytes(body)
        pc += len(body)
    code = []
    for _ in range(2):
        for s in starts:
            code += [0x20, s & 0xFF, s >> 8]                    # jsr routine
    for t in calls:
        code += list(t)
    for zp in sfr_writes:
        code += [0x85, zp]                                      # sta zp
    code += [0x80, 0xFE]                                        # bra *
    img[0:len(code)] = bytes(code)
    for vaddr, target in (vectors or {}).items():
        off = vaddr - base
        img[off] = target & 0xFF
        img[off + 1] = target >> 8
    return bytes(img), base


def _zp_sfrs(dev, count=8):
    return sorted(s.address for s in Devices[dev]["symbol_table"]
                  if s.address < 0x100 and not s.weak)[:count]


def _same_class(a, b):
    return detect._signature(a) == detect._signature(b)


class BaseTests(unittest.TestCase):
    def test_vote_finds_a_low_base(self):
        data, base = _program(0x1400, 0x0C00)
        guess = detect.infer_base(data)
        self.assertEqual(guess.base, 0x1400)
        self.assertEqual(guess.method, "vote")

    def test_full_image_sits_at_zero(self):
        guess = detect.infer_base(bytes(0x10000))
        self.assertEqual((guess.base, guess.method), (0, "fills"))

    def test_vector_fallback_when_vote_is_flat(self):
        # no calls at all; every vector points at the image start
        data = bytearray(b"\xea" * 0x1000)
        data[0] = 0x78                                          # sei
        for k in range(6):
            data[0x1000 - 12 + 2 * k:0x1000 - 10 + 2 * k] = b"\x00\xf0"
        guess = detect.infer_base(bytes(data))
        self.assertEqual((guess.base, guess.method), (0xF000, "vectors"))

    def test_uncertain_when_nothing_stands_out(self):
        guess = detect.infer_base(bytes(b"\xff" * 0x800))
        self.assertIsNone(guess.base)


class BankTests(unittest.TestCase):
    def test_only_programmed_banks_are_returned(self):
        data = bytearray(b"\xff" * 0x20000)
        data[0x8000:0x8010] = b"\x01" * 16
        self.assertEqual([off for off, _ in detect.split_banks(bytes(data))], [0x8000])
        data[0x18000] = 0x02
        self.assertEqual(len(detect.split_banks(bytes(data))), 2)


class DeviceTests(unittest.TestCase):
    def test_six_vector_part(self):
        vt = Devices["M50734"]["vector_table"]
        data, base = _program(0x8000, 0x8000, sfr_writes=_zp_sfrs("M50734"),
                              vectors={v: 0x8000 for v in vt})
        guess = detect.detect_device(data, base)
        self.assertTrue(guess.fits)
        self.assertTrue(_same_class(guess.device, "M50734"), guess)

    def test_seventeen_vector_part(self):
        vt = Devices["M3886"]["vector_table"]
        data, base = _program(0x8000, 0x8000, sfr_writes=_zp_sfrs("M3886"),
                              vectors={v: 0x8000 for v in vt})
        guess = detect.detect_device(data, base)
        self.assertTrue(guess.fits)
        self.assertEqual(tuple(Devices[guess.device]["vector_table"]), tuple(vt), guess)

    def test_vectors_into_a_missing_rom_count_as_external(self):
        vt = sorted(Devices["M50734"]["vector_table"])
        vecs = {v: 0x5000 for v in vt}
        vecs[0xFFFE] = 0x8000                                   # reset stays here
        data, base = _program(0x8000, 0x8000, sfr_writes=_zp_sfrs("M50734"), vectors=vecs)
        guess = detect.detect_device(data, base)
        self.assertTrue(guess.fits)
        self.assertGreaterEqual(guess.external, 0.5)
        self.assertIn("outside this image", guess.reason)

    def test_not_740_code_does_not_fit(self):
        guess = detect.detect_device(bytes(b"\xff" * 0x8000), 0x8000)
        self.assertFalse(guess.fits)
        self.assertEqual(guess.confidence, "low")


class VectorRangeTests(unittest.TestCase):
    def test_device_vectors_outside_the_image_are_skipped(self):
        # a 13-bit part's vectors (0x1ff4) with the ROM at the top of memory:
        # used to raise "Vector address ... outside of traceable range"
        data, base = _program(0xF400, 0x0C00, vectors={0xFFFE: 0xF400})
        mem, _ = command.build_disassembly(data, "50740A", base)
        self.assertIsNotNone(mem)


class UnmappedTests(unittest.TestCase):
    def test_calls_outside_the_image_are_reported(self):
        calls = [(0x20, 0x00, 0x50)] * 3 + [(0x22, 0x10)]      # jsr $5000 x3, jsr \$ff10
        data, base = _program(0x8000, 0x8000, calls=calls,
                              vectors={0xFFFE: 0x8000})
        mem, _ = command.build_disassembly(data, "M50734", base)
        runs = detect.unmapped_targets(mem, base, base + len(data))
        self.assertEqual(runs, [(0x50, 0x50, 3)])               # special page not counted


def _cli(args, files):
    d = tempfile.mkdtemp()
    try:
        paths = []
        for name, content in files:
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(content)
            paths.append(p)
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr, sys.argv
        sys.stdout, sys.stderr = out, err
        sys.argv = ["m740recon"] + list(args) + paths
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


class CliTests(unittest.TestCase):
    def _low_image(self):
        vt = Devices["50740A"]["vector_table"]
        return _program(0x1400, 0x0C00, sfr_writes=_zp_sfrs("50740A"),
                        vectors={v: 0x1400 for v in vt})

    def test_header_names_detected_base_and_device(self):
        data, base = self._low_image()
        code, out, err = _cli([], [("rom.bin", data)])
        self.assertEqual(code, 0)
        self.assertIn("; base    0x1400   detected", out)
        self.assertIn("; device  ", out)
        self.assertIn(".org 0x1400", out)
        self.assertNotIn(";2000 ", out)                         # no padding listed

    def test_named_device_is_not_detected(self):
        data, base = self._low_image()
        code, out, err = _cli(["-m", "50740A"], [("rom.bin", data)])
        self.assertNotIn("; device", out)
        self.assertIn("; base    0x1400", out)

    @asmchain.requires_as740
    def test_low_image_reassembles(self):
        data, base = self._low_image()
        code, out, err = _cli([], [("rom.bin", data)])
        self.assertEqual(asmchain.assemble(out, base, len(data)), data)

    def test_json_carries_detection(self):
        import json
        data, base = self._low_image()
        code, out, err = _cli(["-j"], [("rom.bin", data)])
        model = json.loads(out)
        self.assertEqual(model["detection"]["base"]["address"], "0x1400")
        self.assertIn("device", model["detection"])

    def test_single_programmed_bank_is_used(self):
        data, base = _program(0x8000, 0x8000, vectors={0xFFFE: 0x8000})
        big = data + b"\xff" * 0x18000
        code, out, err = _cli(["-m", "M50734"], [("rom.bin", big)])
        self.assertEqual(code, 0)
        self.assertIn("; bank    file 0x00000-0x07fff", out)
        self.assertIn("only the 32 KiB bank", err)

    def test_several_programmed_banks_stop(self):
        big = bytearray(b"\xff" * 0x20000)
        big[0x10] = 1
        big[0x18010] = 1
        code, out, err = _cli(["-m", "M50734"], [("rom.bin", bytes(big))])
        self.assertEqual(code, 2)
        self.assertIn("segment lines", err)


if __name__ == "__main__":
    unittest.main()
