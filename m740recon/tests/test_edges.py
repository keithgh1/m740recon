"""Edge cases in detection, dispatch tables, control files and the draft.
All images are synthetic."""

import json
import os
import unittest

from m740recon import command, control, detect, dispatch, suggest
from m740recon.tests.test_detect import _cli, _program, _zp_sfrs
from m740recon.devices import Devices


def _search_rom(code, records, table=0x8100):
    """A 64 KiB image: `code` at 0x8000, a search routine (rts) at 0x8800,
    `records` (bytes) at `table`, handlers `lda #n / rts` at 0x9000+0x10*n."""
    rom = bytearray(b"\xff" * 0x10000)
    rom[0x8000:0x8000 + len(code)] = bytes(code)
    rom[0x8800] = 0x60
    rom[table:table + len(records)] = bytes(records)
    for n in range(4):
        h = 0x9000 + 0x10 * n
        rom[h:h + 3] = bytes([0xA9, n, 0x60])
    rom[0xFFFE], rom[0xFFFF] = 0x00, 0x80
    return bytes(rom)


_KEY_FIRST = [0x41, 0x00, 0x90, 0x42, 0x10, 0x90, 0x0D, 0x20, 0x90, 0x00]


def _names(sym):
    return {a: s.name for a, s in sym.items() if not s.weak}


class TinyImageTests(unittest.TestCase):
    def test_short_image_has_no_vector_base(self):
        guess = detect.infer_base(b"\x60" * 5)
        self.assertIsNone(guess.base)

    def test_tiny_binary_runs(self):
        code, out, err = _cli([], [("rom.bin", b"\x60" * 5)])
        self.assertEqual(code, 0)
        self.assertIn("; base    0xfffb", out)

    def test_empty_binary_is_an_error(self):
        code, out, err = _cli([], [("rom.bin", b"")])
        self.assertEqual(code, 2)
        self.assertIn("is empty", err)


class DeviceFallbackTests(unittest.TestCase):
    def _choose(self, guess):
        saved = detect.detect_device
        detect.detect_device = lambda data, base, build=None: guess
        try:
            header, notices, detection = [], [], {}
            dev = command.choose_device(b"", 0x8000, "M3886", header, notices, detection)
        finally:
            detect.detect_device = saved
        return dev, header, detection

    def test_no_vector_evidence_keeps_the_default(self):
        guess = detect.DeviceGuess("50740A", "low", 0.0, 0.0, 0.0, None, False, "vectors fit 0.00")
        dev, header, detection = self._choose(guess)
        self.assertEqual(dev, "M3886")
        self.assertIn("default", header[0])
        self.assertFalse(detection["device"]["fits"])

    def test_partial_vector_evidence_keeps_the_guess(self):
        guess = detect.DeviceGuess("M50734", "low", 0.17, 0.0, 0.0, None, False, "vectors fit 0.17")
        dev, header, detection = self._choose(guess)
        self.assertEqual(dev, "M50734")
        self.assertFalse(detection["device"]["fits"])


class SearchSiteTests(unittest.TestCase):
    def test_pointer_loaded_after_the_call_is_not_a_table(self):
        code = [0x20, 0x00, 0x88,                  # jsr search
                0x3C, 0x00, 0x60, 0x3C, 0x81, 0x61,  # ldm #<0x8100,$60 / ldm #>,$61
                0xB2, 0x60]                        # jmp [$60]
        mem, _ = command.build_disassembly(_search_rom(code, _KEY_FIRST), "M50734", 0)
        self.assertEqual(dispatch.search_sites(mem, 0, 0x10000), [])
        self.assertEqual(mem.dispatch_tables, [])

    def test_branch_that_skips_the_call_is_not_a_table(self):
        code = [0x3C, 0x00, 0x60, 0x3C, 0x81, 0x61,  # ldm / ldm
                0xB0, 0x03,                        # bcs over the call, to the jmp
                0x20, 0x00, 0x88,                  # jsr search
                0xB2, 0x60]                        # jmp [$60]
        mem, _ = command.build_disassembly(_search_rom(code, _KEY_FIRST), "M50734", 0)
        self.assertEqual(mem.dispatch_tables, [])

    def test_branch_after_the_call_is_allowed(self):
        code = [0x3C, 0x00, 0x60, 0x3C, 0x81, 0x61,
                0x20, 0x00, 0x88,                  # jsr search
                0x90, 0x01, 0x18,                  # bcc +1 / clc
                0xB2, 0x60]
        mem, _ = command.build_disassembly(_search_rom(code, _KEY_FIRST), "M50734", 0)
        self.assertEqual([f.table.start for f in mem.dispatch_tables], [0x8100])


class KeyOffsetTests(unittest.TestCase):
    CODE = [0x3C, 0x00, 0x60, 0x3C, 0x81, 0x61, 0x20, 0x00, 0x88, 0xB2, 0x60]
    # pointer first, key last; the terminator record has key 0x00
    KEY_LAST = [0x00, 0x90, 0x41, 0x10, 0x90, 0x42, 0x20, 0x90, 0x0D, 0x00, 0x00, 0x00]

    def test_key_last_records_keep_their_names(self):
        mem, sym = command.build_disassembly(_search_rom(self.CODE, self.KEY_LAST), "M50734", 0)
        [found] = mem.dispatch_tables
        self.assertEqual((found.table.entryoff, found.table.keyoff), (0, 2))
        names = _names(sym)
        self.assertEqual(names[0x9000], "tbl_8100_A")
        self.assertEqual(names[0x9010], "tbl_8100_B")
        self.assertEqual(names[0x9020], "tbl_8100_CR")

    def test_keyoff_directive(self):
        img = _search_rom(self.CODE, self.KEY_LAST)
        cf = control.parse("addrtable 0x8100 stride=3 entryoff=0 keyoff=2 "
                           "terminator=0x00 label=t_ names=ascii\n")
        ptrs, data, syms = cf.resolve_tables(img)
        self.assertEqual(ptrs, [0x8100, 0x8103, 0x8106])
        self.assertEqual(sorted(s.name for s in syms), ["t_A", "t_B", "t_CR"])

    def test_keyoff_inside_the_pointer_is_rejected(self):
        with self.assertRaises(control.ControlError):
            control.parse("addrtable 0x8100 stride=3 entryoff=0 keyoff=1 terminator=0\n")

    def test_draft_line_round_trips(self):
        img = _search_rom(self.CODE, self.KEY_LAST)
        code, out, err = _cli(["--suggest", "-m", "M50734"], [("rom.bin", img)])
        [line] = [l for l in out.splitlines() if l.startswith("addrtable 0x8100")]
        self.assertIn("keyoff=2", line)
        control.parse(line + "\n")


class NameTests(unittest.TestCase):
    def test_high_bit_keys_are_hex(self):
        img = _search_rom([], [0xC1, 0x00, 0x90, 0x00])
        cf = control.parse("addrtable 0x8100 stride=3 entryoff=1 terminator=0x00 label=t_\n")
        _, _, [sym] = cf.resolve_tables(img)
        self.assertEqual(sym.name, "t_c1")

    def test_generated_names_avoid_control_file_labels(self):
        img = _search_rom([], _KEY_FIRST)
        cf = control.parse("label 0x9400 t_A\n"
                           "addrtable 0x8100 stride=3 entryoff=1 terminator=0x00 label=t_\n")
        _, _, syms = cf.resolve_tables(img)
        self.assertEqual({s.address: s.name for s in syms}[0x9000], "t_A_2")


class DraftSourceTests(unittest.TestCase):
    def test_awkward_path_is_quoted_and_absolute(self):
        tok = suggest._source(os.path.join("a dir", "rom#1.bin"), 0x10)
        self.assertTrue(tok.startswith('"'))
        cf = control.parse("segment rom 0x8000 0x10000 %s\n" % tok)
        [seg] = cf.segments
        self.assertTrue(os.path.isabs(seg.path))
        self.assertTrue(seg.path.endswith("a dir/rom#1.bin"))
        self.assertEqual(seg.off, 0x10)

    def test_plain_path_is_not_quoted(self):
        self.assertFalse(suggest._source("rom.bin", 0).startswith('"'))


class PaddingTests(unittest.TestCase):
    def test_calls_past_a_low_image_are_not_traced(self):
        vt = Devices["50740A"]["vector_table"]
        data, base = _program(0x1400, 0x0C00, sfr_writes=_zp_sfrs("50740A"),
                              vectors={v: 0x1400 for v in vt},
                              calls=[(0x20, 0x00, 0x30)] * 3)      # jsr $3000 x3
        code, out, err = _cli(["-j"], [("rom.bin", data)])
        self.assertEqual(code, 0)
        model = json.loads(out)
        above = [r["name"] for r in model["routines"] if int(r["address"], 16) >= 0x2000]
        self.assertEqual(above, [])

    def test_trace_ranges_limit_the_tracer(self):
        rom = bytearray(b"\xff" * 0x8000)
        rom[0:4] = bytes([0x20, 0x00, 0xD0, 0x60])         # jsr $d000 / rts
        rom[0x5000] = 0x60                                 # padding that would trace
        rom[0x7FFE], rom[0x7FFF] = 0x00, 0x80
        mem, _ = command.build_disassembly(rom, "M50734", 0x8000)
        self.assertTrue(mem.is_instruction_start(0xD000))
        mem, _ = command.build_disassembly(rom, "M50734", 0x8000,
                                           trace_ranges=[(0x8000, 0xC000), (0xFFF0, 0x10000)])
        self.assertFalse(mem.is_instruction_start(0xD000))


class ControlPlacementTests(unittest.TestCase):
    def _cf(self, text):
        return control.parse(text)

    def test_control_addresses_pull_the_image_to_the_top(self):
        cf = self._cf("entry 0xf000 main\n")
        header, detection = ["base    0x1000   detected (medium): x"], {}
        base = command.fit_control_file(cf, 0x2000, 0x1000, header, detection)
        self.assertEqual(base, 0xE000)
        self.assertEqual(detection["base"]["method"], "control")
        self.assertEqual(len([h for h in header if h.startswith("base ")]), 1)

    def test_detected_base_kept_when_addresses_fit(self):
        cf = self._cf("entry 0x1100 main\n")
        base = command.fit_control_file(cf, 0x2000, 0x1000, [], {})
        self.assertEqual(base, 0x1000)

    def test_entry_outside_any_placement_is_a_clean_error(self):
        data = bytes([0x60] * 0x7FFE + [0x00, 0x80])
        code, out, err = _cli_with_control("entry 0x1234 nowhere\n", data)
        self.assertEqual(code, 2)
        self.assertIn("outside", err)
        self.assertNotIn("Traceback", err)


def _cli_with_control(text, data):
    import io
    import shutil
    import sys
    import tempfile
    d = tempfile.mkdtemp()
    try:
        ctl = os.path.join(d, "fw.m740")
        with open(ctl, "w") as f:
            f.write(text)
        rom = os.path.join(d, "rom.bin")
        with open(rom, "wb") as f:
            f.write(data)
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr, sys.argv
        sys.stdout, sys.stderr = out, err
        sys.argv = ["m740recon", "-m", "M50734", "-c", ctl, rom]
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


if __name__ == "__main__":
    unittest.main()
