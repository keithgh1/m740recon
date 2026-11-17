"""Tests for the control-file `include` directive and the listing annotation
hook (the plumbing later signal features build on)."""

import io
import os
import shutil
import sys
import tempfile
import unittest

from m740recon import control, command
from m740recon.listing import Printer
from m740recon.tests import fixtures


class IncludeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _write(self, rel, text):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_include_merges_directives(self):
        self._write("board.m740", "label 0x10 counter\n")
        top = self._write("fw.m740", "device M50734\ninclude board.m740\n"
                                     "entry 0x8000 reset\n")
        cf = control.load(top)
        names = {s.address: s.name for s in cf.symbols}
        self.assertEqual(cf.device, "M50734")
        self.assertEqual(names[0x10], "counter")
        self.assertEqual(names[0x8000], "reset")

    def test_nested_include_resolves_relative_to_including_file(self):
        self._write("hw/pins.m740", "label 0x20 inner\n")
        self._write("hw/board.m740", "include pins.m740\n")
        top = self._write("fw.m740", "include hw/board.m740\n")
        cf = control.load(top)
        self.assertEqual([s.name for s in cf.symbols], ["inner"])

    def test_include_from_parse_uses_base_dir(self):
        self._write("board.m740", "label 0x30 viaparse\n")
        cf = control.parse("include board.m740\n", base_dir=self.dir)
        self.assertEqual([s.name for s in cf.symbols], ["viaparse"])

    def test_segment_path_in_included_file_is_relative_to_it(self):
        rom = os.path.join(self.dir, "hw", "rom.bin")
        os.makedirs(os.path.dirname(rom))
        with open(rom, "wb") as f:
            f.write(bytes([0xAB]) * 0x10)
        self._write("hw/map.m740", "segment rom 0xfff0 0x10000 rom.bin\n")
        top = self._write("fw.m740", "include hw/map.m740\n")
        image = control.load(top).build_image()
        self.assertEqual(image[0xfff0], 0xAB)

    def test_cycle_rejected(self):
        self._write("a.m740", "include b.m740\n")
        self._write("b.m740", "include a.m740\n")
        with self.assertRaises(control.ControlError) as ctx:
            control.load(os.path.join(self.dir, "a.m740"))
        self.assertIn("include cycle", str(ctx.exception))

    def test_self_include_rejected(self):
        top = self._write("a.m740", "include a.m740\n")
        with self.assertRaises(control.ControlError) as ctx:
            control.load(top)
        self.assertIn("include cycle", str(ctx.exception))

    def test_missing_file_reports_line(self):
        top = self._write("fw.m740", "device M50734\ninclude nope.m740\n")
        with self.assertRaises(control.ControlError) as ctx:
            control.load(top)
        self.assertIn("line 2", str(ctx.exception))
        self.assertIn("nope.m740", str(ctx.exception))

    def test_error_in_included_file_names_that_file_and_line(self):
        inc = self._write("board.m740", "label 0x10 ok\nbogus 1\n")
        top = self._write("fw.m740", "include board.m740\n")
        with self.assertRaises(control.ControlError) as ctx:
            control.load(top)
        msg = str(ctx.exception)
        self.assertIn(inc, msg)
        self.assertIn("line 2", msg)

    def test_include_needs_one_path(self):
        with self.assertRaises(control.ControlError):
            control.parse("include\n")


def _listing(annotations):
    rom = fixtures.snapshot_image()
    start = 0x10000 - len(rom)
    memory, symtab = command.build_disassembly(rom, "M50734", start)
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        Printer(memory, start, symtab, annotations=annotations).print_listing()
    finally:
        sys.stdout = old
    return memory, buf.getvalue()


class PrinterAnnotationTests(unittest.TestCase):
    def test_no_annotations_is_unchanged(self):
        _, plain = _listing(None)
        _, empty = _listing({})
        self.assertEqual(plain, empty)

    def test_annotation_appended_after_hexdump(self):
        memory, plain = _listing(None)
        addr = next(a for a, _ in memory.iter_instructions())
        _, noted = _listing({addr: "HELLO: note"})
        tag = ";%04x  " % addr
        before = [l for l in plain.splitlines() if tag in l]
        after = [l for l in noted.splitlines() if tag in l]
        self.assertEqual(len(before), 1)
        self.assertEqual(after, [before[0] + " HELLO: note"])
        # every other line is untouched
        self.assertEqual(len(plain.splitlines()), len(noted.splitlines()))
        diff = [p for p, n in zip(plain.splitlines(), noted.splitlines()) if p != n]
        self.assertEqual(len(diff), 1)


if __name__ == "__main__":
    unittest.main()
