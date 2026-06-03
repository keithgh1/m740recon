import os
import tempfile
import unittest

from m740dasm import control
from m740dasm.tests import asmchain


class ControlParseTests(unittest.TestCase):
    def test_parses_device_entry_label_comment(self):
        cf = control.parse(
            "# a control file\n"
            "device M50734\n"
            "entry 0x8130 reset\n"
            "entry 0x9000\n"
            "label 0xc063 tbl_ctrl_std\n"
            'label 0x8533 main_loop "fetch host byte; dispatch"\n'
            'comment 0x82a7 "power-on head fire"\n'
        )
        self.assertEqual(cf.device, "M50734")
        self.assertEqual(cf.entry_points, [0x8130, 0x9000])
        by_addr = {s.address: s for s in cf.symbols}
        self.assertEqual(by_addr[0x8130].name, "reset")
        self.assertEqual(by_addr[0xc063].name, "tbl_ctrl_std")
        self.assertEqual(by_addr[0x8533].comment, "fetch host byte; dispatch")
        self.assertFalse(by_addr[0x8533].weak)
        self.assertNotIn(0x9000, by_addr)        # entry with no name -> no symbol
        self.assertEqual(cf.comments[0x82a7], "power-on head fire")

    def test_first_writer_wins(self):
        cf = control.parse("label 0x10 first\nlabel 0x10 second\n")
        self.assertEqual(cf.symbols[0].name, "first")

    def test_blank_and_comment_only_lines_ignored(self):
        cf = control.parse("\n   \n# just a comment\n")
        self.assertEqual(cf.entry_points, [])
        self.assertEqual(cf.symbols, [])

    def test_bad_address_raises(self):
        with self.assertRaises(control.ControlError):
            control.parse("entry nothex\n")

    def test_unknown_directive_raises(self):
        with self.assertRaises(control.ControlError):
            control.parse("frobnicate 0x10\n")


class ControlIntegrationTests(unittest.TestCase):
    """An entry point should make code that the default trace misses appear,
    named as requested -- the core thing disasm_nx.py did by hand."""

    def _image(self):
        rom = bytearray(0x10000)
        rom[0x8000:0x8002] = bytes([0xEA, 0x60])           # nop ; rts  (reset)
        rom[0x9000:0x9003] = bytes([0xA9, 0x01, 0x60])     # lda #0x01 ; rts (handler)
        rom[0xFFFE] = 0x00                                  # reset vector -> 0x8000
        rom[0xFFFF] = 0x80
        return rom

    def test_unreached_handler_not_code_by_default(self):
        text = asmchain.disasm_text(self._image(), device="M50734", start_address=0)
        self.assertNotIn("myhandler", text)
        self.assertNotIn("lda #0x01", text)        # 0x9000 stays data

    def test_control_entry_traces_and_names_handler(self):
        cf = control.parse("device M50734\nentry 0x9000 myhandler\n")
        text = asmchain.disasm_text(self._image(), device=cf.device,
                                    start_address=0, entry_points=cf.entry_points,
                                    extra_symbols=cf.symbols)
        self.assertIn("myhandler:", text)          # named
        self.assertIn("lda #0x01", text)           # now decoded as code


class ControlSegmentTests(unittest.TestCase):
    def test_parses_segments(self):
        cf = control.parse(
            "segment ram 0x0000 0x4000 zero\n"
            "segment sys 0x4000 0x8000 lower.bin@0x4000\n"
            "segment fw  0x8000 0x10000 upper.bin\n"
        )
        self.assertEqual(len(cf.segments), 3)
        self.assertEqual(cf.segments[0].kind, "zero")
        self.assertEqual(cf.segments[1].path, "lower.bin")
        self.assertEqual(cf.segments[1].off, 0x4000)
        self.assertEqual(cf.segments[2].off, 0)

    def test_build_image_places_bytes(self):
        d = tempfile.mkdtemp(prefix="m740seg_")
        try:
            with open(os.path.join(d, "a.bin"), "wb") as f:
                f.write(bytes(range(32)))
            cf = control.parse(
                "segment ram 0x0000 0x0010 zero\n"
                "segment a   0x0010 0x0018 a.bin@0x04\n", base_dir=d)
            img = cf.build_image()
            self.assertEqual(len(img), 0x10000)
            self.assertEqual(bytes(img[0x00:0x10]), bytes(16))
            self.assertEqual(bytes(img[0x10:0x18]), bytes(range(4, 12)))
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    def test_out_of_range_segment_rejected(self):
        with self.assertRaises(control.ControlError):
            control.parse("segment x 0xF000 0x10001 zero\n")

    def test_source_too_short_rejected(self):
        d = tempfile.mkdtemp(prefix="m740seg_")
        try:
            with open(os.path.join(d, "small.bin"), "wb") as f:
                f.write(b"\x01\x02")
            cf = control.parse("segment x 0x0000 0x0010 small.bin\n", base_dir=d)
            with self.assertRaises(control.ControlError):
                cf.build_image()
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


class ControlAddrTableTests(unittest.TestCase):
    def test_parse_addrtable(self):
        cf = control.parse(
            "addrtable 0xc0d4 stride=3 entryoff=1 terminator=0x00 label=cmd_esc_\n")
        self.assertEqual(len(cf.addr_tables), 1)
        t = cf.addr_tables[0]
        self.assertEqual((t.start, t.stride, t.entryoff, t.terminator,
                          t.label_prefix), (0xc0d4, 3, 1, 0x00, "cmd_esc_"))

    def test_addrtable_needs_a_bound(self):
        with self.assertRaises(control.ControlError):
            control.parse("addrtable 0x1000 stride=3\n")

    def test_addrtable_entryoff_exceeds_stride(self):
        with self.assertRaises(control.ControlError):
            control.parse("addrtable 0x1000 stride=2 entryoff=1 count=4\n")

    def _table_image(self):
        # [char, lo, hi] entries, 0x00-terminated, at 0x1000
        img = bytearray(0x10000)
        img[0x1000:0x1006] = bytes([0x41, 0x00, 0x20,    # 'A' -> 0x2000
                                    0x42, 0x00, 0x30])   # 'B' -> 0x3000
        img[0x1006] = 0x00                                # terminator
        # the two handlers are reachable ONLY through the table
        img[0x2000:0x2003] = bytes([0xA9, 0x01, 0x60])    # lda #1 ; rts
        img[0x3000:0x3003] = bytes([0xA9, 0x02, 0x60])    # lda #2 ; rts
        return img

    def test_resolve_tables(self):
        cf = control.parse(
            "addrtable 0x1000 stride=3 entryoff=1 terminator=0x00 label=cmd_\n")
        ptrs, data, syms = cf.resolve_tables(self._table_image())
        self.assertEqual(ptrs, [0x1001, 0x1004])     # pointer positions
        self.assertEqual(set(data), {0x1000, 0x1003})  # the char bytes
        names = {s.address: s.name for s in syms}
        self.assertEqual(names, {0x2000: "cmd_A", 0x3000: "cmd_B"})
        self.assertTrue(all(not s.weak for s in syms))

    def test_addrtable_feeds_tracer(self):
        cf = control.parse(
            "addrtable 0x1000 stride=3 entryoff=1 terminator=0x00 label=cmd_\n")
        text = asmchain.disasm_text(self._table_image(), device="M50734",
                                    start_address=0, control=cf)
        self.assertIn("cmd_A:", text)       # target named
        self.assertIn("cmd_B:", text)
        self.assertIn(".word cmd_A", text)  # table entry rendered as a pointer
        self.assertIn("lda #0x02", text)    # handler decoded as code


class ControlRangeTests(unittest.TestCase):
    def test_range_byte_forces_data(self):
        img = bytearray(0x10000)
        img[0x8000:0x8002] = bytes([0xEA, 0x60])           # reset: nop ; rts
        img[0x9000:0x9003] = bytes([0xA9, 0x01, 0x60])     # would decode as code
        img[0xFFFE] = 0x00
        img[0xFFFF] = 0x80
        # entry would trace 0x9000; the range forces it to data instead
        cf = control.parse("entry 0x9000 h\nrange 0x9000 0x9003 byte\n")
        text = asmchain.disasm_text(img, device="M50734", start_address=0,
                                    control=cf)
        self.assertIn("h:", text)               # still named
        self.assertNotIn("lda #0x01", text)     # but kept out of the code trace

    def test_range_kinds_accepted(self):
        cf = control.parse(
            "range 0x1000 0x1010 byte\n"
            "range 0x1010 0x1020 word\n"
            "range 0x1020 0x1030 addr\n"
            "range 0x1030 0x1040 text\n")
        self.assertEqual([r[2] for r in cf.ranges], ["byte", "word", "addr", "text"])

    def test_range_unknown_kind_rejected(self):
        with self.assertRaises(control.ControlError):
            control.parse("range 0x1000 0x1010 quux\n")

    def test_word_range_must_be_even(self):
        with self.assertRaises(control.ControlError):
            control.parse("range 0x1000 0x1003 word\n")

    def test_word_and_text_rendering(self):
        img = bytearray(0x10000)
        img[0x8000:0x8002] = bytes([0xEA, 0x60])            # reset: nop ; rts
        img[0x8100:0x8104] = bytes([0x34, 0x12, 0x78, 0x56])  # two words
        img[0x8200:0x8205] = b"Hi\x00!?"                     # text + an embedded NUL
        img[0xFFFE], img[0xFFFF] = 0x00, 0x80
        cf = control.parse("range 0x8100 0x8104 word\n"
                           "range 0x8200 0x8205 text\n")
        text = asmchain.disasm_text(bytes(img), device="M50734",
                                    start_address=0, control=cf)
        self.assertIn(".word 0x1234", text)
        self.assertIn(".word 0x5678", text)
        self.assertIn('.ascii "Hi"', text)        # printable run
        self.assertIn(".byte 0x00", text)         # NUL falls back to .byte


class ControlNamedHandlerTests(unittest.TestCase):
    """A dispatch table names and traces its handlers (the disasm_nx.py job,
    on a synthetic table)."""

    def test_addrtable_names_via_ascii(self):
        cf = control.parse(
            "addrtable 0x8100 stride=3 entryoff=1 terminator=0x00"
            " label=ctl_ names=ascii\n")
        from m740dasm.tests import fixtures
        img = bytearray(fixtures.dispatch_image())
        # rewrite the table keys to control codes so names=ascii applies
        img[0x8100] = 0x07          # BEL
        img[0x8103] = 0x0a          # LF
        text = asmchain.disasm_text(bytes(img), device="M50734",
                                    start_address=0, control=cf)
        self.assertIn("ctl_BEL:", text)
        self.assertIn("ctl_LF:", text)


if __name__ == "__main__":
    unittest.main()
