"""Tests for the JSON / call-graph report (report.py)."""

import json
import unittest

from m740dasm import command, report


def _image():
    """A small program exercising every edge kind the report distinguishes:
    direct call (two sites), special-page call, a tail-call jump, and a
    computed (indirect) jump that must be counted but not turned into an edge.
    """
    rom = bytearray(0x10000)
    # reset @ 0x8000
    rom[0x8000:0x800c] = bytes([
        0x20, 0x00, 0x90,     # 8000 jsr 0x9000
        0x20, 0x00, 0x90,     # 8003 jsr 0x9000   (second call site)
        0x20, 0x00, 0x91,     # 8006 jsr 0x9100
        0x4c, 0x00, 0x92,     # 8009 jmp 0x9200   (tail call)
    ])
    rom[0x9000:0x9003] = bytes([0x22, 0xc0,        # 9000 jsr \0xffc0 (special page)
                                0x60])             # 9002 rts
    rom[0x9100:0x9104] = bytes([0x20, 0x00, 0x92,  # 9100 jsr 0x9200
                                0x60])             # 9103 rts
    rom[0x9200:0x9202] = bytes([0xb2, 0x10])       # 9200 jmp [0x10] (indirect)
    rom[0xffc0] = 0x60                             # ffc0 rts
    # point every M50734 vector (0xFFF4..0xFFFE) at the 0x8000 handler so the
    # image has no null vectors tracing 0x0000 into a spurious routine
    for v in range(0xFFF4, 0x10000, 2):
        rom[v], rom[v + 1] = 0x00, 0x80
    return bytes(rom)


def _model():
    rom = _image()
    memory, symtab = command.build_disassembly(rom, "M50734", 0)
    return report.build_model(memory, symtab, 0, len(rom), "M50734")


class CallGraphModelTests(unittest.TestCase):
    def setUp(self):
        self.model = _model()
        self.byaddr = {r["address"]: r for r in self.model["routines"]}

    def test_routine_roots_and_counts(self):
        meta = self.model["meta"]
        self.assertEqual(meta["routine_count"], 5)        # 8000,9000,9100,9200,ffc0
        self.assertEqual(meta["call_edge_count"], 6)      # 4 from reset + 2 from subs
        self.assertEqual(meta["indirect_sites"], 1)       # the jmp [0x10]
        self.assertEqual(set(self.byaddr),
                         {"0x8000", "0x9000", "0x9100", "0x9200", "0xffc0"})

    def test_direct_call_with_two_sites(self):
        callee = self.byaddr["0x9000"]
        self.assertIn("subroutine", callee["kind"])
        sites = sorted(e["site"] for e in callee["called_by"])
        self.assertEqual(sites, ["0x8000", "0x8003"])     # both call sites kept

    def test_special_page_call_is_an_edge(self):
        self.assertIn("0xffc0", self.byaddr)
        sub9000 = self.byaddr["0x9000"]
        self.assertEqual([e["name"] for e in sub9000["calls"]], ["sub_ffc0"])

    def test_tailcall_and_direct_call_both_reach_9200(self):
        callee = self.byaddr["0x9200"]
        types = {e["type"] for e in callee["called_by"]}
        self.assertEqual(types, {"call", "tailcall"})

    def test_vector_handler_is_a_root_with_no_callers(self):
        reset = self.byaddr["0x8000"]
        self.assertIn("vector", reset["kind"])
        self.assertEqual(reset["called_by"], [])

    def test_model_is_deterministic(self):
        self.assertEqual(self.model, _model())


class RenderingTests(unittest.TestCase):
    def setUp(self):
        self.model = _model()

    def test_json_round_trips(self):
        text = report.to_json(self.model)
        self.assertEqual(json.loads(text), self.model)
        self.assertTrue(self.model["symbols"] and self.model["vectors"]
                        and self.model["xrefs"])

    def test_call_graph_text(self):
        text = report.format_call_graph(self.model)
        self.assertIn("sub_9200", text)
        self.assertIn("-> sub_9000", text)
        self.assertIn("(tailcall)", text)
        self.assertIn("computed (indirect) call/jump", text)   # honesty line


if __name__ == "__main__":
    unittest.main()
