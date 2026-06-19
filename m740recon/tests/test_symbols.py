import re
import unittest
from m740recon import symbols, memory, disasm
from m740recon.devices import Devices
from m740recon.tables import AddressModes

class SymbolCreatingAnalyzerTests(unittest.TestCase):

    def test_analyze_makes_lab_symbol_for_jump_target(self):
        table = symbols.SymbolTable()
        analyzer = symbols.SymbolCreatingAnalyzer(table)
        mem = memory.Memory(bytearray(0x10000))
        intable = disasm.Instruction(location=0xF000, opcode=0x60,
                                  addr_mode=AddressModes.Implied)
        mem.set_instruction(0xF000, intable)
        mem.annotate_jump_target(0xF000)
        analyzer.analyze(mem)
        self.assertEqual(table[0xf000].name, 'lab_f000')

    def test_analyze_makes_sub_symbol_for_call_target(self):
        table = symbols.SymbolTable()
        analyzer = symbols.SymbolCreatingAnalyzer(table)
        mem = memory.Memory(bytearray(0x10000))
        intable = disasm.Instruction(location=0xF000, opcode=0x60,
                                  addr_mode=AddressModes.Implied)
        mem.set_instruction(0xF000, intable)
        mem.annotate_call_target(0xF000)
        analyzer.analyze(mem)
        self.assertEqual(table[0xf000].name, 'sub_f000')

    def test_analyze_makes_sub_symbol_for_jump_and_call_target(self):
        table = symbols.SymbolTable()
        analyzer = symbols.SymbolCreatingAnalyzer(table)
        mem = memory.Memory(bytearray(0x10000))
        intable = disasm.Instruction(location=0xF000, opcode=0x60,
                                  addr_mode=AddressModes.Implied)
        mem.set_instruction(0xF000, intable)
        mem.annotate_jump_target(0xF000)
        mem.annotate_call_target(0xF000)
        analyzer.analyze(mem)
        self.assertEqual(table[0xf000].name, 'sub_f000')

    def test_analyze_doesnt_make_symbol_for_jump_to_mid_Instruction(self):
        table = symbols.SymbolTable()
        analyzer = symbols.SymbolCreatingAnalyzer(table)
        mem = memory.Memory(bytearray(0x10000))
        intable = disasm.Instruction(opcode=0x31, operands=(0xaa, 0xbb,),
                                  addr_mode=AddressModes.Absolute)
        self.assertTrue(len(intable), 3)
        mem.set_instruction(0xF000, intable)
        self.assertTrue(mem.is_instruction_start(0xF000))
        self.assertTrue(mem.is_instruction_continuation(0xF001))
        mem.annotate_jump_target(0xF001) # middle of Instruction
        analyzer.analyze(mem)
        self.assertEqual(table._symbols_by_address, {}) # xxx add accessor

    def test_analyze_doesnt_overwrite_existing_code_symbol(self):
        table = symbols.SymbolTable()
        analyzer = symbols.SymbolCreatingAnalyzer(table)
        mem = memory.Memory(bytearray(0x10000))
        intable = disasm.Instruction(location=0xF000, opcode=0x60,
                                  addr_mode=AddressModes.Implied)
        mem.set_instruction(0xF000, intable)
        mem.annotate_jump_target(0xF000)
        mem.annotate_call_target(0xF000)
        # a user-provided (non-weak) symbol already names this code target
        table[0xf000] = symbols.Symbol(address=0xf000, name="print")
        analyzer.analyze(mem)
        # analysis must keep the user symbol, not replace it with sub_f000
        self.assertEqual(table[0xf000].name, "print")
        self.assertFalse(table[0xf000].weak)


class DeviceSymbolTableTests(unittest.TestCase):
    """Validate the per-device symbol tables in devices.py.

    The symbol data moved from module-level ``*_SYMBOLS`` lists in symbols.py
    into ``Devices[...]['symbol_table']``; the original tests scanned the old
    location and so validated nothing.  These iterate the real tables.
    """

    _AS740_NAME = re.compile(r'\A[a-z\.\$_]{1}[\da-z\.\$_]{0,78}\Z', re.IGNORECASE)

    def _tables(self):
        # devices alias shared table objects; de-dupe scans by identity
        unique = {}
        for name, dev in Devices.items():
            tbl = dev["symbol_table"]
            unique[id(tbl)] = (name, tbl)
        return list(unique.values())

    def test_addresses_are_in_range(self):
        for name, tbl in self._tables():
            for s in tbl:
                self.assertTrue(0 <= s.address <= 0xFFFF,
                                "address 0x%x out of range in %s" % (s.address, name))

    def test_each_symbol_has_name_and_comment(self):
        for name, tbl in self._tables():
            for s in tbl:
                self.assertTrue(len(s.name) > 1, "short name %r in %s" % (s.name, name))
                self.assertTrue(hasattr(s, "comment"))

    def test_symbol_names_never_repeat(self):
        for name, tbl in self._tables():
            seen = set()
            for s in tbl:
                self.assertNotIn(s.name, seen, "name %r repeats in %s" % (s.name, name))
                seen.add(s.name)

    def test_symbol_addresses_never_repeat(self):
        for name, tbl in self._tables():
            seen = set()
            for s in tbl:
                self.assertNotIn(s.address, seen,
                                 "address 0x%x repeats in %s" % (s.address, name))
                seen.add(s.address)

    def test_symbol_names_are_legal_for_as740(self):
        for name, tbl in self._tables():
            for s in tbl:
                self.assertTrue(self._AS740_NAME.match(s.name),
                                "name %r not valid for as740 in %s" % (s.name, name))
