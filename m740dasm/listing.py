import struct

class Printer(object):
    def __init__(self, memory, start_address, symbol_table, comments=None,
                 show_xrefs=False):
        self.memory = memory
        self.start_address = start_address
        self.symbol_table = symbol_table
        self.comments = comments or {}        # addr -> user comment text
        self.show_xrefs = show_xrefs
        self.xrefs = {}                       # addr -> set of referencing addresses
        self.last_line_type = None

    def print_listing(self):
        if self.show_xrefs:
            self.xrefs = self._compute_xrefs()
        self.print_header()
        self.print_symbols()

        address = self.start_address
        while address < len(self.memory):
            self.print_blank(address)
            self.print_comment(address)
            self.print_label(address)

            if self.memory.is_instruction_start(address):
                inst = self.memory.get_instruction(address)
                self.print_instruction_line(address, inst)
                address += len(inst)
            else:
                if self.memory.is_vector_start(address):
                    self.print_vector_line(address)
                    address += 2
                elif self.memory.is_word_start(address):
                    self.print_word_line(address)
                    address += 2
                elif self.memory.is_text_start(address):
                    address += self.print_text_run(address)
                elif self.memory.is_data(address):
                    self.print_data_line(address)
                    address += 1
                elif self.memory.is_unknown(address):
                    self.print_unknown_line(address)
                    address += 1
                else:
                    msg = "Unhandled location type %r at 0x%04x" % (
                        self.memory.types[address], address)
                    raise NotImplementedError(msg) # always a bug

    def print_header(self):
        print('    .area CODE1 (ABS)')
        print('    .org 0x%04x\n' % self.start_address)

    def is_equate(self, address):
        """A symbol emitted as a constant equate rather than a body label.

        Symbols below the listed image are equates, as before.  Direct-page
        (zero-page) symbols are *always* equates, even when the image starts at
        0x0000: as740 assembles a reference to a body label in absolute mode,
        but a reference to an equate whose value is < 0x100 in zero-page mode.
        Emitting a direct-page address as a body label would therefore grow
        every zero-page instruction by one byte and shift all following code.
        """
        return address < self.start_address or address < 0x100

    def print_symbols(self):
        used_symbols = set()
        for address, inst in self.memory.iter_instructions():
            if inst.data_ref_address in self.symbol_table:
                used_symbols.add(inst.data_ref_address)

        for address, target in self.memory.iter_vectors():
            if target in self.symbol_table:
                used_symbols.add(target)

        for address in sorted(used_symbols):
            if self.is_equate(address):
                symbol = self.symbol_table[address]
                line = ("    %s = 0x%02x" % (symbol.name, symbol.address)).ljust(28)
                if symbol.comment:
                    line += ";%s" % symbol.comment
                print(line)
        print('')

    def print_blank(self, address):
        typ = self.memory.types[address]
        if self.last_line_type is not None:
            if typ != self.last_line_type:
                if address not in self.symbol_table:
                    print('')
        self.last_line_type = typ

    def _compute_xrefs(self):
        """Map each referenced address to the set of instructions that
        reference it (via a static branch/call target or a data operand)."""
        refs = {}
        for address, inst in self.memory.iter_instructions():
            for target in (inst.code_ref_address, inst.data_ref_address):
                if target is not None:
                    refs.setdefault(target, set()).add(address)
        return refs

    def _format_xrefs(self, address, limit=8):
        sources = sorted(self.xrefs[address])
        shown = ", ".join(self.format_abs_address(s) for s in sources[:limit])
        if len(sources) > limit:
            shown += ", +%d more" % (len(sources) - limit)
        return shown

    def print_comment(self, address):
        text = self.comments.get(address)
        if text:
            for line in text.split("\n"):
                print("    ;%s" % line)

    def print_label(self, address):
        # Addresses emitted as equates must not also be emitted as body labels,
        # or the symbol would be defined twice (and as an absolute-mode label).
        if address in self.symbol_table and not self.is_equate(address):
            print("")
            if self.show_xrefs and address in self.xrefs:
                print("    ; xref: %s" % self._format_xrefs(address))
            print("%s:" % self.format_abs_address(address))

    def print_data_line(self, address):
        self._print_byte_line(address, "DATA")

    def print_unknown_line(self, address):
        self._print_byte_line(address, "UNKNOWN")

    def _print_byte_line(self, address, tag):
        line = ('    .byte 0x%02x' % self.memory[address]).ljust(28)
        line += ';%04x  %02x          %s %s ' % (
            address,
            self.memory[address],
            tag,
            self._data_byte_repr(self.memory[address])
            )
        print(line)

    def _data_byte_repr(self, b):
        if (b >= 0x20) and (b <= 0x7e):  # printable 7-bit ascii
            return "0x%02x '%s'" % (b, chr(b))
        else:
            return "0x%02x" % b

    def print_word_line(self, address):
        lo = self.memory[address]
        hi = self.memory[(address + 1) & 0xFFFF]
        line = ('    .word 0x%04x' % (lo | (hi << 8))).ljust(28)
        line += ';%04x  %02x %02x       WORD' % (address, lo, hi)
        print(line)

    def _is_ascii_safe(self, b):
        # printable ASCII that as740 accepts unescaped inside .ascii "..."
        return 0x20 <= b <= 0x7e and b not in (0x22, 0x5c)  # exclude " and \

    def print_text_run(self, address):
        """Render a text region: maximal runs of safe printable characters as
        .ascii, anything else as .byte.  Returns the number of bytes consumed."""
        end = address + 1
        while end < len(self.memory) and self.memory.is_text_continuation(end):
            end += 1
        a = address
        while a < end:
            if self._is_ascii_safe(self.memory[a]):
                start = a
                chars = []
                while a < end and self._is_ascii_safe(self.memory[a]):
                    chars.append(chr(self.memory[a]))
                    a += 1
                text = ''.join(chars)
                line = ('    .ascii "%s"' % text).ljust(28)
                line += ';%04x  TEXT "%s"' % (start, text)
                print(line)
            else:
                self.print_data_line(a)
                a += 1
        return end - address

    def print_vector_line(self, address):
        target = struct.unpack('<H', self.memory[address:address+2])[0]
        target = self.format_abs_address(target)
        line = ('    .word %s' % target).ljust(28)
        line += ';%04x  %02x %02x       VECTOR' % (address, self.memory[address], self.memory[address+1])
        if address in self.symbol_table:
            comment = self.symbol_table[address].comment
            if comment:
                line += ' ' + comment
        print(line)

    def print_mode_byte_line(self, address):
        line = ('    .byte 0x%02X' % self.memory[address]).ljust(28)
        line += ';%04x  %02x          MODE' % (address, self.memory[address])
        print(line)

    def print_reserved_byte_line(self, address):
        line = ('    .byte 0x%02X' % self.memory[address]).ljust(28)
        line += ';%04x  %02x          RESERVED' % (address, self.memory[address])
        print(line)

    def print_instruction_line(self, address, inst):
        disasm = inst.to_string(self.symbol_table)
        hexdump = (' '.join([ '%02x' % h for h in inst.all_bytes ])).ljust(9)

        line = '    ' + disasm.ljust(24)
        if not line.endswith(' '):
            line += ' '
        line += ';%04x  %s' % (address, hexdump)

        if inst.illegal:
            line += "Illegal instruction"

        print(line)

    def format_abs_address(self, address):
        if address in self.symbol_table:
            return self.symbol_table[address].name
        return '0x%04x' % address
