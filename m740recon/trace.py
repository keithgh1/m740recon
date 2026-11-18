import heapq
import os
from operator import attrgetter
from m740recon.tables import AddressModes, FlowTypes
from m740recon.dataflow import _Regs, _apply_effects

class Tracer(object):
    def __init__(self, memory, entry_points, vectors, traceable_range,
                 analyze=False, readonly_ranges=(), discover_tables=False):
        self.memory = memory
        self.traceable_range = traceable_range
        self.queue = TraceQueue()
        # optional value-tracking analysis: resolve computed jumps/calls
        self.analyze = analyze
        self.readonly_ranges = list(readonly_ranges)
        # optional: enumerate ROM jump tables feeding computed jumps
        self.discover_tables = discover_tables
        # targets already enqueued by analysis.  A target that cannot actually
        # be decoded (e.g. it overlaps a previously decoded instruction) stays
        # is_unknown forever; without this set it would be rediscovered on every
        # pass and the analyze loop in trace() would never terminate.
        self._analysis_seen = set()

        for address in entry_points:
            if address not in traceable_range:
                msg = "Entry point address 0x%04X is outside of traceable range"
                raise ValueError(msg % address)
            self.memory.annotate_entry_point(address)
            self.enqueue_address(address)

        for address in vectors:
            if address not in traceable_range:
                msg = "Vector address 0x%04X is outside of traceable range"
                raise ValueError(msg % address)
            self.enqueue_vector(address)

    def trace(self, disassemble_func):
        self._decode = disassemble_func
        self._run_queue(disassemble_func)
        if self.analyze:
            # Iterate: a value-propagation pass over the discovered code may
            # resolve indirect jumps to new code, which is then decoded and may
            # itself contain more indirect jumps.  Each round adds >=1 target,
            # so this terminates.
            while True:
                discovered = self._analyze_pass()
                if not discovered:
                    break
                self._run_queue(disassemble_func)
        self.mark_data_references()

    def _run_queue(self, disassemble_func):
        mem_len = len(self.memory)

        while len(self.queue):
            ps = self.queue.pop() # current processor state

            inst = disassemble_func(self.memory, ps.pc)

            if "LOG" in os.environ: # XXX hack
                self._log(inst, ps)

            inst_len = len(inst)
            if (ps.pc + inst_len) >= mem_len:
                continue  # ignore instruction that would wrap around memory

            if self.memory.is_instruction_start(ps.pc):
                # tracing previously seen instruction with new processor state
                pass
            elif not self.memory.is_unknown(ps.pc, inst_len):
                # ignore new instruction that would overlap a previous marking
                continue
            else:
                # mark new instruction
                self.memory.set_instruction(ps.pc, inst)

            new_ps = ps.copy()  # new state after this instruction
            new_ps.pc = (ps.pc + inst_len) & 0xFFFF

            # trace this instruction
            handler = self._instruction_handlers.get(inst.opcode)
            if handler is None:
                handler = self._generic_handlers[inst.flow_type]
            handler(self, inst, ps, new_ps)

    # ---- value-tracking analysis (opt-in) --------------------------------

    def _is_readonly(self, address):
        for start, end in self.readonly_ranges:
            if start <= address < end:
                return True
        return False

    def _analyze_pass(self):
        """Walk the discovered code in address order tracking block-local
        constant register / zero-page values, and resolve indirect jumps and
        calls.  Returns the list of newly discovered (and now enqueued) code
        targets.

        Soundness: register/zp values are only carried across a straight-line
        fallthrough from the immediately preceding instruction, and are reset
        at any block leader (jump/call target / entry point) and after any
        call.  A value is therefore used only when it is provably constant on
        the path reaching the indirect branch, so a resolved target is always
        real code (never data).
        """
        regs = _Regs()
        prev_falls_through = False
        discovered = []
        table_pointers = []
        for address, inst in list(self.memory.iter_instructions()):
            leader = (self.memory.is_jump_target(address) or
                      self.memory.is_call_target(address) or
                      self.memory.is_entry_point(address))
            if leader or not prev_falls_through:
                regs = _Regs()

            target = self._resolve_indirect(inst, regs)
            if target is not None and target in self.traceable_range:
                self.memory.computed_targets.add(target)
                is_call = inst.flow_type == FlowTypes.IndirectSubroutineCall
                if is_call:
                    self.memory.annotate_call_target(target)
                else:
                    self.memory.annotate_jump_target(target)
                if self.memory.is_unknown(target) and target not in self._analysis_seen:
                    self._analysis_seen.add(target)
                    self.enqueue_address(target)
                    discovered.append(target)
            elif (target is None and self.discover_tables and
                  inst.addr_mode == AddressModes.ZeroPageIndirect):
                for ptr_addr, tgt in self._detect_jump_table(inst, regs):
                    self.memory.computed_targets.add(tgt)
                    self.memory.annotate_jump_target(tgt)
                    table_pointers.append(ptr_addr)
                    if self.memory.is_unknown(tgt) and tgt not in self._analysis_seen:
                        self._analysis_seen.add(tgt)
                        self.enqueue_address(tgt)
                        discovered.append(tgt)

            regs = _apply_effects(inst, regs)
            prev_falls_through = inst.flow_type in (
                FlowTypes.Continue, FlowTypes.ConditionalJump,
                FlowTypes.SubroutineCall, FlowTypes.IndirectSubroutineCall)

        # mark each table pointer so it renders as a .word once the loop over
        # decoded instructions is finished (avoids mutating during iteration)
        for ptr_addr in table_pointers:
            if (self.memory.is_unknown(ptr_addr) and
                    self.memory.is_unknown((ptr_addr + 1) & 0xFFFF)):
                self.memory.set_vector(ptr_addr)
        return discovered

    _TABLE_CAP = 256

    def _detect_jump_table(self, inst, regs):
        """If the jmp/jsr [zp] pointer was loaded from a contiguous [lo,hi]
        table in ROM, enumerate plausible entries and return (ptr_addr, target)
        pairs.  Conservative: every entry must be a readonly, in-range, non-null
        pointer, and at least two entries must qualify.  Enumeration stops at
        the first entry that overlaps already-typed bytes or whose target does
        not look like the start of code (see _plausible_entry), so it does not
        run past the end of the table into neighbouring data."""
        zp = inst.zp_addr
        lo_src = regs.zp_src.get(zp)
        hi_src = regs.zp_src.get((zp + 1) & 0xFF)
        if not (lo_src and hi_src):
            return []
        if lo_src[0] != 'idx' or hi_src[0] != 'idx' or lo_src[2] != hi_src[2]:
            return []
        base, base_hi = lo_src[1], hi_src[1]
        if base_hi != (base + 1) & 0xFFFF:        # contiguous lo,hi,lo,hi,...
            return []
        entries = []
        for i in range(self._TABLE_CAP):
            ptr = (base + 2 * i) & 0xFFFF
            if not (self._is_readonly(ptr) and self._is_readonly((ptr + 1) & 0xFFFF)):
                break
            if not (self.memory.is_vector_start(ptr) or
                    self.memory.is_unknown(ptr, 2)):
                break                   # table cannot overlap code or data
            tgt = self.memory[ptr] | (self.memory[(ptr + 1) & 0xFFFF] << 8)
            if tgt not in self.traceable_range or tgt in (0x0000, 0xFFFF):
                break
            if not self._plausible_entry(tgt):
                break
            entries.append((ptr, tgt))
        return entries if len(entries) >= 2 else []

    _TRIAL_LEN = 64     # instructions decoded when vetting a table target
    _FILL_LEN = 4       # identical 0x00/0xFF bytes that count as fill

    def _is_fill(self, address):
        first = self.memory[address]
        if first not in (0x00, 0xFF):
            return False
        for i in range(1, self._FILL_LEN):
            if self.memory[(address + i) & 0xFFFF] != first:
                return False
        return True

    def _plausible_entry(self, target):
        """True when `target` can start code: it is a known instruction start,
        or a straight-line trial decode from it reaches a flow stop or known
        code without hitting fill (erased/blank ROM), an illegal opcode, or
        the middle of another instruction or data."""
        decode = getattr(self, "_decode", None)
        pc = target
        for _ in range(self._TRIAL_LEN):
            if self.memory.is_instruction_start(pc):
                return True
            if not self.memory.is_unknown(pc) or self._is_fill(pc):
                return False
            if decode is None:
                return True
            inst = decode(self.memory, pc)
            if inst.illegal or pc + len(inst) >= len(self.memory):
                return False
            if not self.memory.is_unknown(pc, len(inst)):
                return False
            if inst.flow_type not in (FlowTypes.Continue,
                                      FlowTypes.ConditionalJump,
                                      FlowTypes.SubroutineCall,
                                      FlowTypes.IndirectSubroutineCall):
                return True
            pc = (pc + len(inst)) & 0xFFFF
        return True

    def _resolve_indirect(self, inst, regs):
        """Return the target of an indirect jump/call if statically known."""
        am = inst.addr_mode
        if am == AddressModes.IndirectAbsolute:           # jmp [abs]
            ptr = inst.abs_addr
            if self._is_readonly(ptr) and self._is_readonly((ptr + 1) & 0xFFFF):
                return self.memory[ptr] | (self.memory[(ptr + 1) & 0xFFFF] << 8)
            return None
        if am == AddressModes.ZeroPageIndirect:           # jmp [zp] / jsr [zp]
            lo = regs.zp.get(inst.zp_addr)
            hi = regs.zp.get((inst.zp_addr + 1) & 0xFF)
            if lo is not None and hi is not None:
                return lo | (hi << 8)
            return None
        return None

    def _log(self, inst, ps):
        print("TRACE " + str(ps).ljust(24) + str(inst))

    # Handlers for specific instructions

    _instruction_handlers = {}

    # Fallback handlers for when an instruction handler is not available

    def _trace_generic_continue(self, inst, ps, new_ps):
        self.enqueue_processor_state(new_ps)

    def _trace_generic_stop(self, inst, ps, new_ps):
        pass

    def _trace_generic_conditional_jump(self, inst, ps, new_ps):
        # don't take the branch
        self.enqueue_processor_state(new_ps)

        # take the branch
        new_ps = new_ps.copy()
        new_ps.pc = inst.code_ref_address
        self.enqueue_processor_state(new_ps)
        self.memory.annotate_jump_target(inst.code_ref_address)

    def _trace_generic_unconditional_jump(self, inst, ps, new_ps):
        self.memory.annotate_jump_target(inst.code_ref_address)
        new_ps.pc = inst.code_ref_address
        self.enqueue_processor_state(new_ps)

    def _trace_generic_subroutine_call(self, inst, ps, new_ps):
        # enqueue the next instruction after call returns
        # XXX the processor flags are dropped here because we don't
        # know how the subroutine would have affected them.
        new_ps2 = ProcessorState(pc=new_ps.pc)
        self.enqueue_processor_state(new_ps2)

        # enqueue the subroutine called
        new_ps.pc = inst.code_ref_address
        self.memory.annotate_call_target(inst.code_ref_address)
        self.enqueue_processor_state(new_ps)

    def _trace_generic_indirect_unconditional_jump(self, inst, ps, new_ps):
        pass

    def _trace_generic_indirect_subroutine_call(self, inst, ps, new_ps):
        # enqueue the next instruction after call returns
        # XXX the processor flags are dropped here because we don't
        # know how the subroutine would have affected them.
        new_ps2 = ProcessorState(pc=new_ps.pc)
        self.enqueue_processor_state(new_ps2)

    def _trace_generic_subroutine_return(self, inst, ps, new_ps):
        pass

    _generic_handlers = {
        FlowTypes.Continue:          _trace_generic_continue,
        FlowTypes.Stop:             _trace_generic_stop,
        FlowTypes.UnconditionalJump: _trace_generic_unconditional_jump,
        FlowTypes.ConditionalJump:   _trace_generic_conditional_jump,
        FlowTypes.SubroutineCall:    _trace_generic_subroutine_call,
        FlowTypes.IndirectUnconditionalJump: _trace_generic_indirect_unconditional_jump,
        FlowTypes.SubroutineReturn:  _trace_generic_subroutine_return,
        FlowTypes.IndirectSubroutineCall: _trace_generic_indirect_subroutine_call,
    }

    def enqueue_processor_state(self, ps):
        if ps.pc in self.traceable_range:
            if self.memory.is_unknown(ps.pc):
                self.queue.push(ps)
            elif self.memory.is_instruction_start(ps.pc):
                # we need to queue it again to so it's traced with the current
                # processor state
                self.queue.push(ps)

    def enqueue_address(self, address):
        if address in self.traceable_range:
            ps = ProcessorState(pc=address)
            self.enqueue_processor_state(ps)

    def enqueue_vector(self, address):
        if address not in self.traceable_range:
            return
        # respect a control-file range that already typed these two bytes as
        # data/word/text: don't reclassify them as a vector or trace through them
        if (not self.memory.is_vector_start(address) and
                not self.memory.is_unknown(address, 2)):
            return
        self.memory.set_vector(address)
        target = self.memory.read_word(address)
        # TODO 0xFFFF can be replaced with a check for is unknown or is
        # start of instruction, since 0xFFFF is the reset vector
        if (target != 0xFFFF) and (target in self.traceable_range):
            self.memory.annotate_jump_target(target)
            self.enqueue_address(target)

    def mark_data_references(self):
        # mark addresses used in instruction data references as data
        for _, inst in self.memory.iter_instructions():
            # the data reference may actually be an address of code, so we
            # only mark it if it is unknown
            if inst.data_ref_address is not None:
                if self.memory.is_unknown(inst.data_ref_address):
                    self.memory.set_data(inst.data_ref_address)

        # when an instruction uses indexed addressing, we know the start
        # address of the data from data_ref_address but we do not know the
        # length of the data.  we assume all unknown bytes that follow the
        # data start address are part of the same chunk of data.
        for address in self.traceable_range:
            if address < 0xffff: # XXX hack, < 0xffff should not be needed
                if self.memory.is_data(address):
                    next_address = (address + 1) & 0xFFFF
                    if self.memory.is_unknown(next_address):
                        self.memory.set_data(next_address)


class TraceQueue(object):
    '''A queue for holding processor states that need to be traced.  States may
    be pushed in any order but are always popped sorted by the program counter.
    A state that was pushed will be ignored if it is pushed again, even if it
    was popped off.'''

    def __init__(self):
        self.untraced_processor_states = SortedSet(key=attrgetter('pc'))
        self.traced_processor_states = set()

    def __len__(self):
        return len(self.untraced_processor_states)

    def push(self, processor_state):
        if processor_state not in self.traced_processor_states:
            if processor_state not in self.untraced_processor_states:
                self.untraced_processor_states.add(processor_state)

    def pop(self):
        if self.untraced_processor_states:
            processor_state = self.untraced_processor_states.pop()
            self.traced_processor_states.add(processor_state)
            return processor_state
        raise KeyError("pop from empty trace queue")


class SortedSet(object):
    '''A set-like object where pop() returns items in sorted order.

    A heap of (key, sequence, item) with lazy deletion plus a membership set:
    add / pop are O(log n) and membership is O(1).  (A sorted list re-sorted
    on every add with linear membership tests made tracing quadratic.)'''

    def __init__(self, items=None, key=None):
        self.key = key if key is not None else (lambda item: item)
        self._heap = []
        self._members = set()
        self._seq = 0
        if items is not None:
            for item in items:
                self.add(item)

    def __len__(self):
        return len(self._members)

    def __contains__(self, item):
        return item in self._members

    def __iter__(self):
        return iter(sorted(self._members, key=self.key))

    @property
    def items(self):
        return sorted(self._members, key=self.key)

    def __eq__(self, other):
        return sorted(other) == self.items

    def add(self, item):
        if item not in self._members:
            self._members.add(item)
            self._seq += 1
            heapq.heappush(self._heap, (self.key(item), self._seq, item))

    def remove(self, item):
        try:
            self._members.remove(item)      # the heap entry is skipped on pop
        except KeyError:
            raise KeyError(item)

    def pop(self):
        while self._heap:
            _, _, item = heapq.heappop(self._heap)
            if item in self._members:
                self._members.remove(item)
                return item
        raise KeyError("pop from empty SortedSet")


Unknown = object()


class ProcessorState(object):
    __slots__ = ('pc')

    def __init__(self, pc=Unknown):
        self.pc = pc  # program counter

    def __repr__(self):
        return "<ProcessorState %s>" % str(self)

    def __str__(self):
        pc = "    " if self.pc is Unknown else "%04x" % self.pc
        return "pc=%s" % pc

    def __eq__(self, other):
        return self.pc == other.pc

    def __hash__(self):
        return hash(self.pc)

    def copy(self):
        return ProcessorState(pc=self.pc)
