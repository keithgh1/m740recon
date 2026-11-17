"""Block-local constant propagation over 740 instructions.

Shared by the tracer (computed-jump resolution) and the signal access
classifier.  Values are only ever proven constants: anything not explicitly
modeled forgets the affected state.
"""

from m740recon.tables import AddressModes, FlowTypes


_ZP_MODES = frozenset((
    AddressModes.ZeroPage, AddressModes.ZeroPageX, AddressModes.ZeroPageY,
    AddressModes.IndirectX, AddressModes.IndirectY, AddressModes.ZeroPageIndirect,
    AddressModes.ZeroPageBit, AddressModes.ZeroPageBitRelative,
    AddressModes.ZeroPageImmediate,
))

# implied instructions that provably do not change A/X/Y (flag ops, nop, flow)
_PRESERVES_REGS = frozenset((
    'clc', 'sec', 'cld', 'sed', 'clv', 'cli', 'sei', 'clt', 'set',
    'nop', 'brk', 'rti', 'rts',
))


class _Regs(object):
    '''Abstract machine state.  Each of A/X/Y and each tracked zero-page byte
    is a known int or None (unknown).  The parallel *_src / zp_src fields carry
    provenance: ('idx', base, reg) marks a byte loaded from an indexed table
    base,reg -- used to recognize computed jump tables.'''
    __slots__ = ('a', 'x', 'y', 'zp', 'a_src', 'x_src', 'y_src', 'zp_src')

    def __init__(self):
        self.a = None
        self.x = None
        self.y = None
        self.zp = {}
        self.a_src = None
        self.x_src = None
        self.y_src = None
        self.zp_src = {}


def _load_value_and_src(inst, regs):
    """Return (value, src) a load instruction places into its register."""
    am = inst.addr_mode
    if am == AddressModes.Immediate:
        return inst.immediate, None
    if am == AddressModes.ZeroPage:
        return regs.zp.get(inst.zp_addr), regs.zp_src.get(inst.zp_addr)
    if am == AddressModes.AbsoluteX:
        return None, ('idx', inst.abs_addr, 'x')
    if am == AddressModes.AbsoluteY:
        return None, ('idx', inst.abs_addr, 'y')
    return None, None


def _apply_effects(inst, regs):
    '''Transfer function over _Regs for one instruction.  Conservative: any
    effect not explicitly modeled forgets the affected register(s) / the zero
    page, so a tracked value is only ever a proven constant.'''
    flow = inst.flow_type
    if flow in (FlowTypes.SubroutineCall, FlowTypes.IndirectSubroutineCall):
        return _Regs()                       # callee may clobber everything
    mnemonic = inst.disasm_template.split(' ', 1)[0]
    am = inst.addr_mode
    if mnemonic == 'lda':
        regs.a, regs.a_src = _load_value_and_src(inst, regs)
    elif mnemonic == 'ldx':
        regs.x, regs.x_src = _load_value_and_src(inst, regs)
    elif mnemonic == 'ldy':
        regs.y, regs.y_src = _load_value_and_src(inst, regs)
    elif mnemonic == 'sta':
        if am == AddressModes.ZeroPage:
            regs.zp[inst.zp_addr] = regs.a
            regs.zp_src[inst.zp_addr] = regs.a_src
        elif am in _ZP_MODES:
            regs.zp = {}
            regs.zp_src = {}
    elif mnemonic == 'stx':
        if am == AddressModes.ZeroPage:
            regs.zp[inst.zp_addr] = regs.x
            regs.zp_src[inst.zp_addr] = regs.x_src
        elif am in _ZP_MODES:
            regs.zp = {}
            regs.zp_src = {}
    elif mnemonic == 'sty':
        if am == AddressModes.ZeroPage:
            regs.zp[inst.zp_addr] = regs.y
            regs.zp_src[inst.zp_addr] = regs.y_src
        elif am in _ZP_MODES:
            regs.zp = {}
            regs.zp_src = {}
    elif mnemonic == 'tax':
        regs.x, regs.x_src = regs.a, regs.a_src
    elif mnemonic == 'tay':
        regs.y, regs.y_src = regs.a, regs.a_src
    elif mnemonic == 'txa':
        regs.a, regs.a_src = regs.x, regs.x_src
    elif mnemonic == 'tya':
        regs.a, regs.a_src = regs.y, regs.y_src
    elif mnemonic in _PRESERVES_REGS:
        pass
    else:
        regs.a = regs.x = regs.y = None
        regs.a_src = regs.x_src = regs.y_src = None
        if am in _ZP_MODES:
            regs.zp = {}
            regs.zp_src = {}
    return regs
