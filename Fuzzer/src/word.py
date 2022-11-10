"""
SpecDoctor Helper Functions for Generating Word

TODO: Copyright
"""
import random

from typing import List
from internals import TPE, WordSpec, wordgen, wordread
from riscv_definitions import * # TODO: Fix to get only admitted CSRs


# ================================================================
# WordSpec Helper Functions
#
# Modify WordSpec to generate syntactically correct instructions
# (Do not return, but modify)
# ================================================================


@wordgen(TPE.CFG)
def wgen_jal(spec: WordSpec):
    spec.insts = [spec.syntax]


@wordgen(TPE.CFG)
def wgen_jalr(spec: WordSpec):
    spec.insts = ['la R1, S0',
                  spec.syntax]

    spec.symbols.append('S0')

    # spec.insts = ['andi R2, R2, 0xe',
    #               'la R1, S0',
    #               'add R1, R1, R2',
    #               spec.syntax]
    # spec.xregs.append('R2')
    # spec.symbols.append('S0')


@wordgen(TPE.CFG)
def wgen_br(spec: WordSpec):
    spec.insts = [spec.syntax]


@wordgen(TPE.CFG)
def wgen_eret(spec: WordSpec):
    if spec.syntax == 'mret': epc = 'mepc'
    elif spec.syntax == 'sret': epc = 'sepc'
    else: epc = 'uepc'

    spec.insts = ['la R0, S0',
                  'csrrw zero, {}, R0'.format(epc),
                  spec.syntax]
    spec.xregs.append('R0')
    spec.symbols.append('S0')


@wordgen(TPE.CFG)
def wgen_ret(spec: WordSpec):
    spec.insts = [spec.syntax]


@wordgen(TPE.CALL)
def wgen_call(spec: WordSpec):
    spec.insts = [spec.syntax]


# Mask the operand register, so that the memory access
# could occur in the valid range
# NOTE: Valid range size = 1kB (=10 bits), aligned to 8Bytes
@wordgen(TPE.MEM)
def wgen_mr(spec: WordSpec):
    spec.insts = ['andi R1, R1, 0x3f8',
                  'la R2, S0',
                  'add R1, R1, R2',
                  spec.syntax]
    spec.xregs.append('R2')
    spec.symbols.append('S0')


@wordgen(TPE.MEM)
def wgen_mw(spec: WordSpec):
    spec.insts = ['andi R1, R1, 0x3f8',
                  'la R2, S0',
                  'add R1, R1, R2',
                  spec.syntax]
    spec.xregs.append('R2')
    spec.symbols.append('S0')


@wordgen(TPE.MEM)
def wgen_atomic(spec: WordSpec):
    spec.insts = ['andi R1, R1, 0x3f8',
                  'la R3, S0',
                  'add R1, R1, R3',
                  spec.syntax]
    spec.xregs.append('R3')
    spec.symbols.append('S0')


@wordgen(TPE.CSR)
def wgen_csr_r(spec: WordSpec):
    csr = random.choice(sum(tuple(CSRS.values()), ()))

    if 'pmpaddr' in csr:
        raise Exception('CSR r/w pmpaddr not supported')
    else:
        bits = random.choice([1,3])
        offset = random.randint(0, 31)
        spec.insts = [f'addi R2, zero, {bits}',
                      f'slli R2, R2, {offset}',
                      spec.syntax.format(csr)]
        spec.xregs.append('R2')


@wordgen(TPE.CSR)
def wgen_csr_i(spec: WordSpec):
    csr = random.choice(sum(tuple(CSRS.values()), ()))

    spec.insts = [spec.syntax.format(csr)]


@wordgen(TPE.CSR)
def wgen_sfence(spec: WordSpec):
    spec.insts = ['lui R2, 0xfffff',
                  'and R0, R0, R2',
                  'addi R1, zero, 0', # NOTE: No ASID
                  spec.syntax]
    spec.xregs.append('R2')


@wordgen(TPE.NONE)
def wgen_fp(spec: WordSpec):
    rm = random.choice(['rne', 'rtz', 'rdn',
                        'rup', 'rmm', 'dyn'])

    spec.insts = [spec.syntax.format(rm)]


@wordgen(TPE.NONE)
def wgen_default(spec: WordSpec):
    spec.insts = [spec.syntax]


@wordgen(TPE.NONE)
def wgen_delay(spec: WordSpec):
    spec.insts = ['mul R0, R0, x30']

    spec.xregs.append('R0')


@wordgen(TPE.NONE)
def wgen_nop(spec: WordSpec):
    spec.insts = ['nop']


@wordread()
def wgen_read(spec: WordSpec, insts: List[str]) -> (str, TPE):
    spec.insts = insts

    op = spec.insts[-1].split(' ')[0]
    tpe = Tpe_map[op]

    return op, tpe

# ================================================================
# Opcodes to Helper Function Map
# ================================================================
Wgen_map = {
    **{k: wgen_default for k in rv_ops.keys()},
    **{'jal': wgen_jal},
    **{'jalr': wgen_jalr},
    **{k: wgen_br for k in rv32i_btype.keys()},
    **{k: wgen_eret for k in trap_ret.keys()},
    **{'ret': wgen_ret},
    **{'call': wgen_call},
    **{k: wgen_mr for k in {'lb', 'lh', 'lw', 'ld', 'lbu',
                           'lhu', 'lwu', 'flw', 'fld', 'flq'}},
    **{k: wgen_mw for k in {'sb', 'sh', 'sw', 'sd',
                            'fsw', 'fsd', 'fsq'}},
    **{k: wgen_atomic for k in {*rv32a_rtype.keys(),
                                *rv64a_rtype.keys()}},
    **{k: wgen_csr_r for k in {'csrrw', 'csrrs', 'csrrc'}},
    **{k: wgen_csr_i for k in {'csrrwi', 'csrrsi', 'csrrci'}},
    **{'sfence.vma': wgen_sfence},
    **{k: wgen_fp for k in {*rv32f.keys(), *rv64f.keys(),
                            *rv32d.keys(), *rv64d.keys(),
                            *rv32q.keys(), *rv64q.keys()} -
                            {'flw', 'fld', 'flq', 'fsw', 'fsd', 'fsq'}}
}

Tpe_map = {
    **{k: TPE.NONE for k in rv_ops.keys()},
    **{'nop': TPE.NONE},
    **{'ret': TPE.CFG},
    **{'call': TPE.CALL},
    **{'jal': TPE.CFG},
    **{'jalr': TPE.CFG},
    **{k: TPE.CFG for k in rv32i_btype.keys()},
    **{k: TPE.CFG for k in trap_ret.keys()},
    **{k: TPE.MEM for k in {'lb', 'lh', 'lw', 'ld', 'lbu',
                           'lhu', 'lwu', 'flw', 'fld', 'flq'}},
    **{k: TPE.MEM for k in {'sb', 'sh', 'sw', 'sd',
                            'fsw', 'fsd', 'fsq'}},
    **{k: TPE.MEM for k in {*rv32a_rtype.keys(),
                            *rv64a_rtype.keys()}},
    **{k: TPE.CSR for k in {'csrrw', 'csrrs', 'csrrc'}},
    **{k: TPE.CSR for k in {'csrrwi', 'csrrsi', 'csrrci'}},
    **{'sfence.vma': TPE.CSR},
    **{k: TPE.NONE for k in {*rv32f.keys(), *rv64f.keys(),
                            *rv32d.keys(), *rv64d.keys(),
                            *rv32q.keys(), *rv64q.keys()} -
                            {'flw', 'fld', 'flq', 'fsw', 'fsd', 'fsq'}}
}
