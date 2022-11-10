"""
File: RISCV Opcodes

TODO: Copyright
"""
from enum import Enum

""" Privilege Levels """
class PRV(Enum):
    M = 'Machine'
    H = 'Hypervisor'
    S = 'Supervisor'
    U = 'User'

""" Instruction Formats """
rv32i_rtype = {
    # opcode: (syntax, xregs, fregs, imms, symbols)
    'add' : ('add R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'sub' : ('sub R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'sll' : ('sll R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'slt' : ('slt R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'sltu': ('sltu R0, R1, R2', ('R0', 'R1', 'R2',), (), (), ()),
    'xor' : ('xor R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'srl' : ('srl R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'sra' : ('sra R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'or'  : ('or R0, R1, R2'  , ('R0', 'R1', 'R2',), (), (), ()),
    'and' : ('and R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ())
}

rv32i_itype = {
    'jalr'  : ('jalr R0, 0(R1)'   , ('R0', 'R1',), (), ()           , ()),
    'lb'    : ('lb R0, I6(R1)'    , ('R0', 'R1',), (), (('I6', 1),) , ()),
    'lh'    : ('lh R0, I6(R1)'    , ('R0', 'R1',), (), (('I6', 2),) , ()),
    'lw'    : ('lw R0, I6(R1)'    , ('R0', 'R1',), (), (('I6', 4),) , ()),
    'lbu'   : ('lbu R0, I6(R1)'   , ('R0', 'R1',), (), (('I6', 1),) , ()),
    'lhu'   : ('lhu R0, I6(R1)'   , ('R0', 'R1',), (), (('I6', 2),) , ()),
    'slli'  : ('slli R0, R1, U5'  , ('R0', 'R1',), (), (('U5', 1),) , ()),
    'srli'  : ('srli R0, R1, U5'  , ('R0', 'R1',), (), (('U5', 1),) , ()),
    'srai'  : ('srai R0, R1, U5'  , ('R0', 'R1',), (), (('U5', 1),) , ()),
    'addi'  : ('addi R0, R1, I12' , ('R0', 'R1',), (), (('I12', 1),), ()),
    'slti'  : ('slti R0, R1, I12' , ('R0', 'R1',), (), (('I12', 1),), ()),
    'sltiu' : ('sltiu R0, R1, I12', ('R0', 'R1',), (), (('I12', 1),), ()),
    'xori'  : ('xori R0, R1, I12' , ('R0', 'R1',), (), (('I12', 1),), ()),
    'ori'   : ('ori R0, R1, I12'  , ('R0', 'R1',), (), (('I12', 1),), ()),
    'andi'  : ('andi R0, R1, I12' , ('R0', 'R1',), (), (('I12', 1),), ()),
    'fence' : ('fence'            , ()           , (), ()           , ()),
    'ecall' : ('ecall'            , ()           , (), ()           , ()),
    'ebreak': ('ebreak'           , ()           , (), ()           , ())
}

rv32i_stype = {
    'sb': ('sb R0, I6(R1)', ('R0', 'R1',), (), (('I6', 1),), ()),
    'sh': ('sh R0, I6(R1)', ('R0', 'R1',), (), (('I6', 2),), ()),
    'sw': ('sw R0, I6(R1)', ('R0', 'R1',), (), (('I6', 4),), ())
}

rv32i_btype = {
    'beq' : ('beq R0, R1, S0' , ('R0', 'R1',), (), (), ('S0',)),
    'bne' : ('bne R0, R1, S0' , ('R0', 'R1',), (), (), ('S0',)),
    'blt' : ('blt R0, R1, S0' , ('R0', 'R1',), (), (), ('S0',)),
    'bge' : ('bge R0, R1, S0' , ('R0', 'R1',), (), (), ('S0',)),
    'bltu': ('bltu R0, R1, S0', ('R0', 'R1',), (), (), ('S0',)),
    'bgeu': ('bgeu R0, R1, S0', ('R0', 'R1',), (), (), ('S0',))
}

rv32i_utype = {
    'lui'  : ('lui R0, U20'  , ('R0',), (), (('U20', 1),), ()),
    'auipc': ('auipc R0, U20', ('R0',), (), (('U20', 1),), ())
}

rv32i_jtype = {
    'jal': ('jal R0, S0', ('R0',), (), (), ('S0',))
}

rv64i_rtype = {
    'addw'  : ('addw R0, R1, R2', ('R0', 'R1', 'R2',), (), (), ()),
    'subw'  : ('subw R0, R1, R2', ('R0', 'R1', 'R2',), (), (), ()),
    'sllw'  : ('sllw R0, R1, R2', ('R0', 'R1', 'R2',), (), (), ()),
    'srlw'  : ('srlw R0, R1, R2', ('R0', 'R1', 'R2',), (), (), ()),
    'sraw'  : ('sraw R0, R1, R2', ('R0', 'R1', 'R2',), (), (), ())
}

rv64i_itype = {
    'lwu'  : ('lwu R0, I6(R1)'   , ('R0', 'R1',), (), (('I6', 4),) , ()),
    'ld'   : ('ld R0, I6(R1)'    , ('R0', 'R1',), (), (('I6', 8),) , ()),
    'slli' : ('slli R0, R1, U6'  , ('R0', 'R1',), (), (('U6', 1),) , ()),
    'srli' : ('srli R0, R1, U6'  , ('R0', 'R1',), (), (('U6', 1),) , ()),
    'srai' : ('srai R0, R1, U6'  , ('R0', 'R1',), (), (('U6', 1),) , ()),
    'addiw': ('addiw R0, R1, I12', ('R0', 'R1',), (), (('I12', 1),), ()),
    'slliw': ('slliw R0, R1, U5' , ('R0', 'R1',), (), (('U5', 1),) , ()),
    'srliw': ('srliw R0, R1, U5' , ('R0', 'R1',), (), (('U5', 1),) , ()),
    'sraiw': ('sraiw R0, R1, U5' , ('R0', 'R1',), (), (('U5', 1),) , ())
}

rv64i_stype = {
    'sd': ('sd R0, I6(R1)', ('R0', 'R1',), (), (('I6', 8),), ())
}

rv_zifencei = {
    'fence.i'   : ('fence.i'          , ()           , (), (), ()),
    'sfence.vma': ('sfence.vma R0, R1', ('R0', 'R1',), (), (), ())
}

rv_zicsr = {
    'csrrw' : ('csrrw R0, {}, R1' , ('R0', 'R1',), (), ()          , ()),
    'csrrs' : ('csrrs R0, {}, R1' , ('R0', 'R1',), (), ()          , ()),
    'csrrc' : ('csrrc R0, {}, R1' , ('R0', 'R1',), (), ()          , ()),
    'csrrwi': ('csrrwi R0, {}, U5', ('R0',)      , (), (('U5', 1),), ()),
    'csrrsi': ('csrrsi R0, {}, U5', ('R0',)      , (), (('U5', 1),), ()),
    'csrrci': ('csrrci R0, {}, U5', ('R0',)      , (), (('U5', 1),), ())
}

rv32m_rtype = {
    'mul'   : ('mul R0, R1, R2'   , ('R0', 'R1', 'R2',), (), (), ()),
    'mulh'  : ('mulh R0, R1, R2'  , ('R0', 'R1', 'R2',), (), (), ()),
    'mulhsu': ('mulhsu R0, R1, R2', ('R0', 'R1', 'R2',), (), (), ()),
    'mulhu' : ('mulhu R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'div'   : ('div R0, R1, R2'   , ('R0', 'R1', 'R2',), (), (), ()),
    'divu'  : ('divu R0, R1, R2'  , ('R0', 'R1', 'R2',), (), (), ()),
    'rem'   : ('rem R0, R1, R2'   , ('R0', 'R1', 'R2',), (), (), ()),
    'remu'  : ('remu R0, R1, R2'  , ('R0', 'R1', 'R2',), (), (), ())
}

rv64m_rtype = {
    'mulw' : ('mulw R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'divw' : ('divw R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'divuw': ('divuw R0, R1, R2', ('R0', 'R1', 'R2',), (), (), ()),
    'remw' : ('remw R0, R1, R2' , ('R0', 'R1', 'R2',), (), (), ()),
    'remuw': ('remuw R0, R1, R2', ('R0', 'R1', 'R2',), (), (), ())
}

rv32a_rtype = {
    'lr.w'     : ('lr.w R0, (R1)'         , ('R0', 'R1',)      , (), (), ()),
    'sc.w'     : ('sc.w R0, R2, (R1)'     , ('R0', 'R1', 'R2',), (), (), ()),
    'amoswap.w': ('amoswap.w R0, R2, (R1)', ('R0', 'R1', 'R2',), (), (), ()),
    'amoadd.w' : ('amoadd.w R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amoxor.w' : ('amoxor.w R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amoand.w' : ('amoand.w R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amoor.w'  : ('amoor.w R0, R2, (R1)'  , ('R0', 'R1', 'R2',), (), (), ()),
    'amomin.w' : ('amomin.w R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amomax.w' : ('amomax.w R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amominu.w': ('amominu.w R0, R2, (R1)', ('R0', 'R1', 'R2',), (), (), ()),
    'amomaxu.w': ('amomaxu.w R0, R2, (R1)', ('R0', 'R1', 'R2',), (), (), ())
}

rv64a_rtype = {
    'lr.d'     : ('lr.d R0, (R1)'         , ('R0', 'R1',)      , (), (), ()),
    'sc.d'     : ('sc.d R0, R2, (R1)'     , ('R0', 'R1', 'R2',), (), (), ()),
    'amoswap.d': ('amoswap.d R0, R2, (R1)', ('R0', 'R1', 'R2',), (), (), ()),
    'amoadd.d' : ('amoadd.d R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amoxor.d' : ('amoxor.d R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amoand.d' : ('amoand.d R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amoor.d'  : ('amoor.d R0, R2, (R1)'  , ('R0', 'R1', 'R2',), (), (), ()),
    'amomin.d' : ('amomin.d R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amomax.d' : ('amomax.d R0, R2, (R1)' , ('R0', 'R1', 'R2',), (), (), ()),
    'amominu.d': ('amominu.d R0, R2, (R1)', ('R0', 'R1', 'R2',), (), (), ()),
    'amomaxu.d': ('amomaxu.d R0, R2, (R1)', ('R0', 'R1', 'R2',), (), (), ())
}

rv32f_rtype = {
    'fadd.s'   : ('fadd.s F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fsub.s'   : ('fsub.s F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fmul.s'   : ('fmul.s F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fdiv.s'   : ('fdiv.s F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fsqrt.s'  : ('fsqrt.s F0, F1, {}'   , ()     , ('F0', 'F1',)      , (), ()),
    'fsgnj.s'  : ('fsgnj.s F0, F1, F2'   , ('R0',), ('F0', 'F1', 'F2',), (), ()), # rm: J(N,)/JX
    'fsgnjn.s' : ('fsgnjn.s F0, F1, F2'  , ('R0',), ('F0', 'F1', 'F2',), (), ()), # rm: J(N,)/JX
    'fsgnjx.s' : ('fsgnjx.s F0, F1, F2'  , ('R0',), ('F0', 'F1', 'F2',), (), ()), # rm: J(N,)/JX
    'fmin.s'   : ('fmin.s F0, F1, F2'    , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: MIN/MAX
    'fmax.s'   : ('fmax.s F0, F1, F2'    , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: MIN/MAX
    'fcvt.w.s' : ('fcvt.w.s R0, F0'      , ('R0',), ('F0',)            , (), ()),
    'fcvt.wu.s': ('fcvt.wu.s R0, F0'     , ('R0',), ('F0',)            , (), ()),
    'fmv.x.w'  : ('fmv.x.w R0, F0'       , ('R0',), ('F0',)            , (), ()),
    'feq.s'    : ('feq.s R0, F0, F1'     , ('R0',), ('F0', 'F1',)      , (), ()),
    'flt.s'    : ('flt.s R0, F0, F1'     , ('R0',), ('F0', 'F1',)      , (), ()),
    'fle.s'    : ('fle.s R0, F0, F1'     , ('R0',), ('F0', 'F1',)      , (), ()),
    'fclass.s' : ('fclass.s R0, F0'      , ('R0',), ('F0',)            , (), ()),
    'fcvt.s.w' : ('fcvt.s.w F0, R0'      , ('R0',), ('F0',)            , (), ()),
    'fcvt.s.wu': ('fcvt.s.wu F0, R0'     , ('R0',), ('F0',)            , (), ()),
    'fmv.w.x'  : ('fmv.w.x F0, R0'       , ('R0',), ('F0',)            , (), ())
}

rv32f_r4type = {
    'fmadd.s' : ('fmadd.s F0, F1, F2, F3, {}' , (), ('F0', 'F1', 'F2', 'F3',), (), ()),
    'fmsub.s' : ('fmsub.s F0, F1, F2, F3, {}' , (), ('F0', 'F1', 'F2', 'F3',), (), ()),
    'fnmsub.s': ('fnmsub.s F0, F1, F2, F3, {}', (), ('F0', 'F1', 'F2', 'F3',), (), ()),
    'fnmadd.s': ('fnmadd.s F0, F1, F2, F3, {}', (), ('F0', 'F1', 'F2', 'F3',), (), ())
}

rv32f_itype = {
    'flw': ('flw F0, I6(R1)', ('R1',), ('F0',), (('I6', 4),), ())
}

rv32f_stype = {
    'fsw': ('fsw F0, I6(R1)', ('R1',), ('F0',), (('I6', 4),), ())
}

rv64f_rtype = {
    'fcvt.l.s' : ('fcvt.l.s R0, F0' , ('R0',), ('F0',), (), ()),
    'fcvt.lu.s': ('fcvt.lu.s R0, F0', ('R0',), ('F0',), (), ()),
    'fcvt.s.l' : ('fcvt.s.l F0, R0' , ('R0',), ('F0',), (), ()),
    'fcvt.s.lu': ('fcvt.s.lu F0, R0', ('R0',), ('F0',), (), ())
}

rv32d_rtype = {
    'fadd.d'   : ('fadd.d F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fsub.d'   : ('fsub.d F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fmul.d'   : ('fmul.d F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fdiv.d'   : ('fdiv.d F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fsqrt.d'  : ('fsqrt.d F0, F1, {}'   , ()     , ('F0', 'F1',)      , (), ()),
    'fsgnj.d'  : ('fsgnj.d F0, F1, F2'   , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: J(N,)/JX
    'fsgnjn.d' : ('fsgnjn.d F0, F1, F2'  , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: J(N,)/JX
    'fsgnjx.d' : ('fsgnjx.d F0, F1, F2'  , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: J(N,)/JX
    'fmin.d'   : ('fmin.d F0, F1, F2'    , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: MIN/MAX
    'fmax.d'   : ('fmax.d F0, F1, F2'    , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: MIN/MAX
    'fcvt.d.s' : ('fcvt.d.s F0, F0'      , ()     , ('F0', 'F1',)      , (), ()),
    'fcvt.s.d' : ('fcvt.s.d F0, F0'      , ()     , ('F0', 'F1',)      , (), ()),
    'feq.d'    : ('feq.d R0, F0, F1'     , ('R0',), ('F0', 'F1',)      , (), ()),
    'flt.d'    : ('flt.d R0, F0, F1'     , ('R0',), ('F0', 'F1',)      , (), ()),
    'fle.d'    : ('fle.d R0, F0, F1'     , ('R0',), ('F0', 'F1',)      , (), ()),
    'fclass.d' : ('fclass.d R0, F0'      , ('R0',), ('F0',)            , (), ()),
    'fcvt.w.d' : ('fcvt.w.d R0, F0'      , ('R0',), ('F0',)            , (), ()),
    'fcvt.wu.d': ('fcvt.wu.d R0, F0'     , ('R0',), ('F0',)            , (), ()),
    'fcvt.d.w' : ('fcvt.d.w F0, R0'      , ('R0',), ('F0',)            , (), ()),
    'fcvt.d.wu': ('fcvt.d.wu F0, R0'     , ('R0',), ('F0',)            , (), ())
}

rv32d_r4type = {
    'fmadd.d' : ('fmadd.d F0, F1, F2, F3, {}' , (), ('F0', 'F1', 'F2', 'F3',), (), ()),
    'fmsub.d' : ('fmsub.d F0, F1, F2, F3, {}' , (), ('F0', 'F1', 'F2', 'F3',), (), ()),
    'fnmsub.d': ('fnmsub.d F0, F1, F2, F3, {}', (), ('F0', 'F1', 'F2', 'F3',), (), ()),
    'fnmadd.d': ('fnmadd.d F0, F1, F2, F3, {}', (), ('F0', 'F1', 'F2', 'F3',), (), ())
}

rv32d_itype = {
    'fld': ('fld F0, I6(R1)', ('R1',), ('F0',), (('I6', 8),), ())
}

rv32d_stype = {
    'fsd': ('fsd F0, I6(R1)', ('R1',), ('F0',), (('I6', 8),), ())
}

rv64d_rtype = {
    'fcvt.l.d' : ('fcvt.l.d R0, F0' , ('R0',), ('F0',), (), ()),
    'fcvt.lu.d': ('fcvt.lu.d R0, F0', ('R0',), ('F0',), (), ()),
    'fmv.x.d'  : ('fmv.x.d R0, F0'  , ('R0',), ('F0',), (), ()),
    'fcvt.d.l' : ('fcvt.d.l F0, R0' , ('R0',), ('F0',), (), ()),
    'fcvt.d.lu': ('fcvt.d.lu F0, R0', ('R0',), ('F0',), (), ()),
    'fmv.d.x'  : ('fmv.d.x F0, R0'  , ('R0',), ('F0',), (), ())
}

rv32q_rtype = {
    'fadd.q'   : ('fadd.q F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fsub.q'   : ('fsub.q F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fmul.q'   : ('fmul.q F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fdiv.q'   : ('fdiv.q F0, F1, F2, {}', ()     , ('F0', 'F1', 'F2',), (), ()),
    'fsqrt.q'  : ('fsqrt.q F0, F1, {}'   , ()     , ('F0', 'F1',)      , (), ()),
    'fsgnj.q'  : ('fsgnj.q F0, F1, F2'   , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: J(N,)/JX
    'fsgnjn.q' : ('fsgnjn.q F0, F1, F2'  , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: J(N,)/JX
    'fsgnjx.q' : ('fsgnjx.q F0, F1, F2'  , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: J(N,)/JX
    'fmin.q'   : ('fmin.q F0, F1, F2'    , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: MIN/MAX
    'fmax.q'   : ('fmax.q F0, F1, F2'    , ()     , ('F0', 'F1', 'F2',), (), ()), # rm: MIN/MAX
    'fcvt.q.s' : ('fcvt.q.s F0, F0'      , ()     , ('F0', 'F1',)      , (), ()),
    'fcvt.s.q' : ('fcvt.s.q F0, F0'      , ()     , ('F0', 'F1',)      , (), ()),
    'fcvt.q.d' : ('fcvt.q.d F0, F0'      , ()     , ('F0', 'F1',)      , (), ()),
    'fcvt.d.q' : ('fcvt.d.q F0, F0'      , ()     , ('F0', 'F1',)      , (), ()),
    'feq.q'    : ('feq.q R0, F0, F1'     , ('R0',), ('F0', 'F1',)      , (), ()),
    'flt.q'    : ('flt.q R0, F0, F1'     , ('R0',), ('F0', 'F1',)      , (), ()),
    'fle.q'    : ('fle.q R0, F0, F1'     , ('R0',), ('F0', 'F1',)      , (), ()),
    'fclass.q' : ('fclass.q R0, F0'      , ('R0',), ('F0',)            , (), ()),
    'fcvt.wu.q': ('fcvt.wu.q R0, F0'     , ('R0',), ('F0',)            , (), ()),
    'fcvt.w.q' : ('fcvt.w.q R0, F0'      , ('R0',), ('F0',)            , (), ()),
    'fcvt.q.w' : ('fcvt.q.w F0, R0'      , ('R0',), ('F0',)            , (), ()),
    'fcvt.q.wu': ('fcvt.q.wu F0, R0'     , ('R0',), ('F0',)            , (), ())
}

rv32q_r4type = {
    'fmadd.q' : ('fmadd.q F0, F1, F2, F3, {}' , (), ('F0', 'F1', 'F2', 'F3',), (), ()),
    'fmsub.q' : ('fmsub.q F0, F1, F2, F3, {}' , (), ('F0', 'F1', 'F2', 'F3',), (), ()),
    'fnmsub.q': ('fnmsub.q F0, F1, F2, F3, {}', (), ('F0', 'F1', 'F2', 'F3',), (), ()),
    'fnmadd.q': ('fnmadd.q F0, F1, F2, F3, {}', (), ('F0', 'F1', 'F2', 'F3',), (), ())
}

rv32q_itype = {
    'flq': ('flq F0, I6(R1)', ('R1',), ('F0',), (('I6', 4),), ())
}

rv32q_stype = {
    'fsq': ('fsq F0, I6(R1)', ('R1',), ('F0',), (('I6', 4),), ())
}

rv64q_rtype = {
    'fcvt.l.q' : ('fcvt.l.q R0, F0' , ('R0',), ('F0',), (), ()),
    'fcvt.lu.q': ('fcvt.lu.q R0, F0', ('R0',), ('F0',), (), ()),
    'fmv.x.q'  : ('fmv.x.q R0, F0'  , ('R0',), ('F0',), (), ()),
    'fcvt.q.l' : ('fcvt.q.l F0, R0' , ('R0',), ('F0',), (), ()),
    'fcvt.q.lu': ('fcvt.q.lu F0, R0', ('R0',), ('F0',), (), ()),
    'fmv.q.x'  : ('fmv.q.x F0, R0'  , ('R0',), ('F0',), (), ())
}

trap_ret = {
    'mret': ('mret', (), (), (), ()),
    'sret': ('sret', (), (), (), ()),
    'uret': ('uret', (), (), (), ())
}

pseudo = {
    'ret' : ('ret',     (), (), (), ()),
    'call': ('call S0', (), (), (), ('S0',))
}

rv32i = { **rv32i_rtype, **rv32i_itype, **rv32i_btype,
          **rv32i_stype, **rv32i_jtype, **rv32i_utype }
rv64i = { **rv64i_itype, **rv64i_stype }

rv32m = { **rv32m_rtype }
rv64m = { **rv64m_rtype }

rv32a = { **rv32a_rtype }
rv64a = { **rv64a_rtype }

rv32f = { **rv32f_rtype, **rv32f_r4type,
          **rv32f_itype, **rv32f_stype }
rv64f = { **rv64f_rtype }

rv32d = { **rv32d_rtype, **rv32d_r4type,
          **rv32d_itype, **rv32d_stype }
rv64d = { **rv64d_rtype }

rv32q = { **rv32q_rtype, **rv32q_r4type,
          **rv32q_itype, **rv32q_stype }
rv64q = { **rv64q_rtype }

rv32 = { **rv32i, **rv32m, **rv32a,
         **rv32f, **rv32d, **rv32q }

rv64 = { **rv64i, **rv64m, **rv64a,
         **rv64f, **rv64d, **rv64q }

rv_ops = { **rv32, **rv64, **rv_zifencei }

class OPCODES(Enum):
    rv32i       = rv32i
    rv64i       = rv64i
    rv_zifencei = rv_zifencei
    rv_zicsr    = rv_zicsr
    rv32m       = rv32m
    rv64m       = rv64m
    rv32a       = rv32a
    rv64a       = rv64a
    rv32f       = rv32f
    rv64f       = rv64f
    rv32d       = rv32d
    rv64d       = rv64d
    rv32q       = rv32q
    rv64q       = rv64q
    trap_ret    = trap_ret
    pseudo      = pseudo

""" Operands """
XREGS = ('zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2', 's0', 's1',
         'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 's2', 's3',
         's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 't3', 't4',
         't5', 't6',)
FREGS = ('ft0', 'ft1', 'ft2', 'ft3', 'ft4', 'ft5', 'ft6', 'ft7',
         'fs0', 'fs1', 'fa0', 'fa1', 'fa2', 'fa3', 'fa4', 'fa5',
         'fa6', 'fa7', 'fs2', 'fs3', 'fs4', 'fs5', 'fs6', 'fs7',
         'fs8', 'fs9', 'fs10', 'fs11', 'ft8', 'ft9', 'ft10', 'ft11',)

CSRS = {
    PRV.M: (
        # Standard Machine R/W
        'mstatus', 'misa', 'medeleg', 'mideleg', 'mie', 'mtvec',
        'mcounteren','mcountinhibit', 'mscratch', 'mepc', 'mcause',
        'mtval', 'mip', 'mtinst', 'mtval2', 'pmpcfg0', 'pmpcfg1',
        'pmpcfg2', 'pmpcfg3', 'pmpaddr0', 'pmpaddr1', 'pmpaddr2',
        'pmpaddr3', 'pmpaddr4', 'pmpaddr5', 'pmpaddr6', 'pmpaddr7',
        'pmpaddr8', 'pmpaddr9', 'pmpaddr10', 'pmpaddr11', 'pmpaddr12',
        'pmpaddr13', 'pmpaddr14', 'pmpaddr15', 'tselect', 'tdata1',
        'tdata2', 'tdata3', 'tinfo', 'tcontrol', 'mcontext', 'scontext',
        'dcsr', 'dpc', 'dscratch0', 'dscratch1', 'mcycle', 'minstret',
        # Standard Machine RO
        'mvendorid', 'marchid', 'mimpid', 'mhartid'
    ,),
    PRV.H: (
        # Standard Hypervisor R/w
        'vsstatus', 'vsie', 'vstvec', 'vsscratch', 'vsepc', 'vscause',
        'vstval', 'vsip', 'vsatp', 'hstatus', 'hedeleg', 'hideleg', 'hie',
        'htimedelta', 'hcounteren', 'hgeie', 'htval', 'hip', 'hvip',
        'htinst', 'hgatp', 'hgeip',
        # Tentative CSR assignment for CLIC
        'utvt', 'unxti', 'uintstatus', 'uscratchcsw', 'uscratchcswl',
        'stvt', 'snxti', 'sintstatus', 'sscratchcsw', 'sscratchcswl',
        'mtvt', 'mnxti', 'mintstatus', 'mscratchcsw', 'mscratchcswl'
    ,),
    PRV.S: (
        # Standard Supervisor R/W
        'sstatus', 'sedeleg', 'sideleg', 'sie', 'stvec', 'scounteren',
        'sscratch', 'sepc', 'scause', 'stval', 'sip', 'satp'
    ,),
    PRV.U: (
        # Standard User R/W
        'fflags', 'frm', 'fcsr', 'ustatus', 'uie', 'utvec', 'vstart',
        'vxsat', 'vxrm', 'vcsr', 'uscratch', 'uepc', 'ucause',
        'utval', 'uip',
        # Standard User RO
        'cycle', 'time', 'instret', 'vl', 'vtype', 'vlenb'
    ,)
}

# csrs = [ 'fflags', 'frm', 'fcsr',
#               'sstatus', 'sie', 'sscratch', 'sepc', 'scause', 'stval', 'sip', 'satp',
#               'mhartid', 'mstatus', 'medeleg', 'mie', 'mscratch', 'mepc', 'mcause', 'mtval',
#               'pmpcfg0', 'pmpaddr0', 'pmpaddr1', 'pmpaddr2', 'pmpaddr3', 'pmpaddr4',
#               'pmpaddr5', 'pmpaddr6', 'pmpaddr7' ]
# [ 'ustatus', 'uie', 'uepc', 'ucause', 'utval', 'uip']
# [ 'sedeleg', 'sideleg']
# [ 'pmpcfg1', 'pmpcfg2', 'pmpcfg3']
# [ 'utvec', 'stvec', 'mtvec', 'mcycle', 'minstret', 'mcycleh', 'minstreth' ]
# [ 'mcounteren', 'scounteren' ]
# [ 'mip' ]
