"""
SpecDoctor Data Structure for Instruction Generation

TODO: Copyright
"""
import abc
from enum import Enum
from typing import List, Dict, Tuple


# ================================================================
# Primitive
# ================================================================
# TODO:
# class Primitive:

# ================================================================
# Word:
# Chunk of instructions, building one semantic operation
# Sandboxing instructions to prevent abnormal result
# ================================================================


class TPE(Enum):
    NONE = 0
    CFG  = 1
    MEM  = 2
    CSR  = 3
    CALL = 4


class WordSpec:
    syntax: str
    xregs: List[str]
    fregs: List[str]
    imms: List[str]
    symbols: List[str]
    insts: List[str]

    def __init__(self, syntax: str, xregs: Tuple, fregs: Tuple,
                 imms: Tuple, symbols: Tuple):
        self.syntax = syntax
        self.xregs = list(xregs)
        self.fregs = list(fregs)
        self.imms = list(imms)
        self.symbols = list(symbols)

        self.insts = []


class Word:
    ret: List[str]
    populated: bool = False

    def __init__(self, name: str, tpe: TPE, spec: WordSpec):
        self.name = name
        self.label = ''
        self.insts = tuple(spec.insts)
        self.tpe = tpe

        self.xregs = tuple(spec.xregs)
        self.fregs = tuple(spec.fregs)
        self.imms = tuple(spec.imms)
        self.symbols = tuple(spec.symbols)

        self.ret = []

    def __str__(self):
        assert self.populated, f'{self.name} not populated'

        return '\n'.join([f'{i}' for i in self.ret])

    def _pop(self, inst: str, opvals: Dict) -> str:
        for (op, val) in opvals.items():
            inst = inst.replace(op, val)

        return inst

    def popup(self, label: str, opvals: Dict):
        pop_insts = []
        for inst in self.insts:
            p_inst = self._pop(inst, opvals)
            pop_insts.append(p_inst)

        self.label = label
        self.ret = (f'{self.label + ":" :<20}{pop_insts[0] :<42}',
                    *[f'{"" :>20}{i :<42}' for i in pop_insts[1:]])
        self.populated = True


def wordgen(tpe: TPE):
    def deco(func):
        def wrapper(syntax, xregs, fregs, imms, symbols):
            spec = WordSpec(syntax, xregs, fregs, imms, symbols)

            func(spec)
            return (tpe, spec)
        return wrapper
    return deco


def wordread():
    def deco(func):
        def wrapper(insts):
            spec = WordSpec('', (), (), (), ())

            op, tpe = func(spec, insts)
            return (op, tpe, spec)
        return wrapper
    return deco

# ================================================================
# BasicBlock
# ================================================================


class BasicBlock:
    label: str
    successors: List['BasicBlock'] # TODO: Future annotation
    terminators: List[Word]
    # TODO: primitives: List[Primitive]
    words: List[Word]

    def __init__(self, label: str):
        self.label = label
        self.primitives = []
        self.words = []
        self.successors = []
        self.terminators = []

    def __iter__(self):
        return (self.words + self.terminators).__iter__()

    def __len__(self):
        return len(self.words + self.terminators)

    def __str__(self):
        return '\n'.join([str(i) for i in self.primitives] +
                         [f'{self.label}:'] +
                         [str(i) for i in iter(self)])

    def append_terminator(self, W: Word):
        assert W.tpe == TPE.CFG, f'{W.name} cannot be terminator'
        self.terminators.append(W)

    def append_non_terminator(self, W: Word):
        self.words.append(W)

    def append_primitive(self, P: str):
        self.primitives.append(P)

    def delete(self, target: Word):
        try: self.words.remove(target)
        except:
            raise Exception(f'{target} is not in BB {self.label}')

# ================================================================
# TestCaseDAG
# ================================================================


class TestCaseDAG:
    name: str
    BBs: Tuple[BasicBlock]
    entry: BasicBlock
    exit: BasicBlock

    def __init__(self, name):
        self.name = name

        # create entry and exit points for the function
        self.entry = BasicBlock(f'{self.name}.entry')
        self.exit = BasicBlock(f'{self.name}.exit')
        self.BBs = ()

    def __iter__(self):
        for BB in self.BBs:
            yield BB

    def __str__(self):
        ret = (f'{self.name}:\n' +
               '\n'.join([str(bb) for bb in self.BBs]) +
               '\n')
        return ret
