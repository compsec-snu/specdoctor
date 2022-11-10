"""
SpecDoctor Random Instruction Generator

TODO: Copyright
"""
import re
import random
from typing import List, Dict, Set, Tuple, Callable

from riscv_definitions import OPCODES
from internals import WordSpec, Word, TPE
from word import Wgen_map, wgen_read, wgen_delay, wgen_nop


class InstGenerator:
    opcodes_map: Dict[str, Tuple]
    opcodes: Tuple[str]
    w_opcodes: Tuple[str]
    # NOTE: Use only s2-6
    xnums: Set[int] = set(range(18, 23))
    # NOTE: Use only ft0-4
    fnums: Set[int] = set(range(0, 5))
    # NOTE: tsx uses s7-11, ft5-7, fs0-1
    used_xnums: Set[int]
    used_fnums: Set[int]
    used_imms: Set[int]
    intsx: int = 5

    imask: int = 0xfff

    def __init__(self, supported_isa: List, blocking_insts: List,
                 weights: Dict = {}):
        self.supported_isa = supported_isa
        self.opcodes_map = {}
        for isa in supported_isa:
            self.opcodes_map.update(getattr(OPCODES, isa).value)

        self.opcodes_map.update(getattr(OPCODES, 'pseudo').value)

        self.opcodes = tuple(set(self.opcodes_map.keys()) - set(blocking_insts))
        # NOTE: It does not reflect probability, but is easy
        w_opcodes = []
        for o in self.opcodes:
            n = weights.get(o, 1)
            w_opcodes += [o] * n

        self.w_opcodes = tuple(w_opcodes)

        self.used_xnums = set([])
        self.used_fnums = set([])
        self.used_imms = set([])

    def __get_r(self, tsx: bool):
        xnum = random.choice(tuple(self.xnums - self.used_xnums))
        self.used_xnums.add(xnum)

        xnum = xnum + self.intsx if tsx else xnum
        return f'x{xnum}'

    def __get_f(self, tsx: bool):
        fnum = random.choice(tuple(self.fnums - self.used_fnums))
        self.used_fnums.add(fnum)

        fnum = fnum + self.intsx if tsx else fnum
        return f'f{fnum}'

    # TODO: 1. Consider type of word, 2. Reuse imms, 3. Limit range
    def __get_i(self, iname: str, align: int):
        assert align & (align - 1) == 0, 'align must be power of 2'

        # sign = '' if (iname[0] == 'U') else random.choice(['', '-'])
        sign = ''
        width = int(iname[1:]) if (iname[0] == 'U') else int(iname[1:]) - 1

        mask = (1 << width) - 1
        amask = ~(align - 1)

        imm = self.imask & amask & random.randint(0, mask)
        self.used_imms.add(imm)

        return f'{sign}{imm}'

    def __get_s(self, tpe: TPE, targets: List, tsx: bool, rcv: bool) -> str:
        data = tuple([f'data{i}' for i in range(8)])
        call = ('fn0', 'fn1', 'fn2', 'fn3', 'fn4') # TODO: Sync with Config
        if tsx: data = (list(data) + ['secret'])
        if tpe == TPE.MEM:
            d = random.choice(data)
            return (f'v{d}' if rcv else d)
        elif tpe == TPE.CALL:
            c = random.choice(call)
            return (f'v{c}' if rcv else c)
        else: # TPE.CFG
            return random.choice(targets)

    def clear(self):
        self.used_xnums.clear()
        self.used_fnums.clear()
        self.used_imms.clear()

    def get_bring_secret(self, label: str) -> List[Word]:
        n_brings = 8
        assert n_brings * 2 <= 16, 'n_brings should not be larger then 8'

        adds = [Word('Word(addi)', *Wgen_map['addi'](*self.opcodes_map['addi']))
                for i in range(n_brings)]
        loads = [Word('Word(ld)', *Wgen_map['ld'](*self.opcodes_map['ld']))
                 for i in range(n_brings)]
        # NOTE: These words are used to clean RegisterFileSynthesizable states
        # (Secret values are loaded in to uarch register, and causes false alarm)
        cleans = [Word('Word(addi)',
                       *Wgen_map['addi'](*self.opcodes_map['addi']))
                  for i in range(48)]

        def set_add(word: Word) -> dict:
            xregs = {'R0': 'a0', 'R1': 'zero'}
            imms = {i: self.__get_i(i, a) for i, a in word.imms}
            self.clear()

            return {**xregs, **imms}

        def set_load(word: Word) -> dict:
            xregs = {'R0': 'a1', 'R1': 'a0', 'R2': 'a1'}
            imms = {i: self.__get_i(i, a) for i, a in word.imms}
            symbols = {'S0': 'secret'}
            self.clear()

            return {**xregs, **imms, **symbols}

        def set_clean(word: Word, n: int) -> dict:
            xregs = {'R0': f'x{n % 16}', 'R1': 'zero'}
            imms = {i: '0' for i, a in word.imms}

            return {**xregs, **imms}

        words = [list(x) for x in zip(adds, loads)]
        for i, w in enumerate(words):
            w0, w1 = w
            w0.popup(f'{label}.l{i*2}', set_add(w0))
            w1.popup(f'{label}.l{i*2 + 1}', set_load(w1))

        for i, c in enumerate(cleans):
            c.popup(f'{label}.l{n_brings * 2 + i}', set_clean(c, i))

        return sum(words, []) + cleans

    def get_setup(self, label: str) -> List[Word]:
        xwords = [Word('Word(addi)', *Wgen_map['addi'](*self.opcodes_map['addi']))
                  for i in self.xnums | {n + self.intsx for n in self.xnums}]
        if {'rv32f', 'rv64f', 'rv32d', 'rv64d'} <= set(self.supported_isa):
            fwords = [Word('Word(fld)', *Wgen_map['fld'](*self.opcodes_map['fld']))
                      for i in self.fnums | {n + self.intsx for n in self.fnums}]
        else:
            fwords = []

        def set_misc(word: Word) -> dict:
            imms = {i: self.__get_i(i, a) for i, a in word.imms}
            symbols = {s: self.__get_s(word.tpe, [], False, False)
                       for s in word.symbols}

            return {**imms, **symbols}

        def set_xreg(x: int, word: Word) -> dict:
            xregs = {'R0': f'x{x}', 'R1': 'zero'}
            misc = set_misc(word)
            self.clear()

            return {**xregs, **misc}

        def set_freg(f: int, word: Word) -> dict:
            xregs = {r: self.__get_r(False) for r in word.xregs}
            fregs = {'F0': f'f{f}'}
            misc = set_misc(word)
            self.clear()

            return {**xregs, **fregs, **misc}

        i = 0
        for f, word in enumerate(fwords):
            word.popup(f'{label}.l{i}', set_freg(f, word))
            i += 1

        for x, word in enumerate(xwords):
            word.popup(f'{label}.l{i}', set_xreg(x+18, word))
            i += 1

        return fwords + xwords

    def get_word(self, tpe_ok: Callable = lambda x: True) -> Word:
        while True:
            opcode = random.choice(self.w_opcodes)
            wgen = Wgen_map[opcode]
            tpe, spec = wgen(*self.opcodes_map[opcode])
            if tpe_ok(tpe):
                break

        word = Word(f'Word({opcode})', tpe, spec)
        return word

    def pop_word(self, word: Word, label: str, targets: List, tsx: bool, rcv: bool):
        xregs = {r: self.__get_r(tsx) for r in word.xregs}
        fregs = {f: self.__get_f(tsx) for f in word.fregs}
        imms = {i: self.__get_i(i, a) for i, a in word.imms}
        symbols = {s: self.__get_s(word.tpe, targets, tsx, rcv)
                   for s in word.symbols}
        self.clear()

        opvals = {**xregs, **fregs, **imms, **symbols}

        word.popup(label, opvals)

    def read_word(self, label: str, asm: List[str]) -> Word:
        op, tpe, spec = wgen_read(asm)

        word = Word(f'Word({op})', tpe, spec)
        word.popup(label, {})
        return word

    def get_delay(self) -> Word:
        tpe, spec = wgen_delay('', (), (), (), ())

        word = Word('Word(delay)', tpe, spec)
        return word

    def get_nop(self) -> Word:
        tpe, spec = wgen_nop('', (), (), (), ())

        word = Word('Word(nop)', tpe, spec)
        return word

    def get_ret(self) -> Word:
        tpe, spec = Wgen_map['ret'](*self.opcodes_map['ret'])

        word = Word('Word(ret)', tpe, spec)
        return word
