"""
SpecDoctor Instruction Generator

TODO: Copyright
"""
import re
import abc
import random
from typing import List, Dict

from config import Confs
from inst_generator import InstGenerator
from internals import TPE, BasicBlock, TestCaseDAG


# ===========================================
# Utilities
# ===========================================
def rand(choices: List, freqs: List):
    assert len(choices) == len(freqs), \
        f'rand size mismatch ({len(choices)}vs{len(freqs)})'
    assert sum(freqs) == 1, 'rand: freq sum is not 1'

    intv = [sum(freqs[:i+1]) for i in range(len(freqs))]
    p = random.random()

    for idx, x in enumerate(intv):
        if p < x:
            break

    return choices[idx]



# ===========================================
# Generator
# ===========================================
class Generator:
    def __init__(self, isa: List, blocked: List, weights: Dict = {}):

        self.generator = InstGenerator(isa, blocked, weights)

        self.genDAG = GenerateDAGPass()
        self.fillTMN = FillTerminatorPass(self.generator)
        self.fillINST = FillInstructionPass(self.generator)
        self.mutateTC = MutateTestCasePass(self.generator)
        self.mutateTSX = MutateTransientPass(self.generator)
        self.popINST = PopulateInstructionPass(self.generator)
        self.addPRMT = AddPrimitivePass()

    def create_prefix(self, name: str, secret_in_l1=False) -> str:
        tc = TestCaseDAG(name)

        brings = [False, True] if secret_in_l1 else [False]
        bbs = []
        for i, b in enumerate(brings):
            bb = BasicBlock(f'{name}.bb{i}')
            self.fillINST.run_on_prefix(bb, b)
            bbs.append(bb)

        tc.BBs = (tc.entry, *bbs, tc.exit)
        return str(tc)

    def create_function(self, name: str) -> str:
        func = TestCaseDAG(name)
        self.genDAG.run_on_dag(func, True)
        self.fillTMN.run_on_dag(func, True)
        self.fillINST.run_on_dag(func, False, True)
        self.popINST.run_on_dag(func, True)
        self.addPRMT.run_on_dag(func, True)

        return str(func)

    def mutate_tc(self, name: str, seed: List[str],
                  prps: List[List[str]], tlabel: str) -> (List[str], str):
        testcase = self.read_tc(seed)
        prp_tcs = [self.read_tc(prp) for prp in prps]

        self.mutateTC.run_on_dag(testcase, prp_tcs, tlabel)
        for prp in prp_tcs:
            self.popINST.run_on_dag(prp)
        self.popINST.run_on_dag(testcase)

        return [str(p) for p in prp_tcs], str(testcase)

    def mutate_tsx(self, name: str, seed: List[str]) -> str:
        testcase = self.read_tc(seed)
        self.mutateTSX.run_on_dag(testcase)
        self.popINST.run_on_dag(testcase, True)

        return str(testcase)

    def create_tc(self, name: str, prepare=False, tsx=False, rcv=False) -> str:
        assert not (prepare and tsx), \
            'Create_testcase with both prepare & tsx'

        # 1. Generate DAG (of basic blocks)
        testcase = TestCaseDAG(name)
        self.genDAG.run_on_dag(testcase)

        # 2. Connect basic blocks with cfg instructions
        self.fillTMN.run_on_dag(testcase)

        # 3. Fill in each basic block with random instructions
        self.fillINST.run_on_dag(testcase, prepare)

        # 4. Pop up register indices and imm values
        self.popINST.run_on_dag(testcase, tsx, rcv)

        # 5. Embed assembler primitives
        self.addPRMT.run_on_dag(testcase, tsx)

        return str(testcase)

    def read_tc(self, lines: List[str]) -> TestCaseDAG:
        excptMsg = 'Misformatted testcase\n' + ''.join(lines)
        lTmps = []

        i = 0
        while i < len(lines) - 1: # Handle last empty
            match = re.match('(.*):.*', lines[i])
            if match:
                label = match.group(1)

                j = i + 1
                while j < len(lines) and not re.match('(.*):.*', lines[j]):
                    j += 1

                asm = ([re.sub('^.*:\s+', '', lines[i])] +
                       [re.sub('^\s+', '', l) for l in lines[i+1:j]])
                lTmps.append((label, [re.sub('\s+$', '', l)
                                     for l in asm]))

                i = j
            else:
                raise Exception(excptMsg)

        tmp = lTmps.pop(0)
        testcase = TestCaseDAG(tmp[0])
        bb = None
        scope = 'TC'

        while True:
            try: label, asm = lTmps.pop(0)
            except:
                if scope != 'TC':
                    raise Exception(excptMsg)
                break

            if scope == 'TC' and label == f'{testcase.name}.entry':
                bb = testcase.entry
                testcase.BBs = testcase.BBs + (bb,)
                scope = 'BB'
            elif scope == 'BB':
                bmatch = re.match(f'{bb.label}.(l[0-9]+)', label)
                tmatch = re.match(f'{testcase.name}.(bb[0-9]+)', label)
                if bmatch:
                    wlabel = f'{bb.label}.{bmatch.group(1)}'

                    word = self.generator.read_word(wlabel, asm)
                    bb.append_non_terminator(word)

                elif tmatch:
                    word = bb.words.pop()
                    bb.append_terminator(word)

                    blabel = f'{testcase.name}.{tmatch.group(1)}'
                    bb = BasicBlock(blabel)

                    testcase.BBs = testcase.BBs + (bb,)
                elif label == f'{testcase.name}.exit':
                    testcase.BBs = testcase.BBs + (testcase.exit,)
                    scope = 'TC'
                else:
                    raise Exception(excptMsg)

            else:
                raise Exception(excptMsg)

        bbs = [bb for bb in testcase]
        for i, bb in enumerate(testcase):
            bb.successors = bbs[i+1:]

        return testcase



# ===========================================
# Passes
# ===========================================
class Pass(abc.ABC):
    @abc.abstractmethod
    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        pass


# TODO: 1. Configuration variables
class GenerateDAGPass(Pass):
    min_bb: int = 3
    max_bb: int = 5

    def __init__(self):
        pass

    # Generate DAG where the nodes have only maximum two edges
    def run_on_dag(self, DAG: TestCaseDAG, func=False) -> None:
        name = DAG.name

        n = 0 if func else random.randint(self.min_bb, self.max_bb)

        bbs = [DAG.entry] + [BasicBlock(f'{name}.bb{i}') for i in range(n)]
        num_bb = len(bbs)

        for i in range(num_bb):
            current_bb = bbs[i]

            if i == num_bb - 1:
                current_bb.successors = [DAG.exit]
                break

            # One of the target is always the next bb
            current_bb.successors = [bbs[i+1]]

            # Randomly choose the second target
            target = random.choice((bbs + [DAG.exit])[i+2:])
            current_bb.successors.append(target)

        DAG.BBs = (*bbs, DAG.exit)


# TODO: 1. Configuration variables
class FillTerminatorPass(Pass):
    freq_cond: float = 0.5
    generator: InstGenerator

    def __init__(self, gen: InstGenerator):
        self.generator = gen

    # Fill in terminators of basicblock with branch/jump instructions
    def run_on_dag(self, DAG: TestCaseDAG, func=False) -> None:
        for bb in DAG:
            if bb == DAG.exit:
                break
            elif func:
                ret = self.generator.get_ret()
                bb.append_terminator(ret)
            else: # bb.successors = 2
                terminator = self.generator.get_word(lambda t: t == TPE.CFG)
                bb.append_terminator(terminator)


# TODO: 1. Configuration variables, 2. Smart choice instructions
class FillInstructionPass(Pass):
    min_words: int = 5
    max_words: int = 10

    def __init__(self, gen: InstGenerator):
        self.generator = gen

    def run_on_prefix(self, bb: BasicBlock, bring: bool) -> None:
        get_word = (self.generator.get_bring_secret if bring
                    else self.generator.get_setup)

        for word in get_word(bb.label):
            bb.append_non_terminator(word)

    def run_on_dag(self, DAG: TestCaseDAG, prepare=False, func=False) -> None:
        def tpe_prepare(t: TPE):
            return t != TPE.MEM

        # NOTE: Function uses simple instructions only
        def tpe_func(t: TPE):
            return t == TPE.NONE

        tpe_ok = tpe_prepare if prepare else tpe_func if func else lambda _: True

        for bb in DAG:
            if bb == DAG.exit:
                break

            num_words = random.randint(self.min_words, self.max_words)
            for i in range(num_words):
                word = self.generator.get_word(tpe_ok)
                bb.append_non_terminator(word)


class MutateTestCasePass(Pass):
    def __init__(self, gen: InstGenerator):
        self.generator = gen

    def run_on_dag(self, DAG: TestCaseDAG, prps: List[TestCaseDAG],
                   tlabel: str, tsx=False) -> None:
        mut = True
        num_delay = 0

        for bb in DAG:
            if bb == DAG.exit:
                break

            mutated = []
            while mut and bb.words:
                if random.random() < 0.2:
                    delay = self.generator.get_delay()
                    mutated.append(delay)
                    num_delay += 1

                w = bb.words.pop(0)
                mutated.append(w)
                mut = (w.label != tlabel)

            mutated += bb.words
            bb.words = mutated

        for prp in prps:
            nops = [self.generator.get_nop() for i in range(num_delay)]
            prp.entry.words = nops + prp.entry.words


class MutateTransientPass(Pass):
    def __init__(self, gen: InstGenerator):
        self.generator = gen

    def run_on_dag(self, DAG: TestCaseDAG) -> None:

        for bb in DAG:
            if bb == DAG.exit:
                break

            mutated = []
            while bb.words:
                w = bb.words.pop(0)

                mut = random.random()
                if mut < 0.2: # Append random word
                    new = self.generator.get_word()
                    mutated.append(w)
                    mutated.append(new)
                elif mut < 0.8: # Keep going
                    mutated.append(w)
                else: # Remove existing word
                    pass

            bb.words = mutated


# TODO: 1. Configuration variables
class PopulateInstructionPass(Pass):
    def __init__(self, gen: InstGenerator):
        self.generator = gen

    def run_on_dag(self, DAG: TestCaseDAG, tsx=False, rcv=False) -> None:
        for i, bb in enumerate(DAG):
            if bb == DAG.exit:
                break

            labels = [s.label for s in bb.successors]
            for j, w in enumerate(bb):
                self.generator.pop_word(w, f'{bb.label}.l{j}',
                                        labels, tsx, rcv)


class AddPrimitivePass(Pass):
    def __init__(self):
        pass

    def run_on_dag(self, DAG: TestCaseDAG, on=False) -> None:
        for bb in DAG:
            if bb == DAG.exit:
                break

            if random.random() < 0.2 and on:
                bb.append_primitive('.align 8')
