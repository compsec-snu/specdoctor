#!/usr/bin/env python3

import os
import shutil
from subprocess import Popen, PIPE
import re
import time
import random
from functools import reduce
from enum import Enum
from typing import Optional, List, Set
from threading import BoundedSemaphore, Timer

from word import Tpe_map


class TPE(Enum):
    NONE  = 0
    BR    = 1
    XCPT  = 2
    FLUSH = 3


GEN_CNT = 1000
PFX     = 'pfx'
PRP     = 'prp'
FUNC    = 'fn'
TC      = 'tc'
TSX     = 'tsx'
RCV     = 'rcv'


class RollBackInfo:
    def __init__(self, tpe: str, opcode: str, cause: str):
        self.tpe = tpe
        self.opcode = opcode
        self.cause = cause

    def __eq__(self, o: 'RollBackInfo'):
        ret = ((self.tpe == o.tpe) and
               (Tpe_map[self.opcode] == Tpe_map[o.opcode]) and
               (self.cause == o.cause))
        return ret

    def __str__(self):
        return f'{self.tpe}_{self.opcode}_{self.cause}'

    def __hash__(self):
        return hash(self.tpe) ^ hash(Tpe_map[self.opcode]) ^ hash(self.cause)


class Component:
    def __init__(self, mod: str, mid: int, mem: str):
        self.mod = mod
        self.mid = mid
        self.mem = mem

    def __eq__(self, o: 'Component'):
        ret = ((self.mod == o.mod) and
               (self.mid == o.mid) and
               (self.mem == o.mem))
        return ret

    def __hash__(self):
        return hash(self.mod) ^ hash(self.mid) ^ hash(self.mem)

    def __str__(self):
        return f'{self.mod}({self.mid}): {self.mem}'


class ROBLog:
    def __init__(self, tpe: int, tpc: int, mpc: int, trg_inst: int, ewsz: int):
        self.tpe = TPE(tpe).name
        self.tpc = tpc
        self.mpc = mpc
        self.trg_inst = os.popen('echo "DASM({0:08x})" | spike-dasm'
                                 .format(trg_inst)).read()
        self.trg_opcode = self.trg_inst.replace('\n', '').split(' ')[0]
        self.ewsz = ewsz

        self.str = f'{self.tpe}_{hex(tpc)}_{hex(mpc)}_{self.trg_opcode}_{ewsz}'

    def __str__(self):
        return self.str


class Preprocessor:
    def __init__(self, target: str, output: str, dsize=1024):
        self.target = target
        self.output = output
        self.template = output + '/Template'

        self.rand = random.Random()
        self.randLock = BoundedSemaphore(1)

        assert dsize % 16 == 0, f'Invalid dsize: {dsize}'
        self.dsize = dsize

        os.system(f'rm -rf $PWD/{self.template}')
        os.system(f'cp -r $PWD/Template $PWD/{self.template}')

    def embed_attack(self, pfx: str, prps: List[str], funcs: str,
                     asm: str, ent: int, tid: int) -> str:
        ret = f'{self.output}/.t1_input_{tid}'

        self.randLock.acquire()
        self.rand.seed(ent)
        with open(f'{self.template}/entry.S', 'r') as fd:
            lines = fd.readlines()

        with open(f'{ret}.S', 'w') as fd:
            for line in lines:
                fd.write(line)

                if re.match('^prefix:.*', line):
                    fd.write(pfx)
                elif re.match('^pre_attack[0-9]+:.*', line):
                    prp = prps.pop(0)
                    fd.write(prp)
                elif re.match('^shared:.*', line):
                    fd.write(funcs)
                elif re.match('^attack:.*', line):
                    fd.write(asm)
                elif re.search('^data[0-9]+:.*', line):
                    for i in range(self.dsize // (8 * 2)):
                        r0 = self.rand.randint(0, 0xffffffffffffffff)
                        r1 = self.rand.randint(0, 0xffffffffffffffff)
                        fd.write(f'    .dword {hex(r0)}, {hex(r1)}\n')

        self.rand.seed(time.time())
        self.randLock.release()

        return ret

    def embed_tsx(self, prg: str, tpc: int, cpc: int,
                 mpc: int, tpe: TPE) -> (bool, str):

        syms = os.popen(f'nm {prg}.riscv | grep "tc."').read().split('\n')[:-1]
        sMap = {i[2]: int(i[0], 16)
                for i in [j.split(' ') for j in syms]}

        symbolMap = {v: k for k, v in sMap.items()
                     if re.match('^l[0-9]+', k[-2:])}

        def embed_str(lines: List[str], label: str, s: str):
            try:
                idx = [i for i, l in enumerate(lines) if
                       re.match(f'^{label}:.*', l)][0]
                lines.insert(idx, s)
            except:
                raise Exception(f'{label} not in asm')

        tl = symbolMap[max([i for i in symbolMap.keys() if i <= mpc])]

        ml = symbolMap.get(mpc, None)
        cl = symbolMap.get(cpc, None)

        # Filter out misaligned accesses
        if ml and ((tpe != TPE.BR) or (cl and ml != cl)):
            with open(f'{prg}.S', 'r') as fd:
                asm = fd.readlines()

            if ml == cl:
                # TODO: Support data-flow misprediction
                if self.target == 'Nutshell':
                    print(f'[SpecDoctor] Does not support data-flow misprediction')
                    os.makedirs(f'{self.output}/dataflow', exist_ok=True)
                    name = prg.split('/')[-1]
                    shutil.move(f'{prg}.S', f'{self.output}/dataflow/{name}.S')
                    return False, ''

                embed_str(asm, ml,
                          f'{"" :<20}spdoc_check_d\ntransient:\ntransient_end:\n')
            elif tpe == TPE.BR:
                embed_str(asm, ml, 'transient:\ntransient_end:\n')
                embed_str(asm, cl, f'{"" :<20}spdoc_check_c\n')
            else:
                embed_str(asm, ml, 'transient:\ntransient_end:\n')

            with open(f'{prg}.S', 'w') as fd:
                fd.write(''.join(asm))

            return True, tl
        else:
            return False, ''

    def embed_sec(self, thd: int, prg: str, asm: str,
                  seed: Optional[int], tid: int) -> str:

        if thd not in [3, 4, 5]:
            raise Exception(f'embed_sec thread({thread}) not in 3, 4, 5')
        ret = f'{self.output}/.t{thd}_input_{tid}'

        self.randLock.acquire()
        if seed != None: self.rand.seed(seed)
        with open(f'{prg}.S', 'r') as fd:
            lines = fd.readlines()

        pattern = '^transient:.*' if thd == 3 else '^receive:.*'
        with open(f'{ret}.S', 'w') as fd:
            for line in lines:
                fd.write(line)

                if re.match(pattern, line):
                    fd.write(asm)
                elif seed != None and 'secret:' in line:
                    for i in range(self.dsize // (8 * 2)):
                        r0 = self.rand.randint(0, 0xffffffffffffffff)
                        r1 = self.rand.randint(0, 0xffffffffffffffff)
                        fd.write(f'    .dword {hex(r0)}, {hex(r1)}\n')

        self.rand.seed(time.time())
        self.randLock.release()

        return ret

    def extract_block(self, prg: str, blk: str) -> str:
        with open(f'{prg}.S', 'r') as fd:
            line = ''.join(fd.readlines())

        match = re.match(f'.*({blk}:.*{blk}.exit:).*', line, re.DOTALL)
        tcLine = match.group(1) + '\n'

        tc = [i for i in tcLine.split('\n')
              if 'transient' not in i
              and 'spdoc_check' not in i
              and 'align' not in i]

        return '\n'.join(tc)

    def compile(self, prg: str, atk: str, com: str, ent: int,
                isa=0, spdoc=0) -> Optional[str]:
        flag = f'-C {self.template}'
        mute = '> /dev/null 2>&1'
        os.system(f'make PROGRAM=$PWD/{prg} ' +
                  f'TARGET={self.target} ' +
                  f'ATTACK={atk} COMMIT={com} ENTROPY={ent} ' +
                  f'ISA={isa} ' +
                  f'SPDOC={spdoc} ' +
                  f'{flag} {mute}')

        binary = f'{prg}.riscv'
        image = f'{prg}.bin' # Needed for Nutshell

        if os.path.isfile(f'{binary}'):
            if self.target == 'Nutshell' and not os.path.isfile(f'{image}'):
                return None
            return binary
        else:
            return None

    def clean(self, prg: str):
        flag = f'-C {self.template}'
        mute = '> /dev/null 2>&1'
        os.system(f'make PROGRAM=$PWD/{prg} clean ' +
                  f'{flag} {mute}')


class Simulator:
    def __init__(self, target: str, rsim: str, isim: str):
        self.target = target
        self.rsim = rsim
        self.isim = isim

    def runRTL(self, binary: str, log: str, recv=False, debug=False) -> int:
        timing = '-t' if recv else ''

        if self.target == 'Boom':
            debug = f'-x 70000 --vcd={log.rsplit(".", 1)[0]}.vcd' if debug else '' # TODO: 70000?
            cmd = f'{self.rsim} --seed=0 --verbose {timing} {debug} {binary}'
        elif self.target == 'Nutshell':
            image = binary.split('.riscv')[0] + '.bin'
            debug = f'-d {log.rsplit(".", 1)[0]}.vcd' if debug else ''
            cmd = f'{self.rsim} -s 0 -b 0 -e 0 {timing} {debug} -i {image}'

        p = Popen([i for i in cmd.split(' ') if i != ''],
                  stderr=PIPE, stdout=PIPE)
        timer = Timer(600, p.kill)
        try:
            timer.start()
            _, stderr = p.communicate()
        finally:
            timer.cancel()

        with open(log, 'w') as fd:
            fd.write(stderr.decode('utf-8'))

        ret = p.poll()
        return ret

    # Run ISA simulation to obtain cause message
    def runISA(self, binary: str) -> str:
        ret = os.popen(f'{self.isim} -l {binary} 2>&1').read()
        return ret


class Analyzer:
    def __init__(self, target: str):
        self.target = target

    def analyze_t1(self, binary: str, log: str) -> (bool, Optional[ROBLog]):
        symbols = os.popen(f'nm {binary} | grep " attack"').read().split('\n')
        start = int(symbols[0].split()[0], 16)
        end = int(symbols[1].split()[0], 16)

        with open(f'{log}', 'r') as fd:
            lines = fd.readlines()

        if 'PASSED' not in lines[-1]:
            return (False, None)

        lines = lines[3:-1]
        res = ROBLog(0, 0, 0, 0, 0)
        pattern = '^([0-9]) \((.*)\) -> \((.*)\) DASM\((.*)\) \[(.*)\]\[(.*)\]'
        enc = [10, 16, 16, 16, 10, 10]
        for line in lines:
            match = re.search(pattern, line)
            tpe, tpc, mpc, trg_inst, wsz, ewsz = tuple([int(match.group(i), enc[i-1])
                                                       for i in range(1, 7)])

            if tpc >= start and tpc < end and ewsz > res.ewsz:
                # NOTE: mpc should be under 'attack' label for instruction embedding
                if tpe == TPE.BR.value:
                    if mpc > tpc and mpc < end:
                        res = ROBLog(tpe, tpc, mpc, trg_inst, ewsz)
                elif mpc >= start and mpc < end:
                    res = ROBLog(tpe, tpc, mpc, trg_inst, ewsz)

        if res.ewsz:
            return (True, res)
        else:
            return (False, None)

    def analyze_t3(self, logs: List[str]) -> (bool, Set[Component]):

        pattern = '^\[(.*)\((.*)\)]\((.*)\)=\[(.*)\]'
        logMaps = {}
        for i, log in enumerate(logs):
            with open(f'{log}', 'r') as fd:
                lines = fd.readlines()

            logMap = {}
            for line in lines:
                match = re.search(pattern, line)
                if not match: continue
                (mod, mid, mem, val) = tuple([match.group(i)
                                              for i in range(1, 5)])

                k = (mod, int(mid))
                v = (mem, int(val, 16))
                logMap[k] = logMap.get(k, []) + [v]

            for k, v in logMap.items():
                vals = [i[1] for i in v]
                logMap[k] = (reduce(lambda i, j: i^j, vals), v)

            logMaps[i] = logMap

        diffs = []
        # TODO: Must ensure all logMap items have same keys
        # For (mname, mid)
        for k in logMaps[0].keys():
            # First check, module level hash
            if len(set([m[k][0] for m in logMaps.values()])) != 1:

                def f(x: tuple): return x[0]
                names = list(map(f, set(sum([m[k][1]
                                             for m in logMaps.values()], []))))

                def g(x: str): return (names.count(x) > 1)
                diffs += [Component(k[0], k[1], i)
                          for i in list(set(filter(g, names)))]

        if diffs:
            return (True, set(diffs))
        else:
            return (False, {})

    def analyze_t4(self, logs: List[str]) -> bool:

        pattern = '.*\[SpecDoctor\] Cycle: ([0-9]+).*'

        cycles = []
        passed = True
        for i, log in enumerate(logs):
            with open(f'{log}', 'r') as fd:
                line = '\n'.join(fd.readlines())

            match = re.match(pattern, line, re.DOTALL)
            ###### TODO: Delete ########
            if not match:
                return False
            ############################
            cycles.append(int(match.group(1)))

            passed = passed and ('FAILED' not in line)

        return passed and (len(set(cycles)) > 1)
