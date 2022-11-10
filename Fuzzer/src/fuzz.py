"""
SpecDoctor Fuzzer

TODO: Copyright
"""
import os
import re
import time
import queue
import random
import shutil
import psutil
import signal
import traceback
from readerwriterlock import rwlock
from threading import Thread, BoundedSemaphore
from functools import wraps
from typing import Type, Optional, List, Dict, Tuple, Set

from config import Confs
from utils import *
from generator import Generator
from root_analyzer import RootAnalyzer


#############################################################
# SpecDoctor Fuzzer
#
# Phase 0: Attack scenario selection & configuration
# Phase 1: Instruction fuzzing to find ROB rollback
# Phase 2: Transient instruction fuzzing to find secret leaks
#
# Multithreaded fuzzer
# Thread 1 (Producer): (Phase 0 + Phase 1)
#   Generate asm file triggering ROB rollback (+ metadata)
# Thread 2 (Consumer & Producer):
#   Check the cause of transient execution
#   Manages only the input with maximum transient window
# Thread 3 (Consumer): (Phase 2)
#   Fuzz transient part of asm file from thread 1
#############################################################


def twrapper(tid: int):
    def trycatch(method):
        @wraps(method)
        def _impl(self, *args, **kwargs):
            try:
                method(self, *args, **kwargs)
            except Exception as e:
                with open(self.output +
                          f'/xcpt_traceback-thread{tid}.txt', 'w') as fd:
                    fd.write(traceback.format_exc())

                self.stopped = True
                raise e

        return _impl
    return trycatch


def parse_name(name: str) -> Tuple:
    splits = name.split('_')
    atk, com, ent, loc, tpe = splits[1:6]

    ent = int(ent)
    if splits[0][0] == 't': # trigger
        tpc, mpc, top, ewsz = splits[6:10]
        tpc = int(tpc, 16)
        mpc = int(mpc, 16)
        ewsz = int(ewsz)
        return (atk, com, ent, loc, tpe, tpc, mpc, top, ewsz)
    elif splits[0][0] in ['d', 'r']:
        top, cse = splits[6:8]
        seeds = [int(i) for i in splits[8:]]
        return (atk, com, ent, loc, tpe, top, cse, *seeds)
    else:
        raise NotImplementedError(f'{name} cat not be parsed')


def wRandom(wpool: List[Tuple[Type, float]]) -> Type:
    r = random.random()
    pvt = r * sum([i[1] for i in wpool])

    acc = [(wpool[i][0], sum([w[1] for w in wpool[:i+1]]))
           for i in range(0, len(wpool))]
    upper = [i[0] for i in acc if pvt <= i[1]]

    return upper[0]


def releaseAll(sem: BoundedSemaphore, n: int):
    try:
        for i in range(n): sem.release()
    except ValueError:
        pass


class AtomicCnt:
    def __init__(self, i: int = 0):
        self.sem = BoundedSemaphore(1)
        self.val = i

    def getInc(self) -> int:
        self.sem.acquire()
        val = self.val
        self.val += 1
        self.sem.release()

        return val

    def getDec(self) -> int:
        self.sem.acquire()
        val = self.val
        self.val -= 1
        self.sem.release()

        return val


class SpecDoctorFuzzer:
    verbose: bool = False

    def __init__(self, conf: Confs):

        """ Make necessary directories """
        self.output = conf.output
        self.triggers = f'{self.output}/triggers'
        self.diff = f'{self.output}/diff'
        self.dinput = f'{self.diff}/input'
        self.dlog = f'{self.diff}/log'
        self.receive = f'{self.output}/receive'
        self.excpt = f'{self.output}/excpt'
        self.notiming = f'{self.output}/excpt/notiming'

        self.keep = conf.keep
        self.prev_trgs = queue.Queue()
        self.prev_dinputs = queue.Queue()
        self.prev_recvs = queue.Queue()
        if os.path.isdir(self.output):
            for i in os.listdir(self.triggers): self.prev_trgs.put(i[:-2])
            for i in os.listdir(self.dinput): self.prev_dinputs.put(i[:-2])
            for i in os.listdir(self.receive): self.prev_recvs.put(i[:-2])
            os.system(f'rm -f {self.dlog}/*')
        else:
            os.makedirs(self.output)
            os.makedirs(self.triggers)
            os.makedirs(self.diff)
            os.makedirs(self.dinput)
            os.makedirs(self.dlog)
            os.makedirs(self.excpt)
            os.makedirs(self.receive)
            os.makedirs(self.notiming)
        """"""

        self.conf = conf

        self.target = conf.target
        self.verbose = conf.verbose
        self.num_prp = conf.num_prp
        self.num_func = conf.num_func
        self.num_ctx = conf.num_ctx
        self.n_t1 = conf.n_t1
        self.n_t3 = conf.n_t3
        self.n_t4 = conf.n_t4
        self.t1_thr = conf.t1_thr
        self.t3_thr = conf.t3_thr
        self.l1_thr = conf.l1_thr
        self.atk = conf.atk
        self.com = conf.com
        self.enum = 0

        self.pre = Preprocessor(conf.target, conf.output)
        self.sim = Simulator(conf.target, conf.rsim, conf.isim)
        self.anal = Analyzer(conf.target)

        self.t1Queue = queue.Queue()
        self.t2Queue = queue.Queue()
        self.t4Queue = queue.Queue()

        self.wszMapLock = rwlock.RWLockWrite()
        self.recvMapSem = BoundedSemaphore(1)
        self.t3Sem = BoundedSemaphore(self.n_t3)
        self.t4Sem = BoundedSemaphore(self.n_t4)

        # Initialize to 0
        for i in range(self.n_t3): self.t3Sem.acquire()
        for i in range(self.n_t4): self.t4Sem.acquire()

        #                                         file, tlabel, ewsz, sel_prob
        self.wszMap: Dict[RollBackInfo, [List[Tuple[str, str, int]], float]] = {}
        self.scdMap: Dict[RollBackInfo, Set[Component]] = {}
        self.scdNames: List[str] = []
        # NOTE: Save priority probability
        #                                                     file, scd, self_prob
        self.recvMap: Dict[Tuple[RollBackInfo, Component], Tuple[str, bool, float]] = {}

        self.t = AtomicCnt(0)
        self.d = AtomicCnt(0)
        self.r = AtomicCnt(0)

        self.stopped = False
        signal.signal(signal.SIGTERM, self.sig_handler)

        self.cur = psutil.Process()
        print(f'[SpecDoctor] Start Fuzzing to Find Transient Execution Attack')
        print(f'             Target: {self.target}')
        print(f'             Attack: {self.atk}, Launch: {self.com}')
        print(f'             Output: {self.output}\n')

        if self.verbose:
            print('=Configuration=\n' +
                  f'{conf}')
        print(f'"kill -15 {self.cur.pid}" to gracefully kill the fuzzer')

        with open(self.output + '/pid', 'w') as fd:
            fd.write(f'{self.cur.pid}\n')

    def __del__(self):
        try:
            children = self.cur.children(recursive=True)
            for ch in children:
                os.kill(ch.pid, signal.SIGKILL)
        except: pass

        print('[SpecDoctor] Stop Fuzzing')

    def sig_handler(self, sig, frame):
        print('[SpecDoctor] Received SIGTERM!')

        releaseAll(self.t3Sem, self.n_t3)
        releaseAll(self.t4Sem, self.n_t4)

        self.stopped = True

    def handle_exception(self, cond, msg: str, prg: str, term=True) -> bool:
        if not cond:
            name = prg.split('/')[-1]
            shutil.move(f'{prg}.S', f'{self.excpt}/{self.enum}_{name}.S')
            self.enum += 1

            self.pre.clean(prg)
            if term:
                self.stopped = True
                raise Exception(f'Exception: {msg}, {prg}')

        return bool(not cond)

    def wakeupGet(self, Q: queue.Queue) -> Optional[str]:
        while not self.stopped:
            try:
                name = Q.get(block=True, timeout=1)
                break
            except queue.Empty:
                if self.stopped:
                    return None

        return name

    def fuzz(self):
        targets_args = ([(self.thread1, (i,)) for i in range(self.n_t1)] +
                        [(self.thread2, ())] +
                        [(self.thread3, (i,)) for i in range(self.n_t3)] +
                        [(self.thread4, (i,)) for i in range(self.n_t4)] +
                        [(self.thread5, ())])

        threads = [Thread(target=t, args=a) for t, a in targets_args]

        self.thread0()

        for t in threads: t.start()
        for t in threads: t.join()


#################################################################################
# Thread for bootstrapping from the existing seeds                              #
#################################################################################

    @twrapper(0)
    def thread0(self):
        while self.keep and not self.stopped:
            phase = None
            if not self.prev_dinputs.empty():
                phase = 3
                name = self.prev_dinputs.get()
                pprg = self.dinput + '/' + name
                sflag = False
            elif not self.prev_recvs.empty():
                phase = 4
                name = self.prev_recvs.get()
                pprg = self.receive + '/' + name
                sflag = True
            else:
                break

            atk, com, ent, loc, tpe, top, cse = parse_name(name)[0:7]
            rbi = RollBackInfo(tpe, top, cse)
            seeds = parse_name(name)[7:]

            logs = []
            seedstrs = [str(s) for s in seeds]
            for i, sd in enumerate(seeds):
                prg = self.pre.embed_sec(phase, pprg, '', sd, 0)
                binary = self.pre.compile(prg, atk, com, ent, 0, 1)
                self.handle_exception(binary, 'T0-compilation-failed', prg)

                log = f'{self.output}/.t0_log_s{i}.txt'
                ret = self.sim.runRTL(binary, log, sflag)

                logs.append(log)
                self.pre.clean(prg)

            if phase == 3:
                (scd, diffs) = self.anal.analyze_t3(logs)
                if scd and diffs - self.scdMap.get(rbi, set()):
                    self.scdMap[rbi] = self.scdMap.get(rbi, set()) | diffs
                    prg = self.pre.embed_sec(3, pprg, '', None, 0)
                    os.remove(f'{self.dinput}/{name}.S')

                    d = self.d.getInc()
                    dest = f'd{d}_{atk}_{com}_{ent}_{loc}_{rbi}_{"_".join(seedstrs)}'
                    shutil.copyfile(f'{prg}.S',
                                    f'{self.dinput}/{dest}.S')

                    with open(f'{self.dlog}/{dest}.log', 'w') as fd:
                        fd.write('\n'.join([f'{k}' for k in diffs]))

                    for comp in diffs:
                        if ((rbi, comp) not in self.recvMap.keys()):
                            self.recvMap[(rbi, comp)] = (dest, False, 1.0)

                    l, p = self.wszMap.get(rbi, [[], 1.0])
                    self.wszMap[rbi] = [l, p * 0.8]

                    self.scdNames.append(dest)
                    print(f'[SpecDoctor] Found dinput: {dest}')

                    releaseAll(self.t4Sem, self.n_t4)
                    self.pre.clean(prg)
                else:
                    os.remove(f'{self.dinput}/{name}.S')

            elif phase == 4:
                (_, diff) = self.anal.analyze_t3(logs)
                scd = self.anal.analyze_t4(logs)
                if scd:
                    # TODO: We don't know root cause component
                    for comp in diff:
                        key = (rbi, comp)
                        # TODO: Check key exists in recvMap
                        p = self.recvMap[key][2]
                        self.recvMap[key] = (self.recvMap[key][0], True, p * 0.5)

                    prg = self.pre.embed_sec(4, pprg, '', None, 0)
                    os.remove(f'{self.receive}/{name}.S')

                    r = self.r.getInc()
                    dest = f'r{r}_{atk}_{com}_{ent}_{loc}_{key[0]}_{"_".join(seedstrs)}'
                    shutil.copyfile(f'{prg}.S',
                                    f'{self.receive}/{dest}.S')

                    print(f'[SpecDoctor] Found leakage: {dest}')
                    self.pre.clean(prg)
                else:
                    os.remove(f'{self.receive}/{name}.S')

            else:
                raise Exception(f'phase {phase} is not defined')

            for log in logs: os.remove(log)


#################################################################################
# Thread triggering transient execution (transient-trigger)                     #
#################################################################################

    @twrapper(1)
    def thread1(self, tid: int):
        wszMapSemR = self.wszMapLock.gen_rlock()
        blocked = ['sfence.vma'] if (self.atk in ['U2M', 'U2S']
                                     and self.com == 'ATTACKER') else []
        gen = Generator(self.conf.supported_isa,
                        self.conf.blocking_instructions + blocked,
                        {'call': 18})

        def get_codes(prg: Optional[str], new: bool, loc='MEM') -> (str, List[str], str, str):
            secret_in_l1 = True if loc == 'L1' else False

            get_pfx = ((lambda *_: gen.create_prefix(PFX, secret_in_l1)) if new
                       else (lambda x: self.pre.extract_block(x, PFX)))

            get_prp = ((lambda *_: gen.create_tc(f'{PRP}{i}', True)) if new
                       else (lambda x, i: self.pre.extract_block(x, f'{PRP}{i}')))

            get_func = ((lambda *_: gen.create_function(f'{FUNC}{i}')) if new
                        else (lambda x, i: self.pre.extract_block(x, f'{FUNC}{i}')))

            get_asm = ((lambda *_: gen.create_tc(TC)) if new
                       else (lambda x: self.pre.extract_block(x, TC)))

            pfx = get_pfx(prg)

            prps = []
            for i in range(self.num_prp):
                prp = get_prp(prg, i)
                prps.append(prp)

            funcs = ''
            for i in range(self.num_func):
                func = get_func(prg, i)
                funcs += func

            asm = get_asm(prg)

            return pfx, prps, funcs, asm


        n = 0
        while not self.stopped:
            if not self.prev_trgs.empty():
                name = self.prev_trgs.get()
                prg = f'{self.triggers}/{name}'

                pfx, prps, funcs, asm = get_codes(prg, False)
                atk, com, ent, loc = parse_name(name)[0:4]

                os.remove(f'{prg}.S')

            elif (random.random() < self.t1_thr and
                  [i for v in self.wszMap.values() for i in v[0]]):
                wszMapSemR.acquire()
                name, tlabel, _ = random.choice([i for v in
                                                 self.wszMap.values() for i
                                                 in v[0]])
                prg = f'{self.triggers}/{name}'

                pfx, prps, funcs, seed = get_codes(prg, False)

                prps, asm = gen.mutate_tc(TC, seed.split('\n'),
                                          [p.split('\n') for p in prps], tlabel)
                wszMapSemR.release()

                atk, com, ent, loc = parse_name(name)[0:4]
            else:
                loc = wRandom([('L1', self.l1_thr), ('MEM', 1 - self.l1_thr)])
                pfx, prps, funcs, asm = get_codes(None, True, loc)

                atk = self.atk
                com = self.com
                ent = random.randint(0, 0xffffffff)

            prg = self.pre.embed_attack(pfx, prps, funcs, asm,
                                        ent, tid)
            binary = self.pre.compile(prg, atk, com, ent)
            self.handle_exception(binary, 'T1-compilation-failed', prg)

            log = f'{self.output}/.t1_log_{tid}.txt'
            ret = self.sim.runRTL(binary, log)
            self.handle_exception(ret >= 0, 'T1-RTL-simulation-failed', prg)

            (trgd, res) = self.anal.analyze_t1(binary, log)
            if trgd:
                t = self.t.getInc()
                dest = f't{t}_{atk}_{com}_{ent}_{loc}_{res}'
                shutil.copyfile(f'{prg}.S',
                                f'{self.triggers}/{dest}.S')
                self.t1Queue.put(dest)

            self.pre.clean(prg)
            n += 1


#################################################################################
# Thread analyzing and preprocessing transient triggering testcase              #
#################################################################################

    @twrapper(2)
    def thread2(self):
        wszMapSemW = self.wszMapLock.gen_wlock()

        def new_ewsz(rbi: RollBackInfo, name: str, ewsz: int) -> (bool, Optional[int]):
            if (rbi not in self.wszMap.keys() or
                not self.wszMap[rbi][0]):
                return True, None
            else:
                atk, com, ent, loc, _, _, _, top, _ = parse_name(name)
                parses = [parse_name(i[0]) for i in self.wszMap[rbi][0]]
                victims = [(i[0], i[1], i[2], i[3], i[7]) for i in parses]

                key = (atk, com, ent, loc, top)
                maxE = max([v[2] for v in self.wszMap[rbi][0]])
                if key in victims:
                    ret = ewsz > maxE
                    vidx = victims.index(key)
                else:
                    ret = ewsz > (maxE * 0.5) # TODO: Best parameter
                    vidx = None if len(victims) < 3 else 0
                return ret, vidx

        while not self.stopped:
            name = self.wakeupGet(self.t1Queue)
            if not name: break

            prg = self.triggers + '/' + name
            atk, com, ent, _, tpe, tpc, mpc, top, ewsz = parse_name(name)

            # NOTE: This should always succeed, because T1 has already succeeded
            binary = self.pre.compile(prg, atk, com, ent, 1)
            isaLog = self.sim.runISA(binary).split('\n')

            cse = None
            for i in range(len(isaLog)):
                if re.match('^core   0: {0:#018x}'.format(tpc), isaLog[i]):
                    match = re.match(f'.*(trap.*),.*', isaLog[i+1])
                    if match:
                        cse = match.group(1).replace('_', '-')
                        n = i + 3
                    elif tpe == TPE.BR.name:
                        cse = 'except-uarch'
                        n = i + 1
                    else: # Data optimization
                        cse = 'except-uarch'
                        n = i + 1

                    match = re.match('^core   0: 0x([0-9a-f]*) .*', isaLog[n])
                    cpc = int(match.group(1), 16)
                    break

            self.handle_exception(cse, f'ISALog-{hex(tpc)}-miss', prg, False)
            if not cse:
                continue

            rbi = RollBackInfo(tpe, top, cse)

            new, vidx = new_ewsz(rbi, name, ewsz)
            if new:
                wszMapSemW.acquire()

                suc, tlabel = self.pre.embed_tsx(prg, tpc, cpc, mpc, TPE[tpe])
                if suc:
                    l, p = self.wszMap.get(rbi, [[], 1.0])
                    self.wszMap[rbi] = [l + [(name, tlabel, ewsz)], p]

                    if vidx is not None:
                        victim, _, _ = self.wszMap[rbi][0].pop(vidx)
                        os.remove(f'{self.triggers}/{victim}.S')
                else:
                    os.remove(f'{self.triggers}/{name}.S')

                wszMapSemW.release()
                releaseAll(self.t3Sem, self.n_t3)
            else:
                os.remove(f'{self.triggers}/{name}.S')

            self.pre.clean(prg)


#################################################################################
# Thread for finding secret transmission (secret-transmit)                      #
#################################################################################

    @twrapper(3)
    def thread3(self, tid: int):
        wszMapSemR = self.wszMapLock.gen_rlock()
        blocked = ['sfence.vma'] if (self.atk in ['U2M', 'U2S']
                                     and self.com == 'ATTACKER') else []
        gen = Generator(self.conf.supported_isa,
                        self.conf.blocking_instructions + blocked,
                        {'call': 18})

        while not self.prev_trgs.empty():
            time.sleep(1)

        while not self.stopped:
            if not self.prev_dinputs.empty():
                name = self.prev_dinputs.get()
                prg = f'{self.dinput}/{name}'

                asm = self.pre.extract_block(prg, TSX)

                os.remove(f'{prg}.S')

            elif random.random() < self.t3_thr and self.scdNames:
                name = random.choice(self.scdNames)
                prg = f'{self.dinput}/{name}'

                seed = self.pre.extract_block(prg, TSX).split('\n')
                asm = gen.mutate_tsx(TSX, seed)
            else:
                asm = gen.create_tc(TSX, False, True)

            wszMapSemR.acquire()

            wpool = [(k, v[1]) for k, v in self.wszMap.items()]
            if (not wpool or
                not all([bool(v[0]) for v in self.wszMap.values()])):
                wszMapSemR.release()
                self.t3Sem.acquire()
                continue

            rbi = wRandom(wpool)
            name = random.choice(self.wszMap[rbi][0])[0]
            tprg = self.triggers + '/' + name
            atk, com, ent, loc = parse_name(name)[0:4]

            logs = []
            seeds = []
            for i in range(self.num_ctx):
                sd = random.randint(0, 0xff)
                seeds.append(str(sd))

                prg = self.pre.embed_sec(3, tprg, asm, sd, tid)
                binary = self.pre.compile(prg, atk, com, ent, 0, 1)
                self.handle_exception(binary, 'T3-compilation-failed', prg)

                log = f'{self.output}/.t3_log_{tid}_s{i}.txt'
                ret = self.sim.runRTL(binary, log)
                if self.handle_exception(ret >= 0, 'T3-RTL-simulation-failed',
                                         prg, False):
                    continue

                logs.append(log)
                self.pre.clean(prg)

            (scd, diffs) = self.anal.analyze_t3(logs)
            if scd and diffs - self.scdMap.get(rbi, set()):
                self.scdMap[rbi] = self.scdMap.get(rbi, set()) | diffs
                prg = self.pre.embed_sec(3, tprg, asm, None, tid)
                d = self.d.getInc()
                dest = f'd{d}_{atk}_{com}_{ent}_{loc}_{rbi}_{"_".join(seeds)}'
                shutil.copyfile(f'{prg}.S',
                                f'{self.dinput}/{dest}.S')

                with open(f'{self.dlog}/{dest}.log', 'w') as fd:
                    fd.write('\n'.join([f'{k}' for k in diffs]))

                self.recvMapSem.acquire()
                for comp in diffs:
                    if (rbi, comp) not in self.recvMap.keys():
                        self.recvMap[(rbi, comp)] = (dest, False, 1.0)

                self.recvMapSem.release()
                # NOTE: We don't need wszMapSemW here
                self.wszMap[rbi][1] *= 0.8
                self.scdNames.append(dest)

                print(f'[SpecDoctor] Found dinput: {dest}')

                releaseAll(self.t4Sem, self.n_t4)
                self.pre.clean(prg)

            for log in logs: os.remove(log)
            wszMapSemR.release()


#################################################################################
# Thread for finding secret reception (secret-receive)                          #
#################################################################################

    @twrapper(4)
    def thread4(self, tid: int):
        blocked = ['sfence.vma'] if (self.atk in ['U2M', 'U2S']) else []
        gen = Generator(self.conf.supported_isa,
                        self.conf.blocking_instructions + blocked,
                        {'call': 18})

        while not self.stopped:
            self.recvMapSem.acquire()
            wpool = [(k, v[2]) for k, v in self.recvMap.items()]
            self.recvMapSem.release()

            if not wpool:
                self.t4Sem.acquire()
                continue

            key = wRandom(wpool)
            name = self.recvMap[key][0]
            dprg = f'{self.dinput}/{name}'
            atk, com, ent, loc = parse_name(name)[0:4]

            asm = gen.create_tc(RCV, False, False, True)

            logs = []
            seeds = parse_name(name)[7:]
            for i, sd in enumerate(seeds):
                prg = self.pre.embed_sec(4, dprg, asm, sd, tid)
                binary = self.pre.compile(prg, atk, com, ent, 0, 1)
                self.handle_exception(binary, 'T4-compilation-failed', prg)

                log = f'{self.output}/.t4_log_{tid}_s{i}.txt'
                ret = self.sim.runRTL(binary, log, True)
                self.handle_exception(ret >= 0, 'T4-RTL-simulation-failed', prg)

                logs.append(log)
                self.pre.clean(prg)

            scd = self.anal.analyze_t4(logs)
            if scd:
                self.recvMapSem.acquire()
                # TODO: We don't know the root cause
                p = self.recvMap[key][2]
                self.recvMap[key] = (self.recvMap[key][0], True, p * 0.5)
                self.recvMapSem.release()

                prg = self.pre.embed_sec(4, dprg, asm, None, tid)
                r = self.r.getInc()
                dest = f'r{r}_{atk}_{com}_{ent}_{loc}_{key[0]}_{"_".join([str(s) for s in seeds])}'
                shutil.copyfile(f'{prg}.S',
                                f'{self.receive}/{dest}.S')
                self.t4Queue.put(dest)

                self.pre.clean(prg)

            for log in logs: os.remove(log)


#################################################################################
# Thread for confirming and analyzing secret-receive testcases                  #
#################################################################################

    @twrapper(5)
    def thread5(self):
        rca = RootAnalyzer(self.target)

        while not self.stopped:
            name = self.wakeupGet(self.t4Queue)
            if not name: break

            atk, com, ent, loc = parse_name(name)[0:4]
            prg = self.receive + '/' + name

            logs = []
            seeds = parse_name(name)[7:]
            for i, sd in enumerate(seeds):
                prg = self.pre.embed_sec(5, prg, '', sd, 0)
                binary = self.pre.compile(prg, atk, com, ent, 0, 1)
                self.handle_exception(binary, 'T5-compilation-failed', prg)

                log = f'{self.output}/.t5_log_0_s{i}.txt'
                ret = self.sim.runRTL(binary, log, True, True)
                self.handle_exception(ret >= 0, 'T5-RTL-simulation-failed', prg)

                logs.append(log)
                self.pre.clean(prg)

            if not self.anal.analyze_t4(logs):
                shutil.copyfile(f'{self.receive}/{name}.S',
                                f'{self.notiming}/{name}.S')
                os.remove(f'{self.receive}/{name}.S')
                print(f'[SpecDoctor] {name} does not make timing channel')
                continue

            # assert self.anal.analyze_t4(logs), \
            #     f'{prg} does not make timing channel'

            assert len(logs) == 2, 'RootAnalyzer only supports two logs'
            confirmed, mod, valid = rca.analyze(*[f'{l.rsplit(".", 1)[0]}.vcd'
                                                  for l in logs])
            if confirmed:
                print(f'[SpecDoctor] Found leakage: {name}')

                with open(f'{self.output}/rca-log.txt', 'a') as fd:
                    fd.write(f'{name}: [{mod}]({valid})\n')
            else:
                os.remove(f'{self.receive}/{name}.S')
