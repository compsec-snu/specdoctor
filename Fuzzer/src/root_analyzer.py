"""
SpecDoctor root cause analyzer
for found transient execution attack
"""

import re
import sys
import json
from typing import List, Dict, Tuple, Any
from Verilog_VCD.Verilog_VCD import parse_vcd


def read_json(fname: str) -> Any:
    with open(fname, 'r') as fd:
        ret = json.load(fd)

    return ret

def fullname(sig: Dict[str, str]) -> str:
    path = sig['hier']
    name = re.sub('\[[0-9]+:0\]', '', sig['name'])

    return f'{path}.{name}'

def parse_signals(vcd: str) -> Dict[str, List[Tuple[int, int]]]:
    data = parse_vcd(vcd)

    tvs = {k: v['tv'] for k, v in data.items()}
    names = {fullname(s): k for k, v in data.items()
             for s in v['nets']}

    sig = {k: [(t, int(i, 2)) for t, i in tvs[v]]
           for k, v in names.items()}

    return sig

def calibrate(sig0, sig1, icycle0: int, icycle1: int) -> (Dict, Dict):

    def sync(sig, icycle) -> Dict:
        synced = {k: [(i - icycle, j) for i, j in v]
                  for k, v in sig.items()}

        return synced

    def trim(sig) -> Dict:
        trimmed = {k: [(i, j) for i, j in v if i >= 0]
                   for k, v in sig.items()}

        return trimmed

    sig0_s = sync(sig0, icycle0)
    sig1_s = sync(sig1, icycle1)

    sig0_t = trim(sig0_s)
    sig1_t = trim(sig1_s)

    return sig0_t, sig1_t

def diff(tvs0, tvs1: List[Tuple[int, int]]):
    tvs0 = tvs0.copy()
    tvs1 = tvs1.copy()

    while tvs0 and tvs1:
        t0, v0 = tvs0.pop(0)
        t1, v1 = tvs1.pop(0)

        if t0 == t1:
            if v0 != v1:
                return t0
        else:
            return min(t0, t1)

    if tvs0:
        return tvs0[0][0]
    elif tvs1:
        return tvs1[0][0]
    else:
        return sys.maxsize


class RootAnalyzer:
    def __init__(self, target: str):
        self.target = target

        if target == 'Boom':
            TOP = 'TOP.TestHarness.dut.system'

            self.FInsts = {
                'BoomFrontend'         : 'frontend',
                'BoomCore'             : 'core',
                'PTW'                  : 'ptw',
                'LSU'                  : 'lsu',
                'BoomNonBlockingDCache': 'dcache'
            }

            self.FValids = read_json('boom-logs/ChipTop.valids.json')
            self.FValid_paths = {f'{TOP}.boom_tile.{self.FInsts[k]}.{i}': k
                                 for k, v in self.FValids.items()
                                 for i in v}
            TL_out = ['auto_tl_master_xing_out_a_valid',
                      'auto_tl_master_xing_out_c_valid',
                      'auto_tl_master_xing_out_e_valid']
            TL_in  = ['auto_tl_master_xing_out_b_valid',
                      'auto_tl_master_xing_out_d_valid']

            self.Mem_out_sigs = [f'{TOP}.boom_tile.{i}' for i in TL_out]
            self.Mem_in_sigs = [f'{TOP}.boom_tile.{i}' for i in TL_in]

        elif target == 'Nutshell':
            TOP = 'TOP.NutShellSimTop.soc'

            self.FInsts = {
                'TLB':'TLB',
                'Cache':'Cache',
                'TLB_1':'TLB_1',
                'SimpleBusAutoIDCrossbarNto1':'SimpleBusAutoIDCrossbarNto1',
                'SimpleBusCrossbarNto1':'SimpleBusCrossbarNto1',
                'Cache_1':'Cache_1',
                'SimpleBusUCExpender':'SimpleBusUCExpender',
                'Backend_ooo':'Backend_ooo',
                'Frontend_ooo':'frontend'
            }

            self.FValids = read_json('nutshell-logs/NutShellSimTop.valids.json')
            self.FValid_paths = {f'{TOP}.nutcore.{self.FInsts[k]}.{i}': k
                                 for k, v in self.FValids.items()
                                 for i in v}
            Mem_in = [
                'io_imem_mem_req_ready',
                'io_imem_mem_resp_valid',
                'io_dmem_mem_req_ready',
                'io_dmem_mem_resp_valid',
                'io_dmem_coh_req_valid',
                'io_mmio_req_ready',
                'io_mmio_resp_valid',
                'io_mmio_resp_bits_rdata',
                'io_frontend_req_valid',
            ]
            Mem_out = [
                'io_imem_mem_req_valid',
                'io_dmem_mem_req_valid',
                'io_dmem_coh_req_ready',
                'io_dmem_coh_resp_valid',
                'io_mmio_req_valid',
                'io_frontend_req_ready',
                'io_frontend_resp_valid',
            ]
            self.Mem_out_sigs = [f'{TOP}.nutcore.{i}' for i in Mem_out]
            self.Mem_in_sigs = [f'{TOP}.nutcore.{i}' for i in Mem_in]

        else:
            raise NotImplementedError()


    def analyze(self, vcd0: str, vcd1: str) -> (bool, str, str):
        sig0 = parse_signals(vcd0)
        sig1 = parse_signals(vcd1)

        def find_icycle(tvs: List[Tuple[int, int]]) -> int:
            for t, v in tvs:
                if v == 1:
                    return t

            raise Exception('Interrupt is not asserted')

        icycle0 = find_icycle(sig0['TOP.io_interrupt'])
        icycle1 = find_icycle(sig1['TOP.io_interrupt'])

        sig0, sig1 = calibrate(sig0, sig1, icycle0, icycle1)

        # Check if the cause was from external
        out_d = {s: diff(sig0[s], sig1[s]) for s in self.Mem_out_sigs}
        in_d = {s: diff(sig0[s], sig1[s]) for s in self.Mem_in_sigs}

        earliest_o, earliest_i = min(out_d, key=out_d.get), min(in_d, key = in_d.get)
        c_out, c_in = out_d[earliest_o], in_d[earliest_i]

        if c_out > c_in:
            return (False, '', '') # From outer world

        FValid_d = {p: diff(sig0[p], sig1[p]) for p in self.FValid_paths.keys()}

        earliest_v = min(FValid_d, key=FValid_d.get)
        c = FValid_d[earliest_v]

        return (True, self.FValid_paths[earliest_v], earliest_v)
