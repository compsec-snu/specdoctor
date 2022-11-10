"""
File: SpecDoctor Fuzzing Configuration

TODO: Copyright
"""
import yaml

from riscv_definitions import CSRS, PRV
from typing import List

class Confs:
    target: str = 'None'
    # ==============================================================
    # General
    output: str = 'output'
    verbose: bool = False
    isim: str
    rsim: str
    # ==============================================================
    # Fuzzer
    only_generation: bool = False
    num_prp: int = 2
    num_func: int = 5
    num_ctx: int = 2
    n_t1: int = 1
    n_t3: int = 1
    n_t4: int = 1
    t1_thr: float = 0.2
    t3_thr: float = 0.2
    l1_thr: float = 0.5
    keep: bool = True

    atk: str = '' # S2M, U2S, U2M
    com: str = '' # ATTACKER, VICTIM
    # ==============================================================
    # Generator
    supported_isa = [
        'rv32i', 'rv32m', 'rv32a', 'rv32f', 'rv32d',
        'rv64i', 'rv64m', 'rv64a', 'rv64f', 'rv64d',
        'rv_zifencei'
    ]
    blocking_instructions = [
        'ret', 'ecall', 'ebreak'
    ]
    blocking_csrs = [
        *CSRS[PRV.M],
        *CSRS[PRV.H],
        *CSRS[PRV.S],
        'ustatus', 'uie', 'uepc', 'ucause', 'utval', 'uip'
    ]

    def __str__(self):
        variables = [x for x in dir(self)
                     if not callable(getattr(self, x))
                     and not x.startswith('__')]

        variables = {k: getattr(self, k) for k in variables}

        return yaml.dump(variables, explicit_start=True, default_flow_style=False)

    def set(self, name, value):
        assert hasattr(self, name), f'{name} is not in Conf'

        # Check logic for each option
        if name == 'supported_opcodes':
            unsupported = set(value) - set([i.name for i in OPCODES])
            assert unsupported == set([]), f'{unsupported} not supported'

        elif name == 'atk':
            assert value in ['S2M', 'U2S', 'U2M'], \
                f'atk({value}) should be one of "S2M", "U2S", "U2M"'

        elif name == 'com':
            assert value in ['ATTACKER', 'VICTIM'], \
                f'com({value}) should be one of "ATTACKER", "VICTIM"'

        elif name in ['n_t1', 'n_t3', 'n_t4']:
            assert value >= 0, \
                f'{name} should be assigned at least 1'

        assert type(getattr(self, name)) == type(value), \
            f'{value} is not type of {name}'

        setattr(self, name, value)

    def check(self):
        # NOTE: Nutshell does not support F, D-extensions
        if self.target == 'Nutshell':
            self.supported_isa.remove('rv32f')
            self.supported_isa.remove('rv32d')
            self.supported_isa.remove('rv64f')
            self.supported_isa.remove('rv64d')

        assert self.atk and self.com, \
            'ATTACK, COMMIT not set'

        assert not (self.atk == 'U2M' and self.com == 'VICTIM'), \
            'U2M and VICTIM cannot be set together'

CONF = Confs()
