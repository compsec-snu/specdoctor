"""
SpecDoctor Fuzzer PoC

TODO: Copyright
"""

import os
import shutil
from argparse import ArgumentParser

from src.config import CONF
from src.fuzz import SpecDoctorFuzzer


def main():
    # Argument parser
    parser = ArgumentParser(description='')
    parser.add_argument(
        '-t', '--target',
        type=str,
        required=True,
        help='Target CPU for fuzzing (Boom, Nutshell)',
        choices=['Boom', 'Nutshell']
    )
    # parser.add_argument(
    #     '-t', '--test',
    #     action='store_true',
    #     help='Run unittest'
    # )
    parser.add_argument(
        '-c', '--config',
        type=str,
        required=False
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        required=False,
        help='Output directory path'
    )
    parser.add_argument(
        '-nctx', '--num_ctx',
        type=int,
        required=False,
        help='Number of input context to compare'
    )
    parser.add_argument(
        '-thr1', '--t1_thr',
        type=float,
        required=False,
        help='Threshold for selecting thread1 mutation'
    )
    parser.add_argument(
        '-thr3', '--t3_thr',
        type=float,
        required=False,
        help='Threshold for selecting thread3 mutation'
    )
    parser.add_argument(
        '-l1', '--l1_thr',
        type=float,
        required=False,
        help='Threshold for placing secret in L1-cache'
    )
    parser.add_argument(
        '-nt1', '--n_t1',
        type=int,
        required=False,
        help='Number of thread1'
    )
    parser.add_argument(
        '-nt3', '--n_t3',
        type=int,
        required=False,
        help='Number of thread3'
    )
    parser.add_argument(
        '-nt4', '--n_t4',
        type=int,
        required=False,
        help='Number of thread4'
    )
    parser.add_argument(
        '-atk', '--atk',
        help='delimited list of attacks (S2M, U2S, U2M)',
        type=str
    )
    parser.add_argument(
        '-com', '--com',
        help='delimited list of commitments (ATTACKER, VICTIM)',
        type=str
    )
    parser.add_argument(
        '-k', '--keep',
        action='store_true',
        help='Keep dinputs and receives',
    )

    try:
        CONF.isim = shutil.which(os.environ['ISIM'])
        CONF.rsim = shutil.which(os.environ['RSIM'])

        if not (os.access(CONF.isim, os.X_OK) and
                os.access(CONF.rsim, os.X_OK)):
            raise Exception
    except:
        raise Exception('Invalid ISIM, RSIM')

    args = parser.parse_args()
    if args.config:
        raise NotImplementedError()

    for k, v in vars(args).items():
        if v != None:
            CONF.set(k, v)
    CONF.check()

    fuzzer = SpecDoctorFuzzer(CONF)
    fuzzer.fuzz()

    # NOTE: unittest is deprecated
    # if getattr(args, 'test', False):
    #     test(fuzzer)
    # else:
    #     fuzzer.fuzz()


def test(fuzzer: SpecDoctorFuzzer):
    while True:
        fuzzer.run()


if __name__ == '__main__':
    main()
