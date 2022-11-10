import sys
import random

def main(prg: str, seed: int, dsize: int):
    f = f'{prg}_{seed}.S'

    random.seed(seed)
    with open(f'{prg}.S', 'r') as fd:
        lines = fd.readlines()

    with open(f'{f}', 'w') as fd:
        for line in lines:
            fd.write(line)

            if 'secret:' in line:
                for i in range(dsize // (8 * 2)):
                    r0 = random.randint(0, 0xffffffffffffffff)
                    r1 = random.randint(0, 0xffffffffffffffff)
                    fd.write(f'    .dword {hex(r0)}, {hex(r1)}\n')


if __name__ == '__main__':
    prg = sys.argv[1]
    seed = int(sys.argv[2])
    dsize = 1024

    main(prg, seed, dsize)
