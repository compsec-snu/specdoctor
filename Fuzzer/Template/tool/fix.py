#!/usr/bin/python3

import sys

eh_size = 64
ph_size = 56
o_p_filesz = 32
o_p_memsz  = 40

o_ph = {
    '.text'           : 0,
    '.bss'            : 1,
    '.tohost'         : 2,
    '.text.preattack0': 3,
    '.text.preattack1': 4,
    '.text.attack'    : 5,
    '.data'           : 6,
    '.text.receive'   : 7,
    '.data.secret'    : 8
}


def main():
    if len(sys.argv) != 2:
        print('Invalid arguments', file=sys.stderr)
        exit(1)

    elf = sys.argv[1]

    with open(elf, 'rb') as fd:
        payload = fd.read()

    arr = bytearray(payload)
    set_size(arr, '.text', 0x1000)
    set_size(arr, '.text.preattack0', 0x400)
    set_size(arr, '.text.preattack1', 0x400)
    set_size(arr, '.text.attack', 0x2000)
    set_size(arr, '.data', 0x7400)
    set_size(arr, '.text.receive', 0x400)
    set_size(arr, '.data.secret', 0x400)

    with open(elf, 'wb') as fd:
        fd.write(bytes(arr))


def set_size(arr: bytearray, seg: str, size: int):
    assert seg in o_ph.keys(), f'Invalid {seg}'

    o_filesz = eh_size + ph_size * o_ph[seg] + o_p_filesz
    o_memsz = eh_size + ph_size * o_ph[seg] + o_p_memsz

    s_in_byte = [i for i in size.to_bytes(8, 'little')]

    for i in range(8):
        arr[o_filesz + i] = s_in_byte[i]
        arr[o_memsz + i] = s_in_byte[i]


if __name__ == '__main__':
    main()
