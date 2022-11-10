/* entry.S */

#include "encoding.h"

#if __riscv_xlen == 64
# define STORE    sd
# define LOAD     ld
# define REGBYTES 8
#else
# define STORE    sw
# define LOAD     lw
# define REGBYTES 4
#endif

#define PASS 1
#define FAIL 3

#define STACK_TOP (_end + 4096)
#define THREAD_TOP (_end + 8192)

    .section ".text.init","ax",@progbits
    .global _start
    .align 2
_start:
    j handle_reset

    /* NMI vector */
    .align 2
nmi_vector:
    j nmi_vector

    .global mtvec_handler
    .align 2
mtvec_handler:
    li gp, FAIL
    la a0, tohost
1:  STORE gp, 0(a0)
    j 1b

    .global stvec_handler
    .align 2
stvec_handler:
    beqz gp, 1f
    csrw sepc, gp
    sret
1:  li gp, PASS
    la a0, tohost
1:  STORE gp, 0(a0)
    j 1b

handle_reset:
    csrwi pmpcfg0, 0
    csrwi mstatus, 0

    /* Init xregs */
    li x1,  0
    li x2,  0
    li x3,  0
    li x4,  0
    li x5,  0
    li x6,  0
    li x7,  0
    li x8,  0
    li x9,  0
    li x10, 0
    li x11, 0
    li x12, 0
    li x13, 0
    li x14, 0
    li x15, 0
    li x16, 0
    li x17, 0
    li x18, 0
    li x19, 0
    li x20, 0
    li x21, 0
    li x22, 0
    li x23, 0
    li x24, 0
    li x25, 0
    li x26, 0
    li x27, 0
    li x28, 0
    li x29, 0
    li x30, 0
    li x31, 0

    li t0, MSTATUS_FS
    csrs mstatus, t0

    la t0, 1f
    csrw mtvec, t0
    fmv.s.x f0, x0
    fmv.s.x f1, x0
    fmv.s.x f2, x0
    fmv.s.x f3, x0
    fmv.s.x f4, x0
    fmv.s.x f5, x0
    fmv.s.x f6, x0
    fmv.s.x f7, x0
    fmv.s.x f8, x0
    fmv.s.x f9, x0
    fmv.s.x f10,x0
    fmv.s.x f11,x0
    fmv.s.x f12,x0
    fmv.s.x f13,x0
    fmv.s.x f14,x0
    fmv.s.x f15,x0
    fmv.s.x f16,x0
    fmv.s.x f17,x0
    fmv.s.x f18,x0
    fmv.s.x f19,x0
    fmv.s.x f20,x0
    fmv.s.x f21,x0
    fmv.s.x f22,x0
    fmv.s.x f23,x0
    fmv.s.x f24,x0
    fmv.s.x f25,x0
    fmv.s.x f26,x0
    fmv.s.x f27,x0
    fmv.s.x f28,x0
    fmv.s.x f29,x0
    fmv.s.x f30,x0
    fmv.s.x f31,x0
1:

    la t0, mtvec_handler
    csrw mtvec, t0
    la t0, stvec_handler
    csrw stvec, t0

    la sp, STACK_TOP
    la tp, THREAD_TOP

    /* Memory layout configuration */
    call pmp_boot
    call vm_boot

    /* Enable S-mode cycle reading */
    li a0, 1
    csrs mcounteren, a0

    li a0, MSTATUS_MPP
    csrc mstatus, a0

    li a0, (MSTATUS_MPP & (MSTATUS_MPP >> 1))
    csrs mstatus, a0
    la t0, attack
    csrw mepc, t0
    mret


    .section ".tohost","aw",@progbits
    .align 6
    .global tohost
tohost:     .dword 0
    .align 6
    .global fromhost
fromhost:   .dword 0


    .section ".text.attack"
    .global attack
    .align 2
attack:
    call main
attack_end:
    la t0, stvec_handler
    jr t0


    .section ".data"
    .global data
data:

    .global data0
    .align 12
data0:
    .dword 0x0706050403020100, 0x0f0e0d0c0b0a0908
    .dword 0x1716151413121110, 0x1f1e1d1c1b1a1918
    .dword 0x2726252423222120, 0x2f2e2d2c2b2a2928
    .dword 0x3736353433323130, 0x3f3e3d3c3b3a3938
    .dword 0x4746454443424140, 0x4f4e4d4c4b4a4948
    .dword 0x5756555453525150, 0x5f5e5d5c5b5a5958
    .dword 0x6766656463626160, 0x6f6e6d6c6b6a6968
    .dword 0x7776757473727170, 0x7f7e7d7c7b7a7978

    .global data1
    .align 12
data1:
    .dword 0x0706050403020100, 0x0f0e0d0c0b0a0908
    .dword 0x1716151413121110, 0x1f1e1d1c1b1a1918
    .dword 0x2726252423222120, 0x2f2e2d2c2b2a2928
    .dword 0x3736353433323130, 0x3f3e3d3c3b3a3938
    .dword 0x4746454443424140, 0x4f4e4d4c4b4a4948
    .dword 0x5756555453525150, 0x5f5e5d5c5b5a5958
    .dword 0x6766656463626160, 0x6f6e6d6c6b6a6968
    .dword 0x7776757473727170, 0x7f7e7d7c7b7a7978


    .section ".data.conflict"
    .global conflict
conflict:

    .global conflict0
    .align 12
conflict0:
    .rept 8
    .dword 0x050505050505005, 0x0505050505050505
    .endr

    .global conflict1
    .align 12
conflict1:
    .rept 8
    .dword 0x050505050505005, 0x0505050505050505
    .endr

    .global conflict2
    .align 12
conflict2:
    .rept 8
    .dword 0x050505050505005, 0x0505050505050505
    .endr

    .global conflict3
    .align 12
conflict3:
    .rept 8
    .dword 0x050505050505005, 0x0505050505050505
    .endr

    .global conflict4
    .align 12
conflict4:
    .rept 8
    .dword 0x050505050505005, 0x0505050505050505
    .endr

    .global conflict5
    .align 12
conflict5:
    .rept 8
    .dword 0x050505050505005, 0x0505050505050505
    .endr

    .global conflict6
    .align 12
conflict6:
    .rept 8
    .dword 0x050505050505005, 0x0505050505050505
    .endr

    .global conflict7
    .align 12
conflict7:
    .rept 8
    .dword 0x050505050505005, 0x0505050505050505
    .endr


    .section ".data.secret"
    .global secret
    .align 12
secret:
    .dword 0x00000000deadbeef
