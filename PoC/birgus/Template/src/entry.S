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

    la t0, mtvec_handler
    csrw mtvec, t0
    la t0, stvec_handler
    csrw stvec, t0

    la sp, STACK_TOP
    la tp, THREAD_TOP

    /* Memory layout configuration */

    /* Enable S-mode cycle reading */

    li a0, MSTATUS_MPP
    // csrc mstatus, a0

    // li a0, (MSTATUS_MPP & (MSTATUS_MPP >> 1))
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

