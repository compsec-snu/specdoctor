/* Macro for SpecDoctor template */ 

/* Target CPU */
#define Boom        0
#define Nutshell    1

#include "mmap.h"

/* Exit payload */
#if TARGET == Boom || ISA == 1
#define sim_exit                                \
    la a0, tohost;                              \
    nop;                                        \
1:  STORE gp, 0(a0);                            \
    j 1b;
#else // Nutshell
#define sim_exit                                \
    la a0, tohost;                              \
    mv a0, gp;                                  \
    .word 0x0005006b;                           \
1:  j 1b;
#endif

/* Attack scenario */
#define S2M         0
#define U2M         1
#define U2S         2

/* Attack commitment */
#define VICTIM      0
#define ATTACKER    1

/* Memory layout setting */
#define USR_OFFSET  0x400000

/* Pseudo fence instruction */
#define fence_r  \
    slli x0, x0, 0

/* SpecDoctor check macro for CF speculation */
#if TARGET == Boom && SPDOC == 1
#define spdoc_check_c                           \
    fence;                                      \
    la a0, spdoc;                               \
    li t0, 1;                                   \
    STORE t0, 0(a0);                            \
1:  j 1b;
#elif TARGET == Nutshell && SPDOC == 1
#define spdoc_check_c                           \
    fence;                                      \
    li a0, 3; /* STATE_SPDOC_CHECK = 3 */       \
    .word 0x0005006b;                          \
1:  j 1b;
#else
#define spdoc_check_c
#endif

/* SpecDoctor check macro for DF speculation */
#if TARGET == Boom && SPDOC == 1
#define spdoc_check_d                           \
    fence_r;                                    \
    la a0, spdoc;                               \
    li t0, 1;                                   \
    STORE t0, 0(a0);                            \
    nop;                                        \
    nop;
#elif TARGET == Nutshell && SPDOC == 1
#define spdoc_check_d
#else
#define spdoc_check_d
#endif

/* PLIC handle payload */
#define plic_on                                 \
    la a0, PLIC_PRIO;                           \
    li t0, 1;                                   \
    sw t0, 4(a0);                               \
    la a0, PLIC_ENABLE;                         \
    li t0, 2;                                   \
    sw t0, 0(a0);                               \
    la a0, PLIC_THR;                            \
    li t0, 0;                                   \
    sw t0, 0(a0);

#define plic_off                                \
    la a0, PLIC_ENABLE;                         \
    li t0, 0;                                   \
    sw t0, 0(a0);

/* Read cycle payload */
#if TARGET == Boom
#define cycle_start                             \
    csrr t3, cycle;
#define cycle_end                               \
    csrr t4, cycle;                             \
    sub t3, t4, t3;                             \
    la a1, timing;                              \
    STORE t3, 0(a1);
#else // Nutshell
#define cycle_start                             \
    li a0, 4; /* STATE_CYCLE_START = 4 */       \
    .word 0x0005006b;
#define cycle_end                               \
    li a0, 5; /* STATE_CYCLE_END = 5 */         \
    .word 0x0005006b;
#endif
