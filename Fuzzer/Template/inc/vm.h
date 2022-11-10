// See LICENSE for license details.

#ifndef _ENV_VIRTUAL_SINGLE_CORE_H
#define _ENV_VIRTUAL_SINGLE_CORE_H

#include "encoding.h"

//-----------------------------------------------------------------------
// Supervisor mode definitions and macros
//-----------------------------------------------------------------------

#define MAX_TEST_PAGES 127 // this must be the period of the LFSR below
#define LFSR_NEXT(x) (((((x)^((x)>>1)) & 1) << 5) | ((x) >> 1))

#define PTSHIFT 9
#define PTMASK (1UL << PTSHIFT) - 1
#define PGSHIFT 12
#define PGSIZE (1UL << PGSHIFT)

#define SIZEOF_TRAPFRAME_T ((__riscv_xlen / 8) * 36)

#ifndef __ASSEMBLER__

typedef unsigned long pte_t;
#define LEVELS (sizeof(pte_t) == sizeof(uint64_t) ? 3 : 2)
#define PTIDXBITS (PGSHIFT - (sizeof(pte_t) == 8 ? 3 : 2))
#define VPN_BITS (PTIDXBITS * LEVELS)
#define VA_BITS (VPN_BITS + PGSHIFT)
#define PTES_PER_PT (1UL << RISCV_PGLEVEL_BITS)
#define MEGAPAGE_SIZE (PTES_PER_PT * PGSIZE)

#define L1_PT_IDX(vaddr)                        \
  ((unsigned long) vaddr >> (2 * PTSHIFT + PGSHIFT)) & PTMASK
#define L2_PT_IDX(vaddr)                        \
  ((unsigned long) vaddr >> (PTSHIFT + PGSHIFT)) & PTMASK
#define L3_PT_IDX(vaddr)                        \
  ((unsigned long) vaddr >> PGSHIFT) & PTMASK

#define PPN(paddr)                               \
  ((pte_t) paddr >> PGSHIFT) << PTE_PPN_SHIFT


typedef struct
{
  long gpr[32];
  long sr;
  long epc;
  long badvaddr;
  long cause;
} trapframe_t;
#endif

#endif
