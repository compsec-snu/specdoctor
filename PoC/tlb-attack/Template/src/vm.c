// See LICENSE for license details

#include <stdint.h>
#include "encoding.h"
#include "vm.h"

/* Page table mode */
#if __riscv_xlen == 32
# error
#elif defined(Sv48)
# error
#else
# define SATP_MODE_CHOICE SATP_MODE_SV39
#endif

/* Page table */
#define l1pt pt[0]
#define l2pt pt[1]
#define data_l3pt pt[2]
#define secret_l3pt pt[3]

// SATP_MODE_SV39
//          l1  l2_pt  data_l3 secret_l3
#define NPT 1 + 1+     1 +     1

#define code_flag                               \
    PTE_V | PTE_R | PTE_X | PTE_A | PTE_D
#define data_flag                               \
    PTE_V | PTE_R | PTE_W | PTE_A | PTE_D

extern uint8_t data0[];
extern uint8_t data1[];
extern uint8_t data2[];
extern uint8_t conflict[];
extern uint8_t secret[];
extern void attack();

pte_t pt[NPT][PTES_PER_PT] __attribute__((aligned(PGSIZE)));

static uint64_t lfsr63(uint64_t x) {
    uint64_t bit = (x ^ (x >> 1)) & 1;
    return (x >> 1) | (bit << 62);
}

void vm_boot()
{
    /* Set VM exactly same as the physical memory */
    // 0x80000000
    l1pt[L1_PT_IDX(DRAM_BASE)] = PPN(l2pt) | PTE_V;

    // [.text.init, .bss, .tohost, .text] 0x80000000
    l2pt[L2_PT_IDX(DRAM_BASE)] = PPN(DRAM_BASE) | code_flag | data_flag;

    // [.text.attack] 0x80200000
    l2pt[L2_PT_IDX(attack)] = PPN(attack) | code_flag;

    // [.data] 0x80400000
    l2pt[L2_PT_IDX(data0)] = PPN(data_l3pt) | PTE_V;

    // [.data.conflict] 0x80600000
    l2pt[L2_PT_IDX(conflict)] = PPN(conflict) | data_flag;

    // [.data.secret] 0x80800000
    l2pt[L2_PT_IDX(secret)] = PPN(secret_l3pt) | PTE_V;
    secret_l3pt[0] = PPN(secret) | data_flag;

    /**********************************************/

    data_l3pt[L3_PT_IDX(data0)] = PPN(data0) | PTE_V | data_flag;
    data_l3pt[L3_PT_IDX(data1)] = PPN(data1) | PTE_V | data_flag;
    data_l3pt[L3_PT_IDX(data2)] = PPN(data2) | PTE_V;
    uintptr_t vm_choice = SATP_MODE_CHOICE;
    uintptr_t satp_value = ((uintptr_t)l1pt >> PGSHIFT)
                          | (vm_choice * (SATP_MODE & ~(SATP_MODE<<1)));

    write_csr(satp, satp_value);
    write_csr(medeleg,
              (1 << CAUSE_USER_ECALL) |
              (1 << CAUSE_MISALIGNED_FETCH) |
              (1 << CAUSE_ILLEGAL_INSTRUCTION) |
              (1 << CAUSE_MISALIGNED_LOAD) |
              (1 << CAUSE_MISALIGNED_STORE) |
              (1 << CAUSE_USER_ECALL) |
              (1 << CAUSE_FETCH_PAGE_FAULT) |
              (1 << CAUSE_LOAD_PAGE_FAULT) |
              (1 << CAUSE_STORE_PAGE_FAULT));

    asm volatile("sfence.vma zero, zero");

    return;
}
