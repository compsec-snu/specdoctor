// See LICENSE for license details

#include <stdint.h>
#include "vm.h"
#include "template.h"

/* Page table mode */
#if __riscv_xlen == 32
# error
#elif defined(Sv48)
# error
#else
# define SATP_MODE_CHOICE SATP_MODE_SV39
#endif

// SATP_MODE_SV39
//          l1  l2  l3_attack  l3_user
#define NPT 1 + 1 + 1 +        1

pte_t pt[NPT][PTES_PER_PT] __attribute__((aligned(PGSIZE)));

/* Page table */
#define l1pt pt[0]
#define l2pt pt[1]
#define attack_l3pt pt[2]
#define user_l3pt pt[3]

#define code_flag                               \
    PTE_V | PTE_R | PTE_X | PTE_A | PTE_D
#define data_flag                               \
    PTE_V | PTE_R | PTE_W | PTE_A | PTE_D

#define victim_flag 0
#if ATTACK == S2M
#define attacker_flag 0
#else // U2M, U2S
#define attacker_flag PTE_U
#endif

#if COMMIT == ATTACKER
#define commit_flag attacker_flag
#else // VICTIM
#define commit_flag victim_flag
#endif

// Number of data pages
#define NDATA 8

extern uint8_t spdoc[];

extern uint8_t data[NDATA][PGSIZE];
extern uint8_t secret[PGSIZE];

extern void pre_attack0();
extern void pre_attack1();
extern void attack();
extern void shared();
extern void receive();

void set_pte_attack(uintptr_t addr, uint64_t flag);
void set_pte_user(uintptr_t addr, uintptr_t flag);
void config(uint64_t random);

static uint64_t lfsr63(uint64_t x) {
    uint64_t bit = (x ^ (x >> 1)) & 1;
    return (x >> 1) | (bit << 62);
}

void vm_boot()
{
    /* Set VM exactly same as the physical memory */
    // 0x80000000
    l1pt[L1_PT_IDX(DRAM_BASE)] = PPN(l2pt) | PTE_V;

    // [text] 0x80000000
    l2pt[L2_PT_IDX(DRAM_BASE)] = PPN(DRAM_BASE) | code_flag | data_flag;

    // [text.preattack0] 0x80200000
    l2pt[L2_PT_IDX(pre_attack0)] = PPN(pre_attack0) | code_flag | commit_flag;
    // [text.preattack1] 0x80400000
    l2pt[L2_PT_IDX(pre_attack1)] = PPN(pre_attack1) | code_flag | commit_flag;

    // [text.attack, data] 0x80600000
    l2pt[L2_PT_IDX(attack)] = PPN(attack_l3pt) | PTE_V;
    // [text.receive] 0x80800000
    l2pt[L2_PT_IDX(receive)] = PPN(receive) | code_flag | attacker_flag;

    // PTE for user level attacker (when receiving) 0x80a00000
    l2pt[L2_PT_IDX(attack + USR_OFFSET)] = PPN(user_l3pt) | PTE_V;

    // [secret] 0x80c00000
    l2pt[L2_PT_IDX(secret)] = PPN(secret) | data_flag | victim_flag;

    /* Depending on the attack scenario, configure page table */
    uint64_t random = ENTROPY;
    config(random);

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

void set_pte_attack(uintptr_t addr, uint64_t flag) {
    uint64_t idx = L3_PT_IDX(addr);
    attack_l3pt[idx] = PPN(addr) | flag;

    return;
}

void set_pte_user(uintptr_t addr, uint64_t flag) {
    uint64_t idx = L3_PT_IDX(addr + USR_OFFSET);
    user_l3pt[idx] = PPN(addr) | flag;

    return;
}

// Set code pages for commit permission
void config(uint64_t random) {
    set_pte_attack((uintptr_t) attack, code_flag | data_flag | commit_flag);
    set_pte_attack((uintptr_t) shared, code_flag | commit_flag);

    set_pte_user((uintptr_t) attack, code_flag | data_flag | PTE_U);
    set_pte_user((uintptr_t) shared, code_flag | PTE_U);

    uint64_t flag;
    for (int i = 0; i < NDATA; i++) {
#if ATTACK == S2M
        random = lfsr63(random);
        flag = random & PTMASK | PTE_V & ~PTE_U;
#else // U2S, U2M
        flag = data_flag | commit_flag;
#endif
        set_pte_attack((uintptr_t) data[i], flag);
        set_pte_user((uintptr_t) data[i], data_flag | PTE_U);
    }

}
