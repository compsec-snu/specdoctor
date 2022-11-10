#define DEFAULT_RSTVEC     0x00001000

#if TARGET == Boom
#define PLIC               0x0c000000
#define PLIC_PRIO          0x0c000000
#define PLIC_ENABLE        0x0c002000
#define PLIC_THR           0x0c200000
#define CLINT_BASE         0x02000000
#define CLINT_SIZE         0x000c0000
#define EXT_IO_BASE        0x40000000
#else // Nutshell
#define PLIC               0x3c000000
#define PLIC_PRIO          0x3c000000
#define PLIC_ENABLE        0x3c002000
#define PLIC_THR           0x3c200000
#endif

#define DRAM_BASE          0x80000000


