OUTPUT_ARCH( "riscv" )
ENTRY(_start)

SECTIONS
{
    . = 0x80000000;
    .text : { *(.text) }
    .bss ALIGN(0x1000) : { *(.bss) }
    .tohost ALIGN(0x1000) : { *(.tohost) }
    _end = .;

    . = ALIGN(0x200000); /* 0x80200000 */
    .text.preattack0 : { *(.text.preattack0) }

    . = ALIGN(0x200000); /* 0x80400000 */
    .text.preattack1 : { *(.text.preattack1) }

    . = ALIGN(0x200000); /* 0x80600000 */
    .text.attack : { *(.text.attack) }
    .data : { *(.data) }

    . = ALIGN(0x200000); /* 0x80800000 */
    .text.receive : { *(.text.receive) }

    . = ALIGN(0x400000); /* 0x80c00000 */
    .data.secret : { *(.data.secret) }
}
