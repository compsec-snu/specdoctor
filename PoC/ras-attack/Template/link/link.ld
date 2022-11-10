OUTPUT_ARCH( "riscv" )
ENTRY(_start)

SECTIONS
{
    . = 0x80000000;
    .text.init : { *(.text.init) }
    .tohost ALIGN(0x1000) : { *(.tohost) }
    .text : { *(.text) }

    /* data segment */
    .data ALIGN(0x40) : { *(.data) }

    /* bss segment */
    .bss ALIGN(0x40) : { *(.bss) }

    . = ALIGN(0x1000);
    _end = .;

    . = ALIGN(0x200000);
    .text.attack : { *(.text.attack) }

    . = ALIGN(0x400000);
    .data.secret : { *(.data.secret) }
}
