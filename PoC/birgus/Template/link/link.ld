OUTPUT_ARCH( "riscv" )
ENTRY(_start)

SECTIONS
{
    . = 0x80000000;
    .text.init : { *(.text.init) }
    .bss ALIGN(0x1000) : { *(.bss) }
    .text : { *(.text) }
    . = ALIGN(0x1000);
    _end = .;

    . = ALIGN(0x200000);
    .text.attack : { *(.text.attack) }

    . = ALIGN(0x200000);
    .data : { *(.data) }
}
