###########################################################
# Makefile for SpecDoctor
# #######################
# Makes baremetal executables to run on RISC-V
###########################################################

TARGET ?= Boom
ifeq ($(TARGET), Boom)
else ifeq ($(TARGET), Nutshell)
else
    $(error Bad TARGET)
endif

# Folders
SRC=src
INC=inc
LNK=link

# Commands and flags
GCC=riscv64-unknown-elf-gcc
OBJDUMP=riscv64-unknown-elf-objdump
OBJCOPY=riscv64-unknown-elf-objcopy
OPT ?= 0 # Compiler optimization
CFLAGS=-mcmodel=medany -ffreestanding -fvisibility=hidden -fno-zero-initialized-in-bss -march=rv64g -mabi=lp64 -std=gnu99 -O$(OPT) -g
LDFLAGS=-static -nostdlib -nostartfiles
DUMPFLAGS=--disassemble-all --disassemble-zeros --section=.
COPYFLAGS=--set-section-flags .bss=alloc,contents -O binary

# Program to compile
PROGRAM ?= entry
BIN=$(addsuffix .riscv,$(PROGRAM))
DUMP=$(addsuffix .dump,$(PROGRAM))
IMAGE=$(addsuffix .bin,$(PROGRAM))

# Variables
ATTACKS := S2M U2M U2S
COMMITS := ATTACKER VICTIM

ATTACK ?= S2M 
COMMIT ?= ATTACKER 
ENTROPY ?= $(shell bash -c 'echo $$RANDOM')
SPDOC ?= 0
ISA ?= 0

ifneq ($(filter $(ATTACK),$(ATTACKS)),)
else
    $(error Bad ATTACK argument)
endif

ifneq ($(filter $(COMMIT),$(COMMITS)),)
else
    $(error Bad COMMIT argument)
endif

all: $(BIN) $(DUMP) $(IMAGE)
	$(shell ./tool/fix.py $(BIN))

dump: $(DUMP)
bin: $(BIN)

# Build executable
$(BIN): $(PROGRAM).S
	$(GCC) $(CFLAGS) $(LDFLAGS) -I$(INC) -T$(LNK)/link.ld -DTARGET=$(TARGET) -DATTACK=$(ATTACK) -DCOMMIT=$(COMMIT) -DENTROPY=$(ENTROPY) -DSPDOC=$(SPDOC) -DISA=$(ISA) $< $(SRC)/* -o $@

# Build dump
$(DUMP): $(BIN)
	$(OBJDUMP) -D $< > $@

# Build image
ifeq ($(TARGET), Boom)
$(IMAGE): ;
else # Nutshell
$(IMAGE): $(BIN)
	$(OBJCOPY) $(COPYFLAGS) $(BIN) $(IMAGE)
endif

# Remove all generated files
clean:
	rm -rf $(BIN) $(DUMP) $(IMAGE)
