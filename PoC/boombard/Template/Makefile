###########################################################
# Makefile for SpecDoctor
# #######################
# Makes baremetal executables to run on RISC-V
###########################################################

# Folders
SRC=src
INC=inc
LNK=link

# Commands and flags
GCC=riscv64-unknown-elf-gcc
OBJDUMP=riscv64-unknown-elf-objdump
CFLAGS=-mcmodel=medany -std=gnu99 -march=rv64g -mabi=lp64 -O0 -g -fno-common -fno-builtin-printf -Wall -Wno-unused-function -Wno-unused-variable
LDFLAGS=-static -nostdlib -nostartfiles -lgcc
DUMPFLAGS=--disassemble-all --disassemble-zeros --section=.

# Program to compile
PROGRAM ?= ${PWD}/boombard
BIN=$(addsuffix .riscv,$(PROGRAM))
DUMP=$(addsuffix .dump,$(PROGRAM))

TRIAL ?= 5
ENTROPY ?= 16727741082765321210

all: $(BIN) $(DUMP)

dump: $(DUMP)
bin: $(BIN)

# Build executable
$(BIN): $(PROGRAM).c
	$(GCC) $(CFLAGS) $(LDFLAGS) -I$(INC) -T$(LNK)/link.ld -DENTROPY=$(ENTROPY) -DTRIAL=$(TRIAL) $(SRC)/* $< -o $@

# Build dump
$(DUMP): $(BIN)
	$(OBJDUMP) -D $< > $@

# Remove all generated files
clean:
	rm -rf $(BIN) $(DUMP)
