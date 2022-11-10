#!/bin/bash

if [[ ! -f "$PWD/../env.sh" ]]; then
    echo "please run ../setup.sh first"
    return
fi

export PYTHONPATH=$PWD/src:$PYTHONPATH

source $PWD/../env.sh

export ISIM=${chipyard}/toolchains/riscv-tools/riscv-isa-sim/build/spike

if [[ ${1} == "Boom" ]]; then
    export RSIM=${chipyard}/sims/verilator/simulator-chipyard-SpecDoctorBoomConfig-debug
    export TARGET=Boom

    rm -rf boom-logs
    ln -s ${chipyard}/specdoctor-logs/ChipTop boom-logs

elif [[ ${1} == "Nutshell" ]]; then
    export RSIM=${nutshell}/build/emu
    export TARGET=Nutshell

    rm -rf nutshell-logs
    ln -s ${nutshell}/specdoctor-logs/NutShellSimTop nutshell-logs
else
    echo "$1 is not supported"
fi
