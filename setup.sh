#!/bin/bash

set -e

echo "This change your computer setting. We recommend using docker!!"
echo "Coninue? [y/n]"

read yn
if [[ $yn != "y" ]]; then
    exit 0
fi

./dependency.sh

root=$PWD

chipyard=${root}/chipyard
chipyard_url=https://github.com/ucb-bar/chipyard.git
chipyard_tag=1.3.0
chipyard_patch=${root}/chipyard.patch

firrtl_chipyard=${chipyard}/tools/firrtl
riscv_boom=${chipyard}/generators/boom
riscv_isa_sim=${chipyard}/toolchains/riscv-tools/riscv-isa-sim

submodule_riscv_isa_sim=toolchains/riscv-tools/riscv-isa-sim

riscv_install=${chipyard}/riscv-tools-install

firrtl_chipyard_patch=${root}/firrtl-chipyard.patch
riscv_boom_patch=${root}/riscv-boom.patch
riscv_isa_sim_patch=${root}/riscv-isa-sim.patch

nutshell=${root}/nutshell
nutshell_url=https://github.com/OSCPU/NutShell.git
nutshell_tag=release-211228
nutshell_patch=${root}/nutshell.patch

firrtl_nutshell=${root}/nutshell/tools/firrtl
firrtl_nutshell_url=https://github.com/chipsalliance/firrtl.git
firrtl_nutshell_commit=7c6f58d986e67b3d0662a4cd6654a68f9cc52cf9
firrtl_nutshell_patch=${root}/firrtl-nutshell.patch


# First clone chipyard, patch and init submodules
echo "[*] setup chipyard"

git clone -b ${chipyard_tag} ${chipyard_url} ${chipyard}

pushd ${chipyard}

git apply ${chipyard_patch}

# torture is deprecated
git submodule update --init generators/rocket-chip
git -C generators/rocket-chip config submodule.torture.update none
./scripts/init-submodules-no-riscv-tools.sh

# update only riscv-isa-sim from toolchains
git -C ${submodule_riscv_isa_sim} config submodule.${submodule_riscv_isa_sim}.update checkout
git submodule update --init --recursive ${submodule_riscv_isa_sim}

# firrtl
pushd ${firrtl_chipyard}
git apply ${firrtl_chipyard_patch}
popd

# riscv-boom
pushd ${riscv_boom}
git apply ${riscv_boom_patch}
popd

# riscv-isa-sim
pushd ${riscv_isa_sim}
git apply ${riscv_isa_sim_patch}

mkdir build
pushd build

../configure --prefix=$PWD
make -j4
popd 
popd

mkdir ${riscv_install}
mkdir ${riscv_install}/lib
mkdir ${riscv_install}/include
mkdir ${riscv_install}/include/fesvr
mkdir ${riscv_install}/include/riscv

cp ${riscv_isa_sim}/build/libfesvr.a ${riscv_install}/lib/
cp ${riscv_isa_sim}/fesvr/*.h ${riscv_install}/include/fesvr/
cp ${riscv_isa_sim}/riscv/mmio_plugin.h ${riscv_install}/include/riscv/
rm ${riscv_install}/include/fesvr/debug_defines.h

# Prepare barstools tapeout
patch -p0 < tapeout.patch

popd

# Build cpu
echo "[**] compile SpecDoctorBoom"

pushd ${chipyard}/sims/verilator
TOPMODULE=BoomTile make CONFIG=SpecDoctorBoomConfig REPL_SEQ_MEM=
popd

# Second clone nutshell, patch
echo "[*] setup nutshell"

git clone -b ${nutshell_tag} ${nutshell_url} ${nutshell}

pushd ${nutshell}
git apply ${nutshell_patch}

git clone ${firrtl_nutshell_url} ${firrtl_nutshell}
pushd ${firrtl_nutshell}
git checkout ${firrtl_nutshell_commit}
git apply ${firrtl_nutshell_patch}
popd

popd 

# compile cpu
echo "[**] compile SpecDoctorNutShell"

pushd ${nutshell}
TOPMODULE=NutCore make ./build/emu
popd

# export env variables
echo "[*] export env variables"

echo "chipyard=${chipyard}" > env.sh
echo "nutshell=${nutshell}" >> env.sh
