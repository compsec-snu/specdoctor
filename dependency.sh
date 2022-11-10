#!/bin/bash

set -ex

echo "[*] dependencies for chipyard-1.3.0"

sudo apt-get update
sudo apt-get install -y curl build-essential bison flex
sudo apt-get install -y libgmp-dev libmpfr-dev libmpc-dev zlib1g-dev vim git default-jdk default-jre
sudo apt-get install -y unzip zip 
curl -s "https://get.sdkman.io" | bash
source "${HOME}/.sdkman/bin/sdkman-init.sh"
sdk install java $(sdk list java | grep -o "\b8\.[0-9]*\.[0-9]*\-tem" | head -1)
sdk install sbt
# # install sbt: https://www.scala-sbt.org/release/docs/Installing-sbt-on-Linux.html
# echo "deb https://dl.bintray.com/sbt/debian /" | sudo tee -a /etc/apt/sources.list.d/sbt.list
# curl -sL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2EE0EA64E40A89B84B2DF73499E82A75642AC823" | sudo apt-key add
# sudo apt-get update
# sudo apt-get install -y sbt
sudo apt-get install -y texinfo gengetopt
sudo apt-get install -y libexpat1-dev libusb-dev libncurses5-dev cmake
# deps for poky
sudo apt-get install -y python3 patch diffstat texi2html texinfo subversion chrpath git wget
# deps for qemu
sudo apt-get install -y libgtk-3-dev
# deps for firemarshal
sudo apt-get install -y python3-pip python3-dev rsync libguestfs-tools expat
# install DTC
sudo apt-get install -y device-tree-compiler

# install verilator
sudo apt-get install -y autoconf
git clone http://git.veripool.org/git/verilator
cd verilator
git checkout v4.034
autoconf && ./configure && make -j16 && sudo make install


echo "[*] dependencies for nutshell-release-211228"

sudo apt-get install -y libsdl2-dev
sudo sh -c "curl -L https://github.com/com-lihaoyi/mill/releases/download/0.10.8/0.10.8 > /usr/local/bin/mill && chmod +x /usr/local/bin/mill"

echo "[*] dependencies for specdoctor"

pip3 install -r requirements.txt
sudo apt-get install -y binutils-riscv64-unknown-elf gcc-riscv64-unknown-elf
git clone https://github.com/riscv-software-src/riscv-isa-sim.git
mkdir riscv-isa-sim/build
cd riscv-isa-sim/build
../configure
make -j4
sudo make install
