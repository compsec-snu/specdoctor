# SpecDoctor: Differential Fuzz Testing to Find Transient Execution Vulnerabilities

## Introduction

SpecDoctor is an RTL testing framework to find transient execution vulnerabilities in CPUs.
Given the CPU RTL design, SpecDoctor outputs standalone PoCs which run on bare-metal CPUs.
Currently SpecDoctor supports *RISC-V Boom*, and *RISC-V NutShell*.
SpecDoctor is accepted at ACM CCS 2022 ([paper][paperlink]).

[paperlink]: https://dl.acm.org/doi/abs/10.1145/3548606.3560578

To be specific, SpecDoctor consists of 1) RoB monitor instrumentation, 2) suspicious RTL components instrumentation, and 3) dynamic fuzzing framework.
RoB monitor instrumentation has to be manually done to print RoBLog on the detection of RoB rollback.
Suspicious RTL components instrumentation is automatically done by SpecDoctor compiler, which finds and instruments suspicious RTL components that can be used as a side channel.
Dynamic fuzzing framework consists of 4 steps: i) configuration, ii) transient-trigger, iii) secret-transmit, and iv) secret-receive.
In configuration step, SpecDoctor populates the template of the attack model (i.e.., context of transient execution, and privileges of attacker and victim) from the given arguments.
In transient-trigger step, SpecDoctor finds instructions triggering a transient execution.
In secret-transmit step, SpecDoctor finds instructions transiently changing the u-arch states depending on secret.
Finally, in secret-receive step, SpecDoctor finds instructions observing the changed u-arch states.
For the detail, please see the paper.

## Setup

```
git clone https://github.com/compsec-snu/specdoctor.git
cd specdoctor
./setup.sh
```

* **setup.sh** installs required libraries and setup environments. Then, it compiles the CPU RTL sources into simulatable binaries, where suspicious RTL components are detected and instrumented.
* **setup.sh** changes the system environments, so we recommend running it in docker.
* RoB monitoring logic, SpecDoctor instrumentation procedure can be found in the sources.

## Run

```
# After Setup
cd specdoctor/Fuzzer
source env.sh <target> # Boom or Nutshell
python3 run.py -t <target> -atk <atk> -com <com> -o <output>
```

* You can get information for the arguments through `python3 run.py --help`

## Citation
```
@inproceedings{10.1145/3548606.3560578,
author = {Hur, Jaewon and Song, Suhwan and Kim, Sunwoo and Lee, Byoungyoung},
title = {SpecDoctor: Differential Fuzz Testing to Find Transient Execution Vulnerabilities},
year = {2022},
isbn = {9781450394505},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3548606.3560578},
doi = {10.1145/3548606.3560578},
abstract = {Transient execution vulnerabilities have critical security impacts to software systems since those break the fundamental security assumptions guaranteed by the CPU. Detecting these critical vulnerabilities in the RTL development stage is particularly important, as it offers a chance to fix the vulnerability early before reaching the chip manufacturing stage.This paper proposes SpecDoctor, an automated RTL fuzzer to discover transient execution vulnerabilities in the CPU. To be specific, SpecDoctor designs a fuzzing template, allowing it to test all different scenarios of transient execution vulnerabilities (e.g., Meltdown, Spectre, ForeShadow, etc.) with a single template. Then SpecDoctor performs a multi-phased fuzzing, where each phase is dedicated to solve an individual vulnerability constraint in the RTL context, thereby effectively finding the vulnerabilities.We implemented and evaluated SpecDoctor on two out-of-order RISC-V CPUs, Boom and NutShell-Argo. During the evaluation, SpecDoctor found transient-execution vulnerabilities which share the similar attack vectors as the previous works. Furthermore, SpecDoctor found two interesting variants which abuse unique attack vectors: Boombard, and Birgus. Boombard exploits an unknown implementation bug in RISC-V Boom, exacerbating it into a critical transient execution vulnerability. Birgus launches a Spectre-type attack with a port contention side channel in NutShell CPU, which is constructed using a unique combination of instructions. We reported the vulnerabilities, and both are confirmed by the developers, illustrating the strong practical impact of SpecDoctor.},
booktitle = {Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security},
pages = {1473–1487},
numpages = {15},
keywords = {differential testing, fuzzing, transient-execution vulnerability},
location = {Los Angeles, CA, USA},
series = {CCS '22}
}
```
