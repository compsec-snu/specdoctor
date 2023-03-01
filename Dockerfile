FROM ubuntu:20.04

# Disable dialog questions
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

# Install git, sudo
RUN apt update \
 && apt install -y \
    git \
    sudo

# Install specdoctor, it takes about 1 hour
WORKDIR "/root"

RUN git clone https://github.com/compsec-snu/specdoctor.git \
 && cd specdoctor \
 && echo "y" | ./setup.sh

ENTRYPOINT ["/bin/bash"]
