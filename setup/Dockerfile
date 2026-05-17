FROM ubuntu:24.04
RUN apt update && apt install -y curl \
        git \
        build-essential \
        gdb \
        ttyd \
        meson \
        ninja-build \
        pkg-config \
        vim \
        python3 \
        python3-pip \
        python3-pyelftools \
        python3-setuptools \
        python3-wheel \
        libnuma-dev \
        libpcap-dev \
        libelf-dev \
        && rm -rf /var/lib/apt/lists/*

# Setup student user
RUN useradd -m -s /bin/bash student && \
    echo "student:keysight2026" | chpasswd

WORKDIR /home/student
USER student

RUN cd /home/student && git clone https://github.com/DPDK/dpdk.git --depth 1

RUN cd /home/student/dpdk && meson setup -Denable_apps="testpmd" -Dexamples="l2fwd" -Denable_drivers="net/pcap,net/null" -Denable_docs="false" -Dtests="false" --buildtype=debug build

USER root
RUN cd /home/student/dpdk && ninja -C build install && ldconfig

# Setup the challenge app using LOCAL files
USER root
RUN mkdir -p /home/student/challenge-app/netem
# Copy the local netem directory to the container
COPY netem /home/student/challenge-app/netem
RUN chown -R student:student /home/student/challenge-app

USER student
WORKDIR /home/student/challenge-app/netem
RUN rm -rf build && meson setup build
RUN ninja -C build

USER root
COPY setup/input.pcap /home/student/input.pcap
RUN chown student:student /home/student/input.pcap

# Switch back to root so ttyd can execute 'login'
USER root
RUN passwd -l root

# Start ttyd on port 7681 (internal)
# -W makes the terminal writable
CMD ["ttyd", "-p", "7681", "-W", "login"]
