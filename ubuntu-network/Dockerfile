FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Instalar herramientas de networking y ttyd
RUN apt-get update && \
    apt-get install -y \
    openssh-server \
    iproute2 \
    iputils-ping \
    tcpdump \
    net-tools \
    iptables \
    traceroute \
    netcat-openbsd \
    dnsutils \
    curl \
    wget \
    vim \
    nano \
    sudo \
    iperf3 \
    nmap \
    hping3 \
    tshark \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instalar ttyd (terminal web)
RUN curl -L https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 -o /usr/local/bin/ttyd && \
    chmod +x /usr/local/bin/ttyd

# Configurar usuario
RUN useradd -m -s /bin/bash -G sudo student && \
    echo 'student:student' | chpasswd && \
    echo 'student ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Habilitar forwarding IPv4
RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

WORKDIR /home/student
USER student

EXPOSE 7681

CMD ["ttyd", "-p", "7681", "-W", "bash"]
