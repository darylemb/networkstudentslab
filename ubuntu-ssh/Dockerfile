FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y openssh-server sudo curl wget vim net-tools iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configurar SSH
RUN mkdir /var/run/sshd && \
    echo 'root:student' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Crear usuario student
RUN useradd -m -s /bin/bash -G sudo student && \
    echo 'student:student' | chpasswd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
