FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openssh-server \
    wget curl git sudo nano xxd \
    python3 python3-pip \
    gnupg ca-certificates unzip net-tools

# Set up SSH
RUN mkdir /var/run/sshd && \
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Add users
RUN useradd -m dev && echo "dev:dev123" | chpasswd && adduser dev sudo
RUN useradd -m qa && echo "qa:qa123" | chpasswd && adduser qa sudo
RUN useradd -m prod && echo "prod:prod123" | chpasswd && adduser prod sudo





# Ensure IPFS_PATH is set in every user’s shell
RUN echo 'export IPFS_PATH=/data/ipfs' >> /etc/profile \
 && echo 'export IPFS_PATH=/data/ipfs' >> /home/dev/.bashrc \
 && echo 'export IPFS_PATH=/data/ipfs' >> /home/qa/.bashrc \
 && echo 'export IPFS_PATH=/data/ipfs' >> /home/prod/.bashrc \
 && chown dev:dev /home/dev/.bashrc \
 && chown qa:qa /home/qa/.bashrc \
 && chown prod:prod /home/prod/.bashrc



# Install IPFS
WORKDIR /tmp
RUN wget https://dist.ipfs.tech/kubo/v0.26.0/kubo_v0.26.0_linux-amd64.tar.gz && \
    tar -xzf kubo_v0.26.0_linux-amd64.tar.gz && \
    cd kubo && bash install.sh && \
    rm -rf /tmp/kubo*

# Volume path
RUN mkdir -p /data/ipfs

ENV IPFS_PATH=/data/ipfs


# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 4001 5001 8080



CMD ["/entrypoint.sh"]
