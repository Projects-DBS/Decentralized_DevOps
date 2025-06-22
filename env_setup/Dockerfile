FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openssh-server \
    wget curl git sudo nano xxd jq \
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

# Set up IPFS_PATH in all user shells
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

# Install IPFS Cluster Service and CLI
RUN wget https://dist.ipfs.tech/ipfs-cluster-service/v1.0.8/ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz && \
    tar -xzf ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz && \
    mv ipfs-cluster-service/ipfs-cluster-service /usr/local/bin/ && \
    rm -rf ipfs-cluster-service*

RUN wget https://dist.ipfs.tech/ipfs-cluster-ctl/v1.0.8/ipfs-cluster-ctl_v1.0.8_linux-amd64.tar.gz && \
    tar -xzf ipfs-cluster-ctl_v1.0.8_linux-amd64.tar.gz && \
    mv ipfs-cluster-ctl/ipfs-cluster-ctl /usr/local/bin/ && \
    rm -rf ipfs-cluster-ctl*

# Install immudb server
RUN wget https://github.com/codenotary/immudb/releases/download/v1.9.5/immudb-v1.9.5-linux-amd64 && \
    mv immudb-v1.9.5-linux-amd64 /usr/local/bin/immudb && \
    chmod +x /usr/local/bin/immudb

# Install immuclient
RUN wget https://github.com/codenotary/immudb/releases/download/v1.5.0/immuclient-v1.5.0-linux-amd64 && \
    mv immuclient-v1.5.0-linux-amd64 /usr/local/bin/immuclient && \
    chmod +x /usr/local/bin/immuclient

# Install immuadmin
RUN wget https://github.com/vchain-us/immudb/releases/download/v1.3.0/immuadmin-v1.3.0-linux-amd64 && \
    mv immuadmin-v1.3.0-linux-amd64 /usr/local/bin/immuadmin && \
    chmod +x /usr/local/bin/immuadmin

# Volume paths
RUN mkdir -p /data/ipfs /data/ipfs-cluster

ENV IPFS_PATH=/data/ipfs
ENV CLUSTER_PATH=/data/ipfs-cluster

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 4001 4002 4003 5001 5002 5003 8080 8081 8082 9094 9095 9096

CMD ["/entrypoint.sh"]
