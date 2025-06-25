FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && \
    apt-get install -y curl wget git build-essential sudo nano openssh-server netcat jq

# Install Node.js 18 LTS and npm
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

# Install IPFS (Go implementation)
RUN wget https://dist.ipfs.io/go-ipfs/v0.24.0/go-ipfs_v0.24.0_linux-amd64.tar.gz && \
    tar -xvzf go-ipfs_v0.24.0_linux-amd64.tar.gz && \
    cd go-ipfs && bash install.sh && \
    cd / && rm -rf go-ipfs*

# Install IPFS Cluster Service and CLI
RUN wget https://dist.ipfs.tech/ipfs-cluster-service/v1.0.8/ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz && \
    tar -xvzf ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz && \
    mv ipfs-cluster-service/ipfs-cluster-service /usr/local/bin/

RUN wget https://dist.ipfs.tech/ipfs-cluster-ctl/v1.1.4/ipfs-cluster-ctl_v1.1.4_linux-amd64.tar.gz && \
    tar -xvzf ipfs-cluster-ctl_v1.1.4_linux-amd64.tar.gz && \
    mv ipfs-cluster-ctl/ipfs-cluster-ctl /usr/local/bin/

# Install OrbitDB and JS IPFS globally as root
RUN npm install -g ipfs orbit-db

RUN mkdir /var/run/sshd

COPY setup.sh /setup.sh
COPY id_ed25519.pub /id_ed25519.pub

RUN chmod +x /setup.sh

# Expose all necessary ports
EXPOSE 4001 5001 8080 9096 9094 22

CMD ["/setup.sh"]
