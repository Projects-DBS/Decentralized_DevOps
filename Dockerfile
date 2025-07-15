FROM ubuntu:22.04

# Build arguments for secrets/config
ARG APP_USERNAME
ARG PASSWORD
ARG CLUSTER_SECRET
ARG ADMIN_PASSWORD
ARG SWARM_KEY

# Set as environment variables so they're accessible at runtime
ENV APP_USERNAME=${APP_USERNAME}
ENV PASSWORD=${PASSWORD}
ENV CLUSTER_SECRET=${CLUSTER_SECRET}
ENV ADMIN_PASSWORD=${ADMIN_PASSWORD}
ENV SWARM_KEY=${SWARM_KEY}
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1


RUN useradd -m -s /bin/bash ${APP_USERNAME} && \
    echo "${APP_USERNAME}:${PASSWORD}" | chpasswd

# Install dependencies
RUN apt-get update && \
    apt-get install -y curl wget git build-essential sudo nano openssh-server jq python3-pip net-tools ufw docker.io openssl unzip zip sshpass psmisc

# SSH server config
RUN mkdir /var/run/sshd
RUN sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Install go-ipfs
RUN wget https://dist.ipfs.io/go-ipfs/v0.24.0/go-ipfs_v0.24.0_linux-amd64.tar.gz && \
    tar -xvzf go-ipfs_v0.24.0_linux-amd64.tar.gz && \
    cd go-ipfs && bash install.sh && \
    cd / && rm -rf go-ipfs*

# Install IPFS Cluster Service and CTL
RUN wget https://dist.ipfs.tech/ipfs-cluster-service/v1.0.8/ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz && \
    tar -xvzf ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz && \
    mv ipfs-cluster-service/ipfs-cluster-service /usr/local/bin/
RUN wget https://dist.ipfs.tech/ipfs-cluster-ctl/v1.1.4/ipfs-cluster-ctl_v1.1.4_linux-amd64.tar.gz && \
    tar -xvzf ipfs-cluster-ctl_v1.1.4_linux-amd64.tar.gz && \
    mv ipfs-cluster-ctl/ipfs-cluster-ctl /usr/local/bin/

# Add entrypoint and admin_auth.json
COPY setup.sh /setup.sh
COPY admin_auth.json /tmp/admin_auth.json

COPY app /home/${APP_USERNAME}/app/

COPY ipns_keys /home/${APP_USERNAME}/ipns_keys/

ENV PYTHONUNBUFFERED=1


RUN chmod +x /setup.sh


RUN chown -R ${APP_USERNAME}:$APP_USERNAME /tmp/
RUN chown -R ${APP_USERNAME}:$APP_USERNAME /home/${APP_USERNAME}/app/
RUN pip install -r /home/${APP_USERNAME}/app/requirements.txt

# Expose required ports
EXPOSE 22  1000 1001 1002 1003

# 6666 9096 9094 4001 8080 5001

ENV FLASK_APP=/home/${APP_USERNAME}/app/app.py


CMD ["/setup.sh"]
