FROM ubuntu:22.04

ARG APP_USERNAME
ARG PASSWORD
ARG CLUSTER_SECRET
ARG SWARM_KEY

ENV APP_USERNAME=${APP_USERNAME}
ENV PASSWORD=${PASSWORD}
ENV CLUSTER_SECRET=${CLUSTER_SECRET}
ENV SWARM_KEY=${SWARM_KEY}
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

COPY configs/decentralized_ssh_auth.sh /usr/local/bin/decentralized_ssh_auth.sh
RUN chmod +x /usr/local/bin/decentralized_ssh_auth.sh


RUN useradd -m -s /bin/bash ${APP_USERNAME} && \
    echo "${APP_USERNAME}:${PASSWORD}" | chpasswd



RUN apt-get update && \
    apt-get install -y curl wget git build-essential sudo nano openssh-server jq python3-pip net-tools ufw docker.io openssl unzip zip sshpass psmisc

RUN sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    echo "AuthorizedKeysCommand /usr/local/bin/decentralized_ssh_auth.sh" >> /etc/ssh/sshd_config && \
    echo "AuthorizedKeysCommandUser guest" >> /etc/ssh/sshd_config && \
    echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config

    
RUN wget https://dist.ipfs.io/go-ipfs/v0.24.0/go-ipfs_v0.24.0_linux-amd64.tar.gz && \
    tar -xvzf go-ipfs_v0.24.0_linux-amd64.tar.gz && \
    cd go-ipfs && bash install.sh && \
    cd / && rm -rf go-ipfs*

RUN wget https://dist.ipfs.tech/ipfs-cluster-service/v1.0.8/ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz && \
    tar -xvzf ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz && \
    mv ipfs-cluster-service/ipfs-cluster-service /usr/local/bin/
RUN wget https://dist.ipfs.tech/ipfs-cluster-ctl/v1.1.4/ipfs-cluster-ctl_v1.1.4_linux-amd64.tar.gz && \
    tar -xvzf ipfs-cluster-ctl_v1.1.4_linux-amd64.tar.gz && \
    mv ipfs-cluster-ctl/ipfs-cluster-ctl /usr/local/bin/

COPY setup.sh /setup.sh
COPY configs/admin_auth.enc /home/${APP_USERNAME}/admin_auth.enc

COPY app /home/${APP_USERNAME}/app/

COPY ipns_keys /home/${APP_USERNAME}/ipns_keys/

COPY configs/admin.pub /admin.pub
RUN chown -R ${APP_USERNAME}:${APP_USERNAME} /home/${APP_USERNAME} /admin.pub


RUN chmod +x /setup.sh


RUN chown -R ${APP_USERNAME}:$APP_USERNAME /tmp/
RUN chown -R ${APP_USERNAME}:$APP_USERNAME /home/${APP_USERNAME}/app/
RUN pip install -r /home/${APP_USERNAME}/app/requirements.txt

EXPOSE 22


ENV FLASK_APP=/home/${APP_USERNAME}/app/app.py


CMD ["/setup.sh"]
