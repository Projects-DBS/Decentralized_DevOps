#!/bin/bash
set -e

export IPFS_PATH=/data/ipfs
export CLUSTER_PATH=/data/ipfs-cluster

HOSTNAME=$(hostname)

# Set ports and users per container
case "$HOSTNAME" in
  dev_m1)
    SWARM_PORT=4001
    API_PORT=5001
    GATEWAY_PORT=8080
    CLUSTER_PORT=9094
    IPFS_USER=dev
    ;;
  qa_m2)
    SWARM_PORT=4002
    API_PORT=5002
    GATEWAY_PORT=8081
    CLUSTER_PORT=9095
    IPFS_USER=qa
    ;;
  prod_m3)
    SWARM_PORT=4003
    API_PORT=5003
    GATEWAY_PORT=8082
    CLUSTER_PORT=9096
    IPFS_USER=prod
    ;;
  *)
    SWARM_PORT=4001
    API_PORT=5001
    GATEWAY_PORT=8080
    CLUSTER_PORT=9094
    IPFS_USER=root
    ;;
esac

# Set up Swarm Key
SWARM_KEY_CONTENT="/key/swarm/psk/1.0.0/
/base16/
633ffede0baebe3b705a86621d4d490fa00e0666bdba9fe89ab41e895619b79c"

mkdir -p "$IPFS_PATH"
chown -R $IPFS_USER:$IPFS_USER "$IPFS_PATH"
if [ ! -f "$IPFS_PATH/swarm.key" ]; then
    echo "$SWARM_KEY_CONTENT" > "$IPFS_PATH/swarm.key"
    chmod 600 "$IPFS_PATH/swarm.key"
    chown $IPFS_USER:$IPFS_USER "$IPFS_PATH/swarm.key"
fi

# Initialize IPFS if needed
if [ ! -f "$IPFS_PATH/config" ]; then
    echo "Initializing IPFS for $HOSTNAME"
    su - $IPFS_USER -c "ipfs init"
    su - $IPFS_USER -c "ipfs config Addresses.Swarm --json '[\"/ip4/0.0.0.0/tcp/$SWARM_PORT\"]'"
    su - $IPFS_USER -c "ipfs config Addresses.API \"/ip4/127.0.0.1/tcp/$API_PORT\""
    su - $IPFS_USER -c "ipfs config Addresses.Gateway \"/ip4/0.0.0.0/tcp/$GATEWAY_PORT\""
fi

# Set up IPFS Cluster secret (same as swarm key for simplicity)
CLUSTER_SECRET="633ffede0baebe3b705a86621d4d490fa00e0666bdba9fe89ab41e895619b79c"
export CLUSTER_SECRET

mkdir -p $CLUSTER_PATH
chown -R $IPFS_USER:$IPFS_USER $CLUSTER_PATH

# Initialize cluster service if not yet initialized
if [ ! -f "$CLUSTER_PATH/service.json" ]; then
    su - $IPFS_USER -c "IPFS_CLUSTER_PATH=$CLUSTER_PATH ipfs-cluster-service init"
fi

# Optionally adjust Cluster service.json ports
CLUSTER_CONF="$CLUSTER_PATH/service.json"
if [ -f "$CLUSTER_CONF" ]; then
    jq --arg addr "/ip4/0.0.0.0/tcp/$CLUSTER_PORT" '.api.listen_multiaddress = $addr' $CLUSTER_CONF > $CLUSTER_CONF.tmp && mv $CLUSTER_CONF.tmp $CLUSTER_CONF
    jq --arg addr "/ip4/0.0.0.0/tcp/$CLUSTER_PORT" '.rpc.listen_multiaddress = $addr' $CLUSTER_CONF > $CLUSTER_CONF.tmp && mv $CLUSTER_CONF.tmp $CLUSTER_CONF
fi

# Start SSH
/usr/sbin/sshd

# Start IPFS daemon (background)
su - $IPFS_USER -c "ipfs daemon &"

# Start IPFS Cluster
su - $IPFS_USER -c "IPFS_CLUSTER_PATH=$CLUSTER_PATH ipfs-cluster-service daemon"
