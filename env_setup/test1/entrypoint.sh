#!/bin/bash
set -e

export IPFS_PATH=/data/ipfs

# Get hostname to decide config
HOSTNAME=$(hostname)

# Default ports
SWARM_PORT=4001
API_PORT=5001
GATEWAY_PORT=8080
IPFS_USER=root

# Customize ports and user per container
case "$HOSTNAME" in
  dev_m1)
    SWARM_PORT=4001
    API_PORT=5001
    GATEWAY_PORT=8080
    IPFS_USER=dev
    ;;
  qa_m2)
    SWARM_PORT=4002
    API_PORT=5002
    GATEWAY_PORT=8081
    IPFS_USER=qa
    ;;
  prod_m3)
    SWARM_PORT=4003
    API_PORT=5003
    GATEWAY_PORT=8082
    IPFS_USER=prod
    ;;
  *)
    echo "⚠️ Unknown container hostname: $HOSTNAME"
    echo "Using default IPFS ports"
    ;;
esac

# Fix ownership so the intended user can access IPFS repo
chown -R $IPFS_USER:$IPFS_USER "$IPFS_PATH"

# Swarm key (same for all containers)
SWARM_KEY_CONTENT="/key/swarm/psk/1.0.0/
/base16/
633ffede0baebe3b705a86621d4d490fa00e0666bdba9fe89ab41e895619b79c"

# Add swarm key if missing
if [ ! -f "$IPFS_PATH/swarm.key" ]; then
    echo "$SWARM_KEY_CONTENT" > "$IPFS_PATH/swarm.key"
    chmod 600 "$IPFS_PATH/swarm.key"
    chown $IPFS_USER:$IPFS_USER "$IPFS_PATH/swarm.key"
fi

# Initialize IPFS if not yet initialized
if [ ! -f "$IPFS_PATH/config" ]; then
    echo "Initializing IPFS for $HOSTNAME"
    ipfs init

    ipfs config Addresses.Swarm --json "[\"/ip4/0.0.0.0/tcp/$SWARM_PORT\"]"
    ipfs config Addresses.API "/ip4/127.0.0.1/tcp/$API_PORT"
    ipfs config Addresses.Gateway "/ip4/0.0.0.0/tcp/$GATEWAY_PORT"
fi

# Start SSH
/usr/sbin/sshd

# Start IPFS
exec ipfs daemon
