#!/bin/bash
set -e

# Define IPFS data path
export IPFS_PATH=/data/ipfs

# Optional: Define and apply swarm key (replace [base64string] with actual key)
SWARM_KEY_CONTENT="/key/swarm/psk/1.0.0/
/base16/
"
SWARM_KEY_FILE="$IPFS_PATH/swarm.key"

# Initialize IPFS if needed
if [ ! -f "$IPFS_PATH/config" ]; then
    echo "Initializing IPFS node..."
    ipfs init
    ipfs config Addresses.Swarm --json '["/ip4/0.0.0.0/tcp/14001"]'
    ipfs config Addresses.API "/ip4/0.0.0.0/tcp/15001"
    ipfs config Addresses.Gateway "/ip4/0.0.0.0/tcp/18080"
    
    echo "$SWARM_KEY_CONTENT" > "$SWARM_KEY_FILE"
    chmod 600 "$SWARM_KEY_FILE"
fi

# Start SSH
/usr/sbin/sshd

# Start IPFS in foreground (container main process)
exec ipfs daemon
