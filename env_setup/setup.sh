#!/bin/bash

USERNAME=guest
PASSWORD="123"
PUBKEY_FILE="/id_ed25519.pub"
CLUSTER_SECRET=3ae87335896900efaba880bfc23c58e6f9263a2bc6aad4499b2a51fd275e48f3


# Create guest user if it doesn't exist
if ! id "$USERNAME" &>/dev/null; then
    useradd -m -s /bin/bash "$USERNAME"
    echo "$USERNAME:$PASSWORD" | chpasswd
fi

# Disable root login via SSH
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Enable both password and public key authentication
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Restrict SSH to only the guest user
if ! grep -q "^AllowUsers $USERNAME" /etc/ssh/sshd_config; then
    echo "AllowUsers $USERNAME" >> /etc/ssh/sshd_config
fi

# Add provided pubkey for SSH
mkdir -p /home/$USERNAME/.ssh
if [ -f "$PUBKEY_FILE" ]; then
    # Only add key if not already present
    grep -q -f "$PUBKEY_FILE" /home/$USERNAME/.ssh/authorized_keys 2>/dev/null || \
        cat "$PUBKEY_FILE" >> /home/$USERNAME/.ssh/authorized_keys
fi
chmod 700 /home/$USERNAME/.ssh
chmod 600 /home/$USERNAME/.ssh/authorized_keys
chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh

# Initialize IPFS for guest if needed


# Copy swarm.key if it exists
if [ -f /swarm.key ]; then
    mkdir -p /home/$USERNAME/.ipfs
    cp /swarm.key /home/$USERNAME/.ipfs/swarm.key
    chown $USERNAME:$USERNAME /home/$USERNAME/.ipfs/swarm.key
fi

# Fix ownership of home in case Docker volume mounts as root
chown -R $USERNAME:$USERNAME /home/$USERNAME

# Start SSH service
service ssh start


# Start IPFS daemon as guest user in background
# Initialize IPFS and Cluster as guest
sudo -u $USERNAME ipfs init
sleep 5
sudo -u $USERNAME ipfs daemon &
sleep 5
sudo -u $USERNAME ipfs-cluster-service init
sleep 5
sudo -u "$USERNAME" bash -c '
  jq --arg secret "'"$CLUSTER_SECRET"'" ".cluster.secret = \$secret" ~/.ipfs-cluster/service.json > ~/.ipfs-cluster/service.json.tmp && mv ~/.ipfs-cluster/service.json.tmp ~/.ipfs-cluster/service.json
'
sleep 5
sudo -u $USERNAME ipfs-cluster-service daemon &


# Keep container running
tail -f /dev/null