#!/bin/bash
set -e

# Use env vars passed from Dockerfile/Compose, or defaults
APP_USERNAME="${APP_USERNAME:-guest}"
PASSWORD="${PASSWORD:-guestpass}"
CLUSTER_SECRET="${CLUSTER_SECRET:-changeme}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-changeme}"
SWARM_KEY="${SWARM_KEY:-changeme}"
HOME_DIR="/home/${APP_USERNAME}"

# Create user if not exists (works with empty/mounted home dir too)
if ! id "$APP_USERNAME" &>/dev/null; then
  useradd -m -s /bin/bash "$APP_USERNAME"
  echo "$APP_USERNAME:$PASSWORD" | chpasswd
  chown -R "$APP_USERNAME:$APP_USERNAME" "$HOME_DIR"
fi

sudo -u "${APP_USERNAME}" pip install --user gunicorn

# Initialize IPFS if not done already
if [ ! -d "${HOME_DIR}/.ipfs" ]; then
    sudo -u "${APP_USERNAME}" ipfs init
    # Setup Swarm key from ENV
    mkdir -p "${HOME_DIR}/.ipfs"
    {
      echo "/key/swarm/psk/1.0.0/"
      echo "/base16/"
      echo "${SWARM_KEY}"
    } > "${HOME_DIR}/.ipfs/swarm.key"
    chown -R "${APP_USERNAME}:${APP_USERNAME}" "${HOME_DIR}/.ipfs"
fi

# Configure IPFS (set only if not already set)
# sudo -u "${APP_USERNAME}" ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080 || true
# sudo -u "${APP_USERNAME}" ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001 || true
sudo -u "${APP_USERNAME}" ipfs config Experimental.IPNSPubsub --bool true || true

if [ -d "/home/${APP_USERNAME}/ipns_keys" ] && compgen -G "/home/${APP_USERNAME}/ipns_keys/*.key" > /dev/null; then
    for keyfile in /home/${APP_USERNAME}/ipns_keys/*.key; do
        keyname=$(basename "$keyfile" .key)
        sudo -u $APP_USERNAME ipfs key import "$keyname" "$keyfile"
    done
    rm -rf /home/${APP_USERNAME}/ipns_keys
fi


# Start SSH
service ssh start

# Start IPFS daemon (in background)
sudo -u "${APP_USERNAME}" ipfs daemon &
sleep 10

# Initialize Cluster Service if needed
if [ ! -d "${HOME_DIR}/.ipfs-cluster" ]; then
  sudo -u "${APP_USERNAME}" ipfs-cluster-service init
  # Set cluster secret
  jq --arg secret "${CLUSTER_SECRET}" '.cluster.secret = $secret' \
    "${HOME_DIR}/.ipfs-cluster/service.json" > "${HOME_DIR}/.ipfs-cluster/service.json.tmp"
  mv "${HOME_DIR}/.ipfs-cluster/service.json.tmp" "${HOME_DIR}/.ipfs-cluster/service.json"
  chown "${APP_USERNAME}:${APP_USERNAME}" "${HOME_DIR}/.ipfs-cluster/service.json"
fi

# Start Cluster Service (in background)
sudo -u "${APP_USERNAME}" ipfs-cluster-service daemon &
sleep 10

# Copy admin auth file to user dir if not exists
mkdir -p "${HOME_DIR}/admin"
if [ ! -f "${HOME_DIR}/admin/admin_auth.json" ]; then
  cp /tmp/admin_auth.json "${HOME_DIR}/admin/admin_auth.json"
  chown "${APP_USERNAME}:${APP_USERNAME}" "${HOME_DIR}/admin/admin_auth.json"
fi

# Add admin_auth.json to IPFS cluster, encrypt, and store DB (if not already done)
sudo -u "${APP_USERNAME}" bash -c "
  cid=\$(ipfs-cluster-ctl add -q ${HOME_DIR}/admin/admin_auth.json)
  encrypted=\$(echo -n \"\$cid\" | openssl enc -aes-256-cbc -a -salt -pbkdf2 -pass pass:\"${ADMIN_PASSWORD}\")
  json_data=\$(jq -n --arg admin \"\$encrypted\" '{\"access_control\": [{\"admin\":\$admin}], \"projects\" : []}')
  echo \"\$json_data\" > ${HOME_DIR}/db.json
  dbcid=\$(ipfs-cluster-ctl add -q ${HOME_DIR}/db.json)
  ipns_output=\$(ipfs name publish --key=\"access_control\" /ipfs/\$dbcid)
  ipns_key=\$(echo \"\$ipns_output\" | awk '{print \$3}' | cut -d\":\" -f1)
  echo \"Access Control IPNS Key is: \$ipns_key\"
  rm ${HOME_DIR}/db.json
"

sudo -u "${APP_USERNAME}" bash -c '
  # Create a temporary file for the JSON
  tmpfile=$(mktemp)
  echo "{\"projects\": []}" > "$tmpfile"

  # Add the file to IPFS Cluster and get the CID
  cid=$(ipfs-cluster-ctl add -q "$tmpfile")

  # Publish the CID to IPNS with the "projects" key
  ipns_output=$(ipfs name publish --key="projects" /ipfs/"$cid")
  ipns_key=$(echo "$ipns_output" | awk "{print \$3}" | cut -d":" -f1)
  echo "Projects IPNS Key is: $ipns_key"

  # Clean up
  rm "$tmpfile"
'

sudo -u "${APP_USERNAME}" bash -c '
  tmpfile=$(mktemp)

  # Write JSON to temp file (no escaping issues)
  cat > "$tmpfile" <<EOF
{
  "roles": [
    {"admin": ["Project Manager", "Product Owner", "Administrator", "DevOps Engineer"]},
    {"developer": ["UI Developer", "Backend Developer"]},
    {"qa": ["Application Tester", "Penetration Tester"]}
  ]
}
EOF

  # Add the file to IPFS Cluster and get the CID
  cid=$(ipfs-cluster-ctl add -q "$tmpfile")
  if [ -z "$cid" ]; then
    echo "Error: Failed to get CID from IPFS Cluster."
    rm "$tmpfile"
    exit 1
  fi

  # Publish the CID to IPNS with the "projects" key
  ipns_output=$(ipfs name publish --key="roles" /ipfs/"$cid")
  if [ $? -ne 0 ]; then
    echo "Error: IPNS publish failed."
    rm "$tmpfile"
    exit 2
  fi

  # Extract IPNS key (adjust parsing if output format changes)
  ipns_key=$(echo "$ipns_output" | awk '\''{print $3}'\'' | cut -d":" -f1)
  echo "Role IPNS Key is: $ipns_key"

  # Clean up
  rm "$tmpfile"
'




sudo -u "${APP_USERNAME}" bash -c '
  # Create a temporary file for the JSON
  tmpfile=$(mktemp)
  echo "{\"project_builds\": []}" > "$tmpfile"

  # Add the file to IPFS Cluster and get the CID
  cid=$(ipfs-cluster-ctl add -q "$tmpfile")

  # Publish the CID to IPNS with the "project_builds" key
  ipns_output=$(ipfs name publish --key="project_builds" /ipfs/"$cid")
  ipns_key=$(echo "$ipns_output" | awk "{print \$3}" | cut -d":" -f1)
  echo "Project Builds IPNS Key is: $ipns_key"

  # Clean up
  rm "$tmpfile"
'



sudo -u "${APP_USERNAME}" bash -c '
  tmpfile=$(mktemp)
  echo "{\"logs\": []}" > "$tmpfile"

  cid=$(ipfs-cluster-ctl add -q "$tmpfile")

  ipns_output=$(ipfs name publish --key="logs" /ipfs/"$cid")
  ipns_key=$(echo "$ipns_output" | awk "{print \$3}" | cut -d":" -f1)
  echo "Logs IPNS Key is: $ipns_key"

  rm "$tmpfile"
'


sudo -u "${APP_USERNAME}" bash -c '
  tmpfile=$(mktemp)
  echo "{\"misc\": []}" > "$tmpfile"

  cid=$(ipfs-cluster-ctl add -q "$tmpfile")

  ipns_output=$(ipfs name publish --key="misc" /ipfs/"$cid")
  ipns_key=$(echo "$ipns_output" | awk "{print \$3}" | cut -d":" -f1)
  echo "Misc IPNS Key is: $ipns_key"

  rm "$tmpfile"
'




sudo -u "${APP_USERNAME}" python3 -u /home/$APP_USERNAME/app/app.py



# Keep container alive
tail -f /dev/null
