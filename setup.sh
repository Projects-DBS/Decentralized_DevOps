#!/bin/bash

set -e

APP_USERNAME="${APP_USERNAME:-guest}"
PASSWORD="${PASSWORD:-guestpass}"
CLUSTER_SECRET="${CLUSTER_SECRET:-changeme}"
SWARM_KEY="${SWARM_KEY:-changeme}"
HOME_DIR="/home/${APP_USERNAME}"
check_setup="${HOME_DIR}/.setup_done"
PORT=1000

pid=$(netstat -tlnp 2>/dev/null | awk -v port=":$PORT" '$4 ~ port {split($7,a,"/"); print a[1]}')
if [ -n "$pid" ]; then
  echo "Killing process on port $PORT (pid: $pid)"
  kill -9 $pid
fi

if [ ! -f "$check_setup" ]; then
  export USERNAME="admin"
  export PUBKEY_CONTENT="$(cat /admin.pub)"

  if ! id "$APP_USERNAME" &>/dev/null; then
    useradd -m -s /bin/bash "$APP_USERNAME"
    echo "$APP_USERNAME:$PASSWORD" | chpasswd
    chown -R "$APP_USERNAME:$APP_USERNAME" "$HOME_DIR"
  fi

  sudo -u "${APP_USERNAME}" pip install --user gunicorn

  if [ ! -d "${HOME_DIR}/.ipfs" ]; then
    sudo -u "${APP_USERNAME}" ipfs init
    mkdir -p "${HOME_DIR}/.ipfs"
    {
      echo "/key/swarm/psk/1.0.0/"
      echo "/base16/"
      echo "${SWARM_KEY}"
    } > "${HOME_DIR}/.ipfs/swarm.key"
    chown -R "${APP_USERNAME}:${APP_USERNAME}" "${HOME_DIR}/.ipfs"
  fi

  sudo -u "${APP_USERNAME}" ipfs config Routing.Type dht
  sudo -u "${APP_USERNAME}" ipfs config --json Ipns.RepublishPeriod '"1h"'
  
  sudo -u "${APP_USERNAME}" ipfs config --json Ipns.UsePubsub true
  sudo -u "${APP_USERNAME}" ipfs config --json Experimental.IPNSPubsub true 

  if [ -d "/home/${APP_USERNAME}/ipns_keys" ] && compgen -G "/home/${APP_USERNAME}/ipns_keys/*.key" > /dev/null; then
    for keyfile in /home/${APP_USERNAME}/ipns_keys/*.key; do
      keyname=$(basename "$keyfile" .key)
      sudo -u $APP_USERNAME ipfs key import "$keyname" "$keyfile"
    done
    rm -rf /home/${APP_USERNAME}/ipns_keys
  fi

  service ssh start
  sudo -u "${APP_USERNAME}" ipfs config --json Experimental.IPNSPubsub true

  sleep 3
  sudo -u "${APP_USERNAME}" ipfs daemon --enable-namesys-pubsub &
  sleep 10

  if [ ! -d "${HOME_DIR}/.ipfs-cluster" ]; then
    sudo -u "${APP_USERNAME}" ipfs-cluster-service init
    jq --arg secret "${CLUSTER_SECRET}" '.cluster.secret = $secret' \
      "${HOME_DIR}/.ipfs-cluster/service.json" > "${HOME_DIR}/.ipfs-cluster/service.json.tmp"
    mv "${HOME_DIR}/.ipfs-cluster/service.json.tmp" "${HOME_DIR}/.ipfs-cluster/service.json"
    chown "${APP_USERNAME}:${APP_USERNAME}" "${HOME_DIR}/.ipfs-cluster/service.json"
  fi

  sudo -u "${APP_USERNAME}" ipfs-cluster-service daemon &
  sleep 10

  sudo -u "${APP_USERNAME}" bash -c "
    cid=\$(ipfs-cluster-ctl add -q /home/${APP_USERNAME}/admin_auth.enc)
    json_data=\$(jq -n --arg admin \"\$cid\" '{\"access_control\": [{\"admin\":\$admin}]}')
    echo \"\$json_data\" > ${HOME_DIR}/db.json
    dbcid=\$(ipfs-cluster-ctl add -q ${HOME_DIR}/db.json)
    ipns_output=\$(ipfs name publish  --key=\"access_control\" --lifetime=17520h /ipfs/\$dbcid)
    ipns_key=\$(echo \"\$ipns_output\" | awk '{print \$3}' | cut -d\":\" -f1)
    rm ${HOME_DIR}/db.json 
  "

  sudo -u "${APP_USERNAME}" bash -c '
    tmpfile=$(mktemp)
    echo "{\"projects\": []}" > "$tmpfile"
    cid=$(ipfs-cluster-ctl add -q "$tmpfile")
    ipns_output=$(ipfs name publish  --key="projects" --lifetime=17520h /ipfs/"$cid")
    ipns_key=$(echo "$ipns_output" | awk "{print \$3}" | cut -d":" -f1)
    rm "$tmpfile"
  '

  sudo -u "${APP_USERNAME}" bash -c '
    tmpfile=$(mktemp)
    cat > "$tmpfile" <<EOF
{
  "roles": [
    {"admin": ["Project Manager", "Product Owner", "Administrator", "DevOps Engineer"]},
    {"developer": ["UI Developer", "Backend Developer"]},
    {"qa": ["Application Tester", "Penetration Tester"]}
  ]
}
EOF
    cid=$(ipfs-cluster-ctl add -q "$tmpfile")
    if [ -z "$cid" ]; then
      echo "Error: Failed to get CID from IPFS Cluster."
      rm "$tmpfile"
      exit 1
    fi
    ipns_output=$(ipfs name publish  --key="roles" --lifetime=17520h /ipfs/"$cid")
    if [ $? -ne 0 ]; then
      echo "Error: IPNS publish failed."
      rm "$tmpfile"
      exit 2
    fi
    ipns_key=$(echo "$ipns_output" | awk '\''{print $3}'\'' | cut -d":" -f1)
    rm "$tmpfile"
  '

  sudo -u "${APP_USERNAME}" bash -c "
    tmpfile=\$(mktemp)
    jq -n --arg user \"$APP_USERNAME\" --arg key \"$PUBKEY_CONTENT\" \
      '{records: [\$key]}' > \"\$tmpfile\"
    cid=\$(ipfs-cluster-ctl add -q \"\$tmpfile\")
    if [ -z \"\$cid\" ]; then
      echo \"Error: Failed to fetch CID from the IPFS Cluster.\"
      rm \"\$tmpfile\"
      exit 1
    fi
    ipns_output=\$(ipfs name publish  --key=\"user_publickey\" --lifetime=17520h /ipfs/\"\$cid\")
    if [ \$? -ne 0 ]; then
      echo \"Error: IPNS publish failed.\"
      rm \"\$tmpfile\"
      exit 2
    fi
    ipns_key=\$(echo \"\$ipns_output\" | awk '{print \$3}' | cut -d\":\" -f1)
    rm \"\$tmpfile\"
  "

  sudo -u "${APP_USERNAME}" bash -c '
    tmpfile=$(mktemp)
    echo "{\"project_builds\": []}" > "$tmpfile"
    cid=$(ipfs-cluster-ctl add -q "$tmpfile")
    ipns_output=$(ipfs name publish  --key="project_builds" --lifetime=17520h /ipfs/"$cid")
    ipns_key=$(echo "$ipns_output" | awk "{print \$3}" | cut -d":" -f1)
    rm "$tmpfile"
  '

  sudo -u "${APP_USERNAME}" bash -c '
    tmpfile=$(mktemp)
    echo "{}" > "$tmpfile"
    cid=$(ipfs-cluster-ctl add -q "$tmpfile")
    ipns_output=$(ipfs name publish  --key="logs" --lifetime=17520h /ipfs/"$cid")
    ipns_key=$(echo "$ipns_output" | awk "{print \$3}" | cut -d":" -f1)
    rm "$tmpfile"
  '

  sudo -u "${APP_USERNAME}" bash -c '
    tmpfile=$(mktemp)
    echo "{\"misc\": []}" > "$tmpfile"
    cid=$(ipfs-cluster-ctl add -q "$tmpfile")
    ipns_output=$(ipfs name publish  --key="misc" --lifetime=17520h /ipfs/"$cid")
    ipns_key=$(echo "$ipns_output" | awk "{print \$3}" | cut -d":" -f1)
    rm "$tmpfile"
  '

  sudo -u "${APP_USERNAME}" python3 -u /home/$APP_USERNAME/app/app.py
  touch "$check_setup"
else
  echo "[INFO] Skipping setup."
  service ssh start
  sudo -u "${APP_USERNAME}" ipfs config --json Experimental.IPNSPubsub true

  sleep 3

  sudo -u "${APP_USERNAME}" ipfs daemon --enable-namesys-pubsub &
  sleep 10
  sudo -u "${APP_USERNAME}" ipfs-cluster-service daemon &
  sleep 10
  sudo -u "${APP_USERNAME}" python3 -u /home/$APP_USERNAME/app/app.py
fi

tail -f /dev/null
