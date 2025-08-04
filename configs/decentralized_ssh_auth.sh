#!/bin/bash

KEYNAME="user_publickey"

IPNS_KEY=$(ipfs key list -l | awk -v name="$KEYNAME" '$2 == name {print $1}')
[ -z "$IPNS_KEY" ] && exit 1

CID=$(ipfs name resolve --nocache -r /ipns/"$IPNS_KEY" 2>/dev/null | awk -F/ '{print $3}')
[ -z "$CID" ] && exit 1

ipfs cat "$CID" | jq -r '.records[]' | tr -d '\r'
