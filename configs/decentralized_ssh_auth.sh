#!/bin/bash

KEYNAME="user_publickey"
MAXIMUM_WAIT=120
WAITINTERVAL=3
ELAP=0

while ! ipfs id > /dev/null 2>&1; do
    sleep $WAITINTERVAL
    ELAP=$((ELAP + WAITINTERVAL))
    if [ $ELAP -ge $MAXIMUM_WAIT ]; then
        exit 2
    fi
done

IPNS_KEY=$(ipfs key list -l | awk -v name="$KEYNAME" '$2 == name {print $1}')
if [ -z "$IPNS_KEY" ]; then
    exit 2
fi

ELAP=0

while [ $ELAP -lt $MAXIMUM_WAIT ]; do
    CID=$(ipfs name resolve --nocache -r /ipns/"$IPNS_KEY" 2>/dev/null | awk -F/ '{print $3}')
    if [ -n "$CID" ]; then
        DATA=$(ipfs cat "$CID" 2>/dev/null)
        if [ -n "$DATA" ]; then
            echo "$DATA" | jq -r '.records[]' | tr -d '\r'
            if [ $? -eq 0 ]; then
                exit 0
            else
                exit 2
            fi
        fi
    fi
    sleep $WAITINTERVAL
    ELAP=$((ELAP + WAITINTERVAL))
done

echo "Could not get the IPFS data in time thus using password authentication."
exit 2
