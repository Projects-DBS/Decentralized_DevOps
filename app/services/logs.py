import subprocess
import json
import tempfile
import os
import datetime

def get_host_ip():
    try:
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, check=True)
        ips = result.stdout.strip().split()
        return ips[0] if ips else '127.0.0.1'
    except Exception:
        return '127.0.0.1'

def immutable_application_log(session, operation, page, message, ipns_log_key):
    username = session.get('username')
    session_started = session.get('start_time')
    role = session.get('role')
    server_ip = get_host_ip()
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    new_log_entry = {
        "username": username,
        "session_started": session_started,
        "server_ip": server_ip,
        "role": role,
        "operation": operation,
        "page": page,
        "message": message,
        "timestamp": timestamp
    }

    try:
        # Step 1: Resolve IPNS key to get current mapping
        resolve_ipns_cmd = f"ipfs name resolve --nocache -r {ipns_log_key}"
        resolve_ipns_result = subprocess.run(resolve_ipns_cmd, shell=True, capture_output=True, text=True)

        if resolve_ipns_result.returncode != 0 or not resolve_ipns_result.stdout.strip():
            # IPNS resolve failed or no mapping exists; start fresh
            server_log_info = {}
        else:
            # Extract CID (strip leading "/ipfs/" if present)
            latest_cid = resolve_ipns_result.stdout.strip().replace('\n','')
            if latest_cid.startswith("/ipfs/"):
                latest_cid = latest_cid[6:]
            # Fetch mapping JSON from IPFS
            cat_cmd = f"ipfs cat {latest_cid}"
            server_log_info_result = subprocess.run(cat_cmd, shell=True, capture_output=True, text=True)
            if server_log_info_result.returncode != 0 or not server_log_info_result.stdout.strip():
                server_log_info = {}
            else:
                try:
                    server_log_info = json.loads(server_log_info_result.stdout.strip())
                except Exception as e:
                    # Fallback in case JSON decode fails
                    # print(f"JSON decode error: {e}")
                    server_log_info = {}

        server_ip = str(server_ip)

        if server_ip not in server_log_info:
            # No log yet for this server; create new log list and add to IPFS
            logs_array = [new_log_entry]
        else:
            # Fetch existing logs for this server from IPFS and append
            server_log_cid = server_log_info.get(server_ip)
            open_server_logs_cmd = f"ipfs cat {server_log_cid}"
            immu_server_log = subprocess.run(open_server_logs_cmd, shell=True, capture_output=True, text=True)
            if immu_server_log.returncode != 0 or not immu_server_log.stdout.strip():
                logs_array = []
            else:
                try:
                    logs_array = json.loads(immu_server_log.stdout.strip())
                except Exception as e:
                    # print(f"JSON decode error: {e}")
                    logs_array = []
            logs_array.append(new_log_entry)

        # Write updated logs_array to temp file and add to IPFS Cluster
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmpfile:
            json.dump(logs_array, tmpfile)
            tmpfile.flush()
            tmp_logs_path = tmpfile.name
        add_logs_cmd = f"ipfs-cluster-ctl add -q {tmp_logs_path}"
        add_logs_result = subprocess.run(add_logs_cmd, shell=True, capture_output=True, text=True)
        new_log_cid = add_logs_result.stdout.strip().replace('\n','')

        # Update server_log_info with new CID for this server_ip
        server_log_info[server_ip] = new_log_cid

        # Write updated mapping to temp file and add to IPFS
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmpfile_info:
            json.dump(server_log_info, tmpfile_info)
            tmpfile_info.flush()
            tmp_info_path = tmpfile_info.name
        add_info_cmd = f"ipfs-cluster-ctl add -q {tmp_info_path}"
        add_info_result = subprocess.run(add_info_cmd, shell=True, capture_output=True, text=True)
        new_server_log_info_cid = add_info_result.stdout.strip()

        # Publish new mapping to IPNS
        publish_cmd = f"ipfs name publish --key=logs {new_server_log_info_cid}"
        subprocess.run(publish_cmd, shell=True, capture_output=True, text=True)

        # Clean up temp files
        os.unlink(tmp_logs_path)
        os.unlink(tmp_info_path)

    except Exception as e:
        # print(f"Log error: {e}")
        pass

    return json.dumps({"status": True})



def get_logs(ipns_key):
    try:
        # 1. Resolve IPNS to get mapping CID
        resolve_cmd = f"ipfs name resolve --nocache -r {ipns_key}"
        resolve_result = subprocess.run(resolve_cmd, shell=True, capture_output=True, text=True)
        mapping_cid = resolve_result.stdout.strip().split("/")[-1]

        # 2. Cat mapping CID to get {ip: log_cid}
        mapping_cmd = f"ipfs cat {mapping_cid}"
        mapping_result = subprocess.run(mapping_cmd, shell=True, capture_output=True, text=True)
        try:
            ip_to_cid = json.loads(mapping_result.stdout)
        except Exception:
            # If nothing is returned, treat as empty logs
            return {}

        # 3. For each IP, cat the log CID and collect logs
        logs = {}
        for ip, log_cid in ip_to_cid.items():
            try:
                log_cmd = f"ipfs cat {log_cid}"
                log_result = subprocess.run(log_cmd, shell=True, capture_output=True, text=True)
                log_entries = json.loads(log_result.stdout)
                # Ensure the result is always a list
                if not isinstance(log_entries, list):
                    log_entries = []
                logs[ip] = log_entries
            except Exception:
                # If anything goes wrong, still return an empty list for that IP
                logs[ip] = []

        return logs

    except subprocess.CalledProcessError as e:
        # Return empty dict if IPFS command fails (no logs)
        return {}
    except Exception as e:
        # Return empty dict for any general error (no logs)
        return {}
