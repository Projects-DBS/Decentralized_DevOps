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

    # --- Step 1: Resolve IPNS key to get current server_log_info CID ---
    try:
        resolve_proc = subprocess.run(
            ['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_log_key],
            capture_output=True, text=True, check=False
        )
    except Exception as e:
        print(f"Error resolving IPNS key: {e}")
        return False

    server_log_info = {}
    if resolve_proc.returncode == 0:
        latest_cid = resolve_proc.stdout.strip()
        cat_proc = subprocess.run(
            ['ipfs', 'cat', latest_cid],
            capture_output=True, text=True, check=False
        )
        if cat_proc.returncode == 0:
            try:
                server_log_info = json.loads(cat_proc.stdout.strip())
                if not isinstance(server_log_info, dict):
                    print("Malformed server_log_info: resetting to empty dict")
                    server_log_info = {}
            except Exception as e:
                print(f"JSON decode error for server_log_info: {e}")
                server_log_info = {}
        else:
            print(f"Failed to cat CID {latest_cid}, resetting server_log_info")
            server_log_info = {}
    else:
        # IPNS name does not exist yet, start fresh
        server_log_info = {}

    # --- Step 2: Load or initialize logs array for current IP ---
    logs_array = []
    if server_ip in server_log_info:
        existing_cid = server_log_info[server_ip]
        cat_proc = subprocess.run(
            ['ipfs', 'cat', existing_cid],
            capture_output=True, text=True, check=False
        )
        if cat_proc.returncode == 0:
            try:
                logs_array = json.loads(cat_proc.stdout.strip())
                if not isinstance(logs_array, list):
                    print("Malformed logs array, resetting to empty list")
                    logs_array = []
            except Exception as e:
                print(f"JSON decode error for logs array: {e}")
                logs_array = []
        else:
            print(f"Failed to cat logs CID {existing_cid}, starting empty log array")

    # --- Step 3: Append new log entry ---
    logs_array.append(new_log_entry)

    # --- Step 4: Add updated logs_array to IPFS cluster ---
    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmpfile:
            json.dump(logs_array, tmpfile)
            tmpfile.flush()
            tmp_logs_path = tmpfile.name

        add_logs_proc = subprocess.run(
            ['ipfs-cluster-ctl', 'add', '-q', tmp_logs_path],
            capture_output=True, text=True, check=False
        )
    finally:
        if os.path.exists(tmp_logs_path):
            os.unlink(tmp_logs_path)

    if add_logs_proc.returncode != 0:
        print(f"Failed to add logs array to IPFS cluster: {add_logs_proc.stderr}")
        return False
    new_log_cid = add_logs_proc.stdout.strip()
    print(f"New logs CID for IP {server_ip}: {new_log_cid}")

    # --- Step 5: Update server_log_info with new CID for this IP ---
    server_log_info[server_ip] = new_log_cid

    # --- Step 6: Add updated server_log_info to IPFS cluster ---
    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmpfile_info:
            json.dump(server_log_info, tmpfile_info)
            tmpfile_info.flush()
            tmp_info_path = tmpfile_info.name

        add_info_proc = subprocess.run(
            ['ipfs-cluster-ctl', 'add', '-q', tmp_info_path],
            capture_output=True, text=True, check=False
        )
    finally:
        if os.path.exists(tmp_info_path):
            os.unlink(tmp_info_path)

    if add_info_proc.returncode != 0:
        print(f"Failed to add server_log_info to IPFS cluster: {add_info_proc.stderr}")
        return False
    new_server_log_info_cid = add_info_proc.stdout.strip()
    print(f"New server_log_info CID: {new_server_log_info_cid}")

    # --- Step 7: Publish the updated CID to IPNS using the correct key ---
    publish_proc = subprocess.run(
        ['ipfs', 'name', 'publish', f'--key=logs', new_server_log_info_cid],
        capture_output=True, text=True, check=False
    )
    if publish_proc.returncode != 0:
        print(f"Failed to publish to IPNS: {publish_proc.stderr}")
        return False
    print(f"Successfully published to IPNS key {ipns_log_key}: {new_server_log_info_cid}")

    return True


def get_logs(ipns_key):
    try:
        resolve_result = subprocess.run(
            ['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_key],
            capture_output=True, text=True
        )
        mapping_cid = resolve_result.stdout.strip().split("/")[-1]

        mapping_result = subprocess.run(
            ['ipfs', 'cat', mapping_cid],
            capture_output=True, text=True
        )
        try:
            ip_to_cid = json.loads(mapping_result.stdout)
        except Exception:
            return {}

        logs = {}
        for ip, log_cid in ip_to_cid.items():
            try:
                log_result = subprocess.run(
                    ['ipfs', 'cat', log_cid],
                    capture_output=True, text=True
                )
                log_entries = json.loads(log_result.stdout)
                if not isinstance(log_entries, list):
                    log_entries = []
                logs[ip] = log_entries
            except Exception:
                logs[ip] = []

        return logs

    except subprocess.CalledProcessError:
        return {}
    except Exception:
        return {}
