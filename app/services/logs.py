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
    server_ip = str(get_host_ip())
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

    server_log_info = {}

    try:
        resolve_cmd = f"ipfs name resolve --nocache -r {ipns_log_key}"
        resolve_proc = subprocess.run(resolve_cmd, shell=True, capture_output=True, text=True)
        if resolve_proc.returncode == 0:
            latest_cid = resolve_proc.stdout.strip()
            cat_cmd = f"ipfs cat {latest_cid}"
            cat_proc = subprocess.run(cat_cmd, shell=True, capture_output=True, text=True)
            if cat_proc.returncode == 0:
                try:
                    server_log_info = json.loads(cat_proc.stdout.strip())
                except Exception as e:
                    return False
            else:
                return False
        else:
            return False

    except Exception as e:
        return False

    logs_array = []
    if server_ip in server_log_info:
        existing_cid = server_log_info[server_ip]
        cat_cmd = f"ipfs cat {existing_cid}"
        cat_proc = subprocess.run(cat_cmd, shell=True, capture_output=True, text=True)
        if cat_proc.returncode == 0:
            try:
                logs_array = json.loads(cat_proc.stdout.strip())
            except Exception as e:
                return False
        else:
            return False

    logs_array.append(new_log_entry)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmpfile:
        json.dump(logs_array, tmpfile)
        tmpfile.flush()
        tmp_logs_path = tmpfile.name

    add_logs_cmd = f"ipfs-cluster-ctl add -q {tmp_logs_path}"
    add_logs_proc = subprocess.run(add_logs_cmd, shell=True, capture_output=True, text=True)
    if add_logs_proc.returncode != 0:
        os.unlink(tmp_logs_path)
        return False
    new_log_cid = add_logs_proc.stdout.strip()
    os.unlink(tmp_logs_path)

    server_log_info[server_ip] = new_log_cid

    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmpfile_info:
        json.dump(server_log_info, tmpfile_info)
        tmpfile_info.flush()
        tmp_info_path = tmpfile_info.name

    add_info_cmd = f"ipfs-cluster-ctl add -q {tmp_info_path}"
    add_info_proc = subprocess.run(add_info_cmd, shell=True, capture_output=True, text=True)
    if add_info_proc.returncode != 0:
        os.unlink(tmp_info_path)
        return False
    new_server_log_info_cid = add_info_proc.stdout.strip()
    os.unlink(tmp_info_path)

    publish_cmd = f"ipfs name publish --key=logs {new_server_log_info_cid}"
    publish_proc = subprocess.run(publish_cmd, shell=True, capture_output=True, text=True)
    if publish_proc.returncode != 0:
        return False

    return True



def get_logs(ipns_key):
    try:
        resolve_cmd = f"ipfs name resolve --nocache -r {ipns_key}"
        resolve_result = subprocess.run(resolve_cmd, shell=True, capture_output=True, text=True)
        mapping_cid = resolve_result.stdout.strip().split("/")[-1]

        mapping_cmd = f"ipfs cat {mapping_cid}"
        mapping_result = subprocess.run(mapping_cmd, shell=True, capture_output=True, text=True)
        try:
            ip_to_cid = json.loads(mapping_result.stdout)
        except Exception:
            return {}

        logs = {}
        for ip, log_cid in ip_to_cid.items():
            try:
                log_cmd = f"ipfs cat {log_cid}"
                log_result = subprocess.run(log_cmd, shell=True, capture_output=True, text=True)
                log_entries = json.loads(log_result.stdout)
                if not isinstance(log_entries, list):
                    log_entries = []
                logs[ip] = log_entries
            except Exception:
                logs[ip] = []

        return logs

    except subprocess.CalledProcessError as e:
        return {}
    except Exception as e:
        return {}
