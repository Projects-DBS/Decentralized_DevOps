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
        resolve_proc = subprocess.run(
            ['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_log_key],
            capture_output=True, text=True, check=False
        )
    except Exception as e:
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
                    pass
            except:
                pass
        else:
            pass
    else:
        pass

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
                    pass
            except Exception as e:
                pass


    logs_array.append(new_log_entry)

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
        pass
    new_log_cid = add_logs_proc.stdout.strip()

    server_log_info[server_ip] = new_log_cid

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
        pass
    new_server_log_info_cid = add_info_proc.stdout.strip()

    publish_proc = subprocess.run(
        ['ipfs', 'name', 'publish', f'--key=logs', '--lifetime=17520h', new_server_log_info_cid],
        capture_output=True, text=True, check=False
    )
    if publish_proc.returncode != 0:
        pass

    pass


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
