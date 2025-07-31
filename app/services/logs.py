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
    try:
        username = session.get('username')
        session_started = session.get('start_time')
        role = session.get('role')
        server_ip = get_host_ip()
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"

        log_entry = {
            "username": username,
            "session_started": session_started,
            "server_ip": server_ip,
            "role": role,
            "operation": operation,
            "page": page,
            "message": message,
            "timestamp": timestamp
        }

        resolve = subprocess.run(
            ['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_log_key],
            capture_output=True, text=True, check=False
        )
        if resolve.returncode != 0 or not resolve.stdout.strip():
            return False, "IPNS resolve failed"

        mapping_cid = resolve.stdout.strip().split("/")[-1]
        cat = subprocess.run(
            ['ipfs', 'cat', mapping_cid],
            capture_output=True, text=True, check=False
        )
        if cat.returncode != 0 or not cat.stdout.strip():
            return False, "Failed to fetch server log info"

        try:
            log_map = json.loads(cat.stdout.strip())
            if not isinstance(log_map, dict):
                return False, "Invalid log info format"
        except Exception:
            return False, "Failed to parse log info"

        logs = []
        if server_ip in log_map:
            existing_cid = log_map[server_ip]
            cat_logs = subprocess.run(
                ['ipfs', 'cat', existing_cid],
                capture_output=True, text=True, check=False
            )
            if cat_logs.returncode != 0 or not cat_logs.stdout.strip():
                return False, "Failed to fetch existing logs"
            try:
                logs = json.loads(cat_logs.stdout.strip())
                if not isinstance(logs, list):
                    return False, "Corrupted log array"
            except Exception:
                return False, "Failed to parse existing logs"

        logs.append(log_entry)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmpfile:
            json.dump(logs, tmpfile)
            tmpfile.flush()
            tmp_logs_path = tmpfile.name
        try:
            add_logs = subprocess.run(
                ['ipfs-cluster-ctl', 'add', '-q', tmp_logs_path],
                capture_output=True, text=True, check=False
            )
            if add_logs.returncode != 0 or not add_logs.stdout.strip():
                return False, "Failed to add logs to IPFS cluster"
            new_log_cid = add_logs.stdout.strip()
        finally:
            if os.path.exists(tmp_logs_path):
                os.unlink(tmp_logs_path)

        log_map[server_ip] = new_log_cid

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmpfile_info:
            json.dump(log_map, tmpfile_info)
            tmpfile_info.flush()
            tmp_info_path = tmpfile_info.name
        try:
            add_info = subprocess.run(
                ['ipfs-cluster-ctl', 'add', '-q', tmp_info_path],
                capture_output=True, text=True, check=False
            )
            if add_info.returncode != 0 or not add_info.stdout.strip():
                return False, "Failed to add log map to IPFS cluster"
            new_map_cid = add_info.stdout.strip()
        finally:
            if os.path.exists(tmp_info_path):
                os.unlink(tmp_info_path)

        publish = subprocess.run(
            ['ipfs', 'name', 'publish', f'--key=logs', '--lifetime=17520h', new_map_cid],
            capture_output=True, text=True, check=False
        )
        if publish.returncode != 0:
            return False, f"Failed to publish new log info to IPNS: {publish.stderr}"

        resolve = subprocess.run(
            ['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_log_key],
            capture_output=True, text=True, check=False
        )
        if resolve.returncode != 0:
            return False, f"Failed to resolve the IPNS for Logs: {resolve.stderr}"


        return True, "Success"

    except Exception as e:
        return False, f"Exception: {str(e)}"

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
