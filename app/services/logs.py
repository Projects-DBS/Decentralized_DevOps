import asyncio
import subprocess
import json
import tempfile
import os
import datetime
import time

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

        cmd_resolve = ['ipfs', 'name', 'resolve', '--nocache', '-r', f'{ipns_log_key}']
        resolve = subprocess.run(cmd_resolve, capture_output=True, text=True)
        mapping_cid = resolve.stdout.strip().split('/')[-1]
        if not mapping_cid:
            return False, f"Failed to resolve IPNS: {resolve.stderr.strip()}"

        cmd_cat_map = ['ipfs', 'cat', mapping_cid]
        map_res = subprocess.run(cmd_cat_map, capture_output=True, text=True)
        if map_res.returncode != 0:
            return False, f"Failed to fetch mapping CID: {map_res.stderr.strip()}"
        log_map = json.loads(map_res.stdout.strip().replace('\n', '').replace('\r',''))
      

        logs = []
        if server_ip in log_map:
            existing_cid = log_map[server_ip]
            cmd_cat_logs = ['ipfs', 'cat', existing_cid]
            logs_res = subprocess.run(cmd_cat_logs, capture_output=True, text=True)
            if logs_res.returncode == 0:
                logs = json.loads(logs_res.stdout.strip().replace('\n', '').replace('\r',''))
            logs.append(log_entry)
        else:
            logs.append(log_entry)
        
    

        

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tmp_logs:
            json.dump(logs, tmp_logs)
            tmp_logs_path = tmp_logs.name

        add_logs_cmd = ['ipfs-cluster-ctl', 'add' , tmp_logs_path, '-q']
        add_logs = subprocess.run(add_logs_cmd, capture_output=True, text=True)
        os.unlink(tmp_logs_path)
        new_log_cid = add_logs.stdout.strip()
        if not new_log_cid:
            return False, f"Failed to add logs to IPFS: {add_logs.stderr.strip()}"

        log_map[server_ip] = new_log_cid
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tmp_map:
            json.dump(log_map, tmp_map)
            tmp_map_path = tmp_map.name

        add_map_cmd = ['ipfs-cluster-ctl', 'add' , tmp_map_path, '-q']
        add_map = subprocess.run(add_map_cmd, capture_output=True, text=True)
        os.unlink(tmp_map_path)
        new_map_cid = add_map.stdout.strip()
        if not new_map_cid:
            return False, f"Failed to add log map to IPFS: {add_map.stderr.strip()}"

        cmd_publish = ['ipfs', 'name', 'publish', '--key=logs', '--lifetime=24h', f'/ipfs/{new_map_cid}']
        publish = subprocess.run(cmd_publish, capture_output=True, text=True)
        if publish.returncode != 0:
            return False, f"Failed to publish new log map to IPNS: {publish.stderr.strip()}"

        return True, "Success"
    except Exception as e:
        return False, f"Exception: {str(e)}"







def get_logs(ipns_key):
    try:
        resolve_result = subprocess.run(
            ['ipfs', 'name', 'resolve', '--nocache', '-r', f'/ipns/{ipns_key}'],
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
