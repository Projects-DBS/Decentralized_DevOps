from datetime import datetime
import os
import subprocess
import tempfile
from flask import json
import requests

def run_cmd(cmd, input_data=None):
    try:
        # cmd should be list for secure execution
        if isinstance(cmd, str):
            cmd_list = cmd.split()
        else:
            cmd_list = cmd
        result = subprocess.run(cmd_list, capture_output=True, text=True, input=input_data)
        if result.returncode != 0:
            return False, f"Execution failed. {result}"
        return result.stdout.strip()
    except Exception as e:
        return False, str(e)

def ipns_keys():
    try:
        result = subprocess.run(['ipfs', 'key', 'list', '-l'], capture_output=True, text=True)
        parts = result.stdout.strip().split() 
        key_dict = {}
        for i in range(0, len(parts), 2):
            hash_ = parts[i]
            name = parts[i + 1]
            key_dict[name] = hash_
        return True, key_dict
    except Exception as msg:
        return False, str(msg)


def ipfs_connect():
    try:
        result = subprocess.run(
            ['ipfs', 'version'],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0 and result.stdout.strip():
            return True
        else:
            return False
    except Exception:
        return False



def remove_user_info(ipns_access_control_key, username):
    try:
        resolved = subprocess.run(
            ['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_access_control_key],
            capture_output=True, text=True
        )
        if resolved.returncode != 0:
            return False, "Failed to resolve IPNS"

        cid = resolved.stdout.strip()
        data = subprocess.run(
            ['ipfs', 'cat', cid], capture_output=True, text=True
        )
        if data.returncode != 0:
            return False, "Failed to fetch data from IPFS"

        info = json.loads(data.stdout)
        ac = info.get("access_control", [])
        found = False
        updated = []
        for entry in ac:
            if username in entry:
                found = True
                entry.pop(username)
            if entry:
                updated.append(entry)
        if not found:
            return False, "Username not found"

        info["access_control"] = updated

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            json.dump(info, tmp)
            tmp_path = tmp.name

        add = subprocess.run(
            ['ipfs', 'add', '-Q', tmp_path], capture_output=True, text=True
        )
        os.unlink(tmp_path)
        if add.returncode != 0:
            return False, "Failed to add updated data to IPFS"

        new_cid = add.stdout.strip()
        publish = subprocess.run(
            ['ipfs', 'name', 'publish', new_cid, f'--key={ipns_access_control_key}'],
            capture_output=True, text=True
        )
        if publish.returncode != 0:
            return False, "Failed to publish to IPNS"

        return True, f"User removed."
    except Exception as e:
        return False, str(e)

def remove_user_pubkey(ipns_user_pubkey_key, username):
    try:
        resolved = subprocess.run(
            ['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_user_pubkey_key],
            capture_output=True, text=True
        )
        if resolved.returncode != 0:
            return False, "Failed to resolve IPNS"

        cid = resolved.stdout.strip()
        data = subprocess.run(
            ['ipfs', 'cat', cid], capture_output=True, text=True
        )
        if data.returncode != 0:
            return False, "Failed to fetch data from IPFS"

        info = json.loads(data.stdout)
        ac = info.get("records", [])
        found = False
        updated = []
        for entry in ac:
            if username in entry:
                found = True
                entry.pop(username)
            if entry:
                updated.append(entry)
        if not found:
            return False, "Username not found"

        info["records"] = updated

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            json.dump(info, tmp)
            tmp_path = tmp.name

        add = subprocess.run(
            ['ipfs', 'add', '-Q', tmp_path], capture_output=True, text=True
        )
        os.unlink(tmp_path)
        if add.returncode != 0:
            return False, "Failed to add updated data to IPFS"

        new_cid = add.stdout.strip()
        publish = subprocess.run(
            ['ipfs', 'name', 'publish', new_cid, f'--key={ipns_user_pubkey_key}'],
            capture_output=True, text=True
        )
        if publish.returncode != 0:
            return False, "Failed to publish to IPNS"

        return True, f"User removed."
    except Exception as e:
        return False, str(e)

def list_all_users(ipns_key_access_control):
    resolve = subprocess.run(['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_key_access_control], capture_output=True, text=True)
    if resolve.returncode != 0:
        return []
    cid = resolve.stdout.strip()
    cat = subprocess.run(
        ['ipfs', 'cat', cid], capture_output=True, text=True
    )
    if cat.returncode != 0:
        return []
    try:
        info = json.loads(cat.stdout)
    except:
        return []
    return [k for entry in info.get("access_control", []) if isinstance(entry, dict) for k in entry]

def retrieve_access_control(ipns_cid, username):
    ipns_cmd = ['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_cid]
    new_ipfs_output = subprocess.run(ipns_cmd, capture_output=True, text=True)
    resolved = new_ipfs_output.stdout.strip()
    cmd1 = ['ipfs', 'cat', resolved]
    data = subprocess.run(cmd1, capture_output=True, text=True)
    final_data = data.stdout.strip()

    try:
        content_no_newlines = final_data.replace('\n', '')
        info = json.loads(content_no_newlines)
        access_control_list = info.get("access_control", [])
        for ac_entry in access_control_list:
            if username in ac_entry:
                return ac_entry[username]
        return 1
    except requests.RequestException as e:
        return 2

def update_project_record(new_cid, version, ipns_key_projects, project_name, access_infos):
    role = access_infos.get("role", "").lower()
    tag = {
        "developer": "dev",
        "qa": "qa",
        "admin": "prod"
    }.get(role, "unknown")

    cmd = ['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_key_projects]
    latest_cid_from_ipns = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    if not latest_cid_from_ipns:
        return False

    cmd = ['ipfs', 'cat', latest_cid_from_ipns]
    res = subprocess.run(cmd, capture_output=True, text=True)
    res = res.stdout.strip()

    if not res:
        return False

    try:
        fixed_res = res.replace('\n', '')
        data = json.loads(fixed_res)
        if 'projects' not in data or not isinstance(data['projects'], list):
            if isinstance(data.get('projects'), dict):
                data['projects'] = [data['projects']]
            else:
                data['projects'] = []
    except Exception as e:
        return False

    project_versions = [
        p.get('version', 1) for p in data['projects']
        if isinstance(p, dict) and p.get('project_name') == project_name
    ]
    if project_versions:
        version_to_use = max(project_versions) + 1
    else:
        version_to_use = 1

    project_info = {
        "project_name": project_name,
        "cid": new_cid,
        "version": version_to_use,
        "timestamp": datetime.now().strftime("%Y-%m-%d:%H-%M-%S"),
        "username": access_infos.get("username"),
        "role": access_infos.get("role"),
        "tag": tag
    }
    data['projects'].append(project_info)

    updated_json_str = json.dumps(data, indent=2)
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tmp_file:
        tmp_file.write(updated_json_str)
        tmp_file_path = tmp_file.name
    ipfs_add_cmd = ['ipfs-cluster-ctl', 'add', tmp_file_path, '-q']
    new_ipfs_output = subprocess.run(ipfs_add_cmd, capture_output=True, text=True)
    new_ipfs_output = new_ipfs_output.stdout.strip()
    if not new_ipfs_output:
        return False

    cmd_publish = ['ipfs', 'name', 'publish', '--key=' + ipns_key_projects, new_ipfs_output]
    publish_output = run_cmd(cmd_publish)

    if not publish_output:
        return False

    return True

def update_repo_ipnss(new_cid, version, ipns_cid, project_name, access_infos):
    ipns_key = "cicd"
    role = access_infos.get("role").lower()
    tag = {
        "developer": "dev",
        "qa": "qa",
        "admin": "prod"
    }.get(role, "unknown")

    latest_cid_from_ipns = run_cmd(['ipfs', 'name', 'resolve', '--nocache', '-r', ipns_cid])
    if not latest_cid_from_ipns or latest_cid_from_ipns[0] is False:
        return False

    latest_cid_from_ipns = latest_cid_from_ipns[0].split("/")[-1]

    project_json = run_cmd(['ipfs', 'cat', latest_cid_from_ipns])
    if not project_json or project_json[0] is False:
        return False

    try:
        data = json.loads(project_json[0])
        if 'projects' not in data:
            data['projects'] = []
    except Exception as e:
        return False

    project_versions = [
        p.get('version', 1) for p in data['projects']
        if isinstance(p, dict) and p.get('project_name') == project_name
    ]
    if project_versions:
        version_to_use = max(project_versions) + 1
    else:
        version_to_use = 1

    project_info = {
        "project_name": project_name,
        "cid": new_cid,
        "version": version_to_use,
        "timestamp": datetime.now().strftime("%Y-%m-%d:%H-%M-%S"),
        "username": access_infos.get("username"),
        "role": access_infos.get("role"),
        "tag": tag
    }
    data['projects'].append(project_info)

    updated_json_str = json.dumps(data, indent=2)
    ipfs_add_cmd = ['ipfs-cluster-ctl', 'add', '-q', '-']
    new_ipfs_output = run_cmd(ipfs_add_cmd, input_data=updated_json_str)
    if not new_ipfs_output or new_ipfs_output[0] is False:
        return False

    cmd_publish = ['ipfs', 'name', 'publish', '--key=' + ipns_key, new_ipfs_output[0]]
    publish_output = run_cmd(cmd_publish)

    if not publish_output or publish_output[0] is False:
        return False

    return True

def get_document_ipfs_cid(cid):

    try:
        result = subprocess.run(
            ['ipfs', 'cat', cid],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode != 0:
            return None

        content_no_newlines = result.stdout.replace('\n', '')
        info = json.loads(content_no_newlines)
        return info
    except Exception:
        return None


