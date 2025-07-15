from datetime import datetime
import os
import subprocess
import tempfile
from flask import json
import requests



def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"Execution failed. {result}"
        return result.stdout.strip()
        
    except Exception as e:
        return False, str(e)


    
def ipns_keys():
    try:
        result = subprocess.run('ipfs key list -l', shell=True, capture_output=True, text=True)
        parts = result.stdout.strip().split()  # Split by spaces
        key_dict = {}
        for i in range(0, len(parts), 2):
            hash_ = parts[i]
            name = parts[i + 1]
            key_dict[name] = hash_
        return True, key_dict
    except Exception as msg:
        return False, str(msg)

def ipfs_connect(base_url):
    try:
        # Try a quick IPFS API endpoint that should always return 200 if running
        health_check = requests.post(f"{base_url}/api/v0/version", timeout=2)
        if health_check.status_code == 200:
            return True
        else:
            raise False
    except Exception as e:
        raise False
    


######################################################################################3



def remove_user_info(ipns_access_control_key, username):
    try:
        resolved = subprocess.run(
            f"ipfs name resolve --nocache -r {ipns_access_control_key}",
            shell=True, capture_output=True, text=True
        )
        if resolved.returncode != 0:
            return False, "Failed to resolve IPNS"

        cid = resolved.stdout.strip()
        data = subprocess.run(
            f"ipfs cat {cid}", shell=True, capture_output=True, text=True
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
            f"ipfs add -Q {tmp_path}", shell=True, capture_output=True, text=True
        )
        os.unlink(tmp_path)
        if add.returncode != 0:
            return False, "Failed to add updated data to IPFS"

        new_cid = add.stdout.strip()
        publish = subprocess.run(
            f"ipfs name publish {new_cid} --key={ipns_access_control_key}",
            shell=True, capture_output=True, text=True
        )
        if publish.returncode != 0:
            return False, "Failed to publish to IPNS"

        return True, f"User removed."
    except Exception as e:
        return False, str(e)

def list_all_users(ipns_key_access_control):
    resolve = subprocess.run(f"ipfs name resolve --nocache -r {ipns_key_access_control}", shell=True, capture_output=True, text=True)
    if resolve.returncode != 0:
        return []
    cid = resolve.stdout.strip()
    cat = subprocess.run(
        f"ipfs cat {cid}", shell=True, capture_output=True, text=True
    )
    if cat.returncode != 0:
        return []
    try:
        info = json.loads(cat.stdout)
    except:
        return []
    return [k for entry in info.get("access_control", []) if isinstance(entry, dict) for k in entry]



def retrieve_access_control(ipns_cid, username):
    # url = f"{base_url}/api/v0/cat?arg=/ipns/{ipns_cid}"

    ipns_cmd = f"ipfs name resolve --nocache -r {ipns_cid}"
    new_ipfs_output = subprocess.run(ipns_cmd, shell=True, capture_output=True, text=True)
    resolved = new_ipfs_output.stdout.strip()
    resolved = resolved.replace('\n', '')
    cmd1 = f"ipfs cat {resolved}"
    data = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
    final_data = data.stdout.strip()

    try:
        # resp = requests.post(url, timeout=20)
        # resp.raise_for_status()
        # content = resp.content.decode('utf-8')
        # Remove all newlines to make JSON valid
        content_no_newlines = final_data.replace('\n', '')
        info = json.loads(content_no_newlines)
        access_control_list = info.get("access_control", [])
        for ac_entry in access_control_list:
            if username in ac_entry:
                print(f"--> {username}")
                print(f"--> {ac_entry[username]}")
                return ac_entry[username]
        
        return 1
    
    
    except requests.RequestException as e:
        print(f"Error retrieving CID: {e}")
        return 2
    

def update_project_record(new_cid, version, ipns_key_projects, project_name, access_infos):
    print("Method started.")
    ipns_key = "access_control"
    role = access_infos.get("role", "").lower()
    tag = {
        "developer": "dev",
        "qa": "qa",
        "admin": "prod"
    }.get(role, "unknown")

    print(f"tag printed: {tag}")

    # Step 1: Resolve current IPNS to get the latest CID
    cmd = f"ipfs name resolve --nocache -r {ipns_key_projects}"
    
    latest_cid_from_ipns = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
    if not latest_cid_from_ipns:
        print("Failed to resolve IPNS key.")
        return False



    # Step 2: Fetch the current project metadata




    cmd = f"ipfs cat {latest_cid_from_ipns}"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    res = res.stdout.strip()


    if not res:
        print("Failed to fetch project metadata from IPFS.")
        return False

    try:
        fixed_res = res.replace('\n', '')
        data = json.loads(fixed_res)



        print(f"Existing record 1: {data}")
        # Always ensure 'projects' is a list
        if 'projects' not in data or not isinstance(data['projects'], list):
            if isinstance(data.get('projects'), dict):
                data['projects'] = [data['projects']]
            else:
                data['projects'] = []
    except Exception as e:
        print(f"JSON parsing error: {e}")
        return False
    print(f"Existing record 2: {data}")
    # Step 3: Determine new version number
    project_versions = [
    p.get('version', 1) for p in data['projects']
        if isinstance(p, dict) and p.get('project_name') == project_name
    ]
    if project_versions:
        version_to_use = max(project_versions) + 1
    else:
        version_to_use = 1

    # Step 4: Add new project info
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

    print(f'data printed {data}')

    updated_json_str = json.dumps(data, indent=2)
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tmp_file:
        tmp_file.write(updated_json_str)
        tmp_file_path = tmp_file.name
    # Step 5: Add the updated JSON to IPFS via cluster
    ipfs_add_cmd = f"ipfs-cluster-ctl add {tmp_file_path} -q"
    new_ipfs_output = subprocess.run(ipfs_add_cmd, shell=True, capture_output=True, text=True)
    new_ipfs_output = new_ipfs_output.stdout.strip()
    if not new_ipfs_output:
        print("Failed to add updated JSON to IPFS cluster.")
        return False

    print("IPFS add output:", new_ipfs_output)
    cmd_publish = f"ipfs name publish --key={ipns_key_projects} {new_ipfs_output}"
    publish_output = run_cmd(cmd_publish)

    if not publish_output:
        print("Failed to publish new CID to IPNS.")
        return False

    print("Successfully published new metadata CID to IPNS.")
    return True


def update_repo_ipnss(new_cid, version, ipns_cid, project_name, access_infos):
    print("Method started.")
    ipns_key = "cicd"
    role = access_infos.get("role").lower()
    tag = {
        "developer": "dev",
        "qa": "qa",
        "admin": "prod"
    }.get(role, "unknown")

    print(f"tag printed: {tag}")
    
    # Step 1: Resolve current IPNS to get the latest CID
    latest_cid_from_ipns = run_cmd(f"ipfs name resolve --nocache -r {ipns_cid}")
    if not latest_cid_from_ipns:
        print("Failed to resolve IPNS key.")
        return False

    latest_cid_from_ipns = latest_cid_from_ipns.split("/")[-1]

    print(f"got latest cid from ipns: {latest_cid_from_ipns}")
    
    # Step 2: Fetch the current project metadata
    project_json = run_cmd(f"ipfs cat {latest_cid_from_ipns}")

    print(f"Existing recoed: {project_json}")

    if not project_json:
        print("Failed to fetch project metadata from IPFS.")
        return False

    try:
        data = json.loads(project_json)
        if 'projects' not in data:
            data['projects'] = []
    except Exception as e:
        print(f"JSON parsing error: {e}")
        return False

    # Step 3: Determine new version number
    project_versions = [
    p.get('version', 1) for p in data['projects']
    if isinstance(p, dict) and p.get('project_name') == project_name
    ]
    if project_versions:
        version_to_use = max(project_versions) + 1
    else:
        version_to_use = 1

    # Step 4: Add new project info
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

    print(f'data printed {data}')

    updated_json_str = json.dumps(data, indent=2)

    # Step 5: Add the updated JSON to IPFS via cluster
    ipfs_add_cmd = ["ipfs-cluster-ctl", "add", "-"]
    new_ipfs_output = run_cmd(ipfs_add_cmd, input_data=updated_json_str)
    if not new_ipfs_output:
        print("Failed to add updated JSON to IPFS cluster.")
        return False
    
    print("IPFS add output:", new_ipfs_output)
    cmd_publish = f"ipfs name publish --key={ipns_key} {new_ipfs_output}"
    publish_output = run_cmd(cmd_publish)

    if not publish_output:
        print("Failed to publish new CID to IPNS.")
        return False

    print("Successfully published new metadata CID to IPNS.")
    return True




def get_document_ipfs_cid(cid, url):
    url = f"{url}/api/v0/cat?arg={cid}"
    try:
        resp = requests.post(url, timeout=15)
        resp.raise_for_status()
        data = resp.content.decode('utf-8')
        content_no_newlines = data.replace('\n', '')
        info = json.loads(content_no_newlines)
        return info
    except Exception as e:
        print("Error fetching from IPFS:", e)
        return None


def ipns_get_project(ipns_key_project, proj_cid, tag):
    tmp_build_path = '/tmp/build/'
    cmd = f"ipfs get {proj_cid} -o {tmp_build_path}"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        return "Unable to fetch the project!"
    if not os.path.isfile(f"{tmp_build_path}Dockerfile"):
        return "Dockerfile not found in the project."
    cmd1 = f"docker build -t app /tmp/build/ ."

    
    


