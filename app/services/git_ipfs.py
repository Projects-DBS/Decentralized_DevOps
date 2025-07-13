import subprocess
from flask import jsonify, request


def git_ipfs_push(project_path, custom_branch, role):
    repo_path = request.json[project_path]
    branch = request.json.get('branch', custom_branch)
    try:
        result = subprocess.run(
            ["git", "push", "ipfs::", branch],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        ) 
        output = result.stdout
        hash_line = [line for line in output.split('\n') if 'ipfs/' in line]
        ipfs_hash = hash_line[0].split('ipfs/')[-1] if hash_line else None
        return jsonify({"status": "ok", "output": output, "ipfs_hash": ipfs_hash})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "output": e.stderr})
