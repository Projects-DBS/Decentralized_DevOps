from datetime import datetime, timedelta, timezone
import os
import re
import shutil
import socket
import subprocess
import tempfile
from time import sleep
import zipfile
from flask import Flask, json, jsonify, render_template, request, redirect, send_file, url_for, flash, session
from services.ipfs import ipfs_connect, remove_user_info, retrieve_access_control, get_document_ipfs_cid, update_project_record, ipns_keys, list_all_users
from services.crypto import decrypt_openssl
from services.session import check_session
from werkzeug.utils import secure_filename


ports = {
    "dev": 1001,
    "qa": 1002,
    "prod": 1003
}



status, keys = ipns_keys()
if status != True:
    print(keys)
    exit()
ipns_key_access_control = keys.get("access_control")
ipns_key_projects = keys.get("projects")
ipns_key_project_builds = keys.get("project_builds")
ipns_key_misc = keys.get("misc")
ipns_key_logs = keys.get("logs")
ipns_key_roles = keys.get("roles")



app = Flask(__name__)
app.secret_key = "change_this_secret"  # Change  this for production
app.permanent_session_lifetime = timedelta(minutes=10)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit


TEMP_DIR = '/tmp'
IPFS_URL = "http://127.0.0.1:5001"

# def check_session(page):
#     try:
#         username = session.get("username")
#         role = session.get("role")
#         expiry = session.get("expiry")
#         page_access = session.get("page_access", [])

#         if not username or not role or not expiry:
#             return "Unauthorized access!"

#         if datetime.now(timezone.utc).timestamp() > expiry:
#             session.clear()
#             return "Session expired. Please log in again."

#         if role not in ["admin", "developer", "qa"]:
#             session.clear()
#             return "Unauthorized access."

#         if page not in page_access:
#             return "Unauthorized page access."

#         return True

#     except Exception:
#         return "Unknown error occurred!"

@app.route('/list_all_users', methods = ['GET'])
def list_all_users_info():
    status = check_session( session,"user_list")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    try:
        users = list_all_users(ipns_key_access_control)
        return jsonify([{"username": u} for u in users])
    except:
        return jsonify ({"status":False, "message": "Error retriving the user list."})


@app.route("/trigger-ci", methods=['GET','POST'])
def trigger_ci_post():
    status = check_session( session,"ci")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("ci.html")


@app.route("/remove-user", methods=['GET'])
def remove_user_page_load():
    status = check_session( session,"remove_user")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("remove_user.html")
    
@app.route("/remove-user", methods=['POST'])
def remove_user():
    try:
        status = check_session( session,"remove_user")
        if status != True:
            flash(status)
            return redirect(url_for("login"))
        data = request.get_json()
        if not data.get('username'):
            return False, "Username is missing", 400
        username = data.get('username')
        if username == "admin" or username == "Admin":
            return jsonify({"success": False, "message": "You cannot remove admin from the Access."})
        success, message = remove_user_info(ipns_key_access_control, username)
        return jsonify({"success": success, "message": message})
    except:
        success = False
        message = "Unable to remove the user from the Access Control list."
        return jsonify({"success": success, "message": message})
        



@app.route("/ci-cd-operations", methods=['GET'])
def cicd_page():
    status = check_session( session,"cicdpage")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("cicd_operations.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")



        if not (3 <= len(username) <= 32) or not username.replace('_', '').isalnum():
            flash("Invalid username. Use 3-32 characters: letters, numbers, and underscores only.")
            return redirect(url_for("login"))

        if not (6 <= len(password) <= 32):
            flash("Invalid password length. Must be 6-32 characters.")
            return redirect(url_for('login'))

        ipfs_conn_status = ipfs_connect(IPFS_URL)

        if ipfs_conn_status == True:
            try:
                user_access = retrieve_access_control(ipns_key_access_control, username)
                if user_access == 1:
                    flash("User not exists!")
                    return redirect(url_for("login"))
                elif user_access == 2:
                    flash("Error to fetch IPFS Data.")
                    return redirect(url_for("login"))
                access_control_cid = decrypt_openssl(user_access, password).decode()
                access_info = get_document_ipfs_cid(access_control_cid, IPFS_URL)

                session.permanent = True
                session["username"] = access_info.get("username")
                session["role"] = access_info.get("role")
                expiry_time = datetime.now(timezone.utc) + timedelta(minutes=10)
                session['expiry'] = expiry_time.timestamp()
                session["page_access"] = access_info.get("pages", [])
                session["access_info"] = access_info
                session["organization"] = access_info.get("organization", []) # <--- Store access_info in session

                if access_info.get("role") == "admin":
                    return redirect(url_for('admin_dashboard'))
                elif access_info.get("role") == "developer":
                    return redirect(url_for('developer_dashboard'))
                elif access_info.get("role") == "qa":
                    return redirect(url_for('qa_dashboard'))

                flash("Role not recognized.")
                return redirect(url_for("login"))

            except Exception as e:
                flash(f"Login failed: Invalid Credentials")
                return redirect(url_for("login"))

        else:
            flash("Connection to IPFS API node failed!")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/organizations", methods=["GET"])
def list_org():
    try:
        status = check_session(session,"user_management")
        if status != True:
            flash(status)
            return redirect(url_for("login"))
        orgs = session.get("organization", [])
        return jsonify(orgs)

    except:
        return jsonify({"message":"Unable to retrieve roles from IPFS Cluster."})



@app.route("/roles", methods=["GET"])
def list_roles():
    try:
        status = check_session(session,"user_management")
        if status != True:
            flash(status)
            return redirect(url_for("login"))
        print(ipns_key_roles)
        cmds = f"ipfs name resolve --nocache -r {ipns_key_roles}"
        result = subprocess.run(cmds, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return jsonify({"message":"Unable to retrieve roles from the IPNS Records."})
        role_cid = result.stdout.strip().replace('\n','')

        print(role_cid)
        
        cmd1 = f"ipfs cat {role_cid}"
        result = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return jsonify({"message":"Unable to retrieve roles from the IPFS Cluster."})
        role_info = result.stdout.strip().replace('\n','')
        roles = json.loads(role_info)
        print(roles)
        return roles["roles"]
    except Exception as e:
        return jsonify({"message":"Unable to retrieve roles from IPFS Cluster."})

@app.route("/admin-dashboard", methods=["GET","POST"])
def admin_dashboard():
    status = check_session( session,"admin_dashboard")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html", username=session.get("username"))

@app.route("/developer-dashboard", methods=["GET", "POST"])
def developer_dashboard():
    status = check_session( session,"developer_dashboard")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("developer_dashboard.html", username=session.get("username"))

@app.route("/qa-dashboard", methods=["GET", "POST"])
def qa_dashboard():
    status = check_session( session,"qa_dashboard")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("qa_dashboard.html", username=session.get("username"))

@app.route("/ipfs-repo-operation", methods=["GET", "POST"])
def push_pull():
    status = check_session( session,"ipfs-repo-operation")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("ipfs-repo-operation.html")

@app.route('/pushto_ipfs', methods=['GET'])
def push_to_ipfs():
    status = check_session( session,"pushto_ipfs")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("pushto_ipfs.html")

@app.route('/pullfrom_ipfs', methods=['GET','POST'])
def pull_from_ipfs():
    status = check_session( session,"pullfrom_ipfs")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("pullfrom_ipfs.html")

@app.route('/get_projects', methods=['POST'])
def get_projects():
    status = check_session( session,"pullfrom_ipfs")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    try:
        cmd = f"ipfs name resolve --nocache -r {ipns_key_projects}"
        new_ipfs_output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        resolved = new_ipfs_output.stdout.strip()

        cmd1 = f"ipfs cat {resolved}"
        data = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
        final_data = data.stdout.strip()
        json_data = json.loads(final_data)
        return jsonify(json_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/artifact_build_info', methods=['GET'])
def build_info():
    status = check_session( session,"build")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    cmd = f"ipfs name resolve --nocache -r {ipns_key_project_builds}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    result = result.stdout.strip().replace('\n','')

    cmd1 = f"ipfs cat {result}"
    result1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
    result1 = result1.stdout.strip().replace('\n','')
    json_result = json.loads(result1)
    return jsonify(json_result), 200

# @app.route('/decommission', methods=['GET'])
# def decommission_page():
#     status = check_session(session, "decommission")
#     if status != True:
#         return jsonify({"status": "error", "message": str(status)}), 401
#     return render_template('decommission.html')

# @app.route('/decommission', methods=['POST'])
# def decommission():
#     status = check_session(session, "decommission")
#     if status != True:
#         return jsonify({"status": "error", "message": str(status)}), 401

#     try:
#         data = request.get_json()
#         server_list = data.get('server_list', [])
#         deployment_server_password = data.get('deployment_server_password')
#         tag = data.get('tag')
#         port = ports.get(tag)

#         if not all([server_list, deployment_server_password, tag, port]):
#             return jsonify({"status": "error", "message": "Missing required parameters"}), 400

#         for server in server_list:
#             # Stop the Gunicorn process
#             command = (
#                 f'pid=$(lsof -t -i:{port}) && '
#                 f'if [ -n "$pid" ]; then kill -9 $pid; fi'
#             )
#             cmd = f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} "{command}"'
#             data = subprocess.run(cmd, shell=True, capture_output=True, text=True)
#             if data.returncode != 0:
#                 return jsonify({"status": "error", "message": f"Failed to stop application on server {server}: {data.stderr.strip()}"}), 500

#             # Remove the application directory
#             command = f'rm -rf /home/guest/www/{tag}'
#             cmd = f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} "{command}"'
#             data = subprocess.run(cmd, shell=True, capture_output=True, text=True)
#             if data.returncode != 0:
#                 return jsonify({"status": "error", "message": f"Failed to remove application directory on server {server}: {data.stderr.strip()}"}), 500

#         return jsonify({"status": "success", "message": "Decommissioning completed successfully!"})

#     except Exception as e:
#         return jsonify({"status": "error", "message": f"Decommissioning failed: {str(e)}"}), 500

@app.route('/decommission', methods=['POST'])
def decommission():
    status = check_session(session, "decommission")
    if status != True:
        return jsonify({"status": "error", "message": str(status)}), 401

    try:
        data = request.get_json()
        server_list = data.get('server_list', [])
        deployment_server_password = data.get('deployment_server_password')
        tag = data.get('tag')

        port = ports.get(tag)  # Assuming your 'ports' dict exists

        if not all([server_list, deployment_server_password, tag, port]):
            return jsonify({"status": "error", "message": "Missing required parameters"}), 400

        failed_servers = []
        success_servers = []

        for server in server_list:
            try:
                # Correctly quoted pkill for only the right gunicorn
                stop_cmd = f'fuser -k {port}/tcp || true'
                cmd = (
                    f'sshpass -p "{deployment_server_password}" ssh -o StrictHostKeyChecking=no '
                    f'guest@{server} "{stop_cmd}"'
                )
                stop_data = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                
                # Optionally clean up the deployment directory
                project_dir = f"/home/guest/www/{tag}"
                cleanup_cmd = f'rm -rf {project_dir}'
                cleanup_full_cmd = (
                    f'sshpass -p "{deployment_server_password}" ssh -o StrictHostKeyChecking=no '
                    f'guest@{server} "{cleanup_cmd}"'
                )
                cleanup_data = subprocess.run(cleanup_full_cmd, shell=True, capture_output=True, text=True, timeout=30)

                # Check if both commands were successful
                if cleanup_data.returncode == 0 and stop_data.returncode == 0:
                    success_servers.append(server)
                else:
                    failed_servers.append({
                        "server": server,
                        "stop_returncode": stop_data.returncode,
                        "stop_stdout": stop_data.stdout.strip(),
                        "stop_stderr": stop_data.stderr.strip(),
                        "cleanup_returncode": cleanup_data.returncode,
                        "cleanup_stderr": cleanup_data.stderr.strip()
                    })

            except Exception as ex:
                failed_servers.append({"server": server, "exception": str(ex)})
                continue

        if len(success_servers) == len(server_list):
            return jsonify({"status": "success", "message": "Decommission done!"})
        elif len(success_servers) == 0:
            return jsonify({
                "status": "error",
                "message": "Decommission failed on all servers.",
                "failed_servers": failed_servers
            })
        else:
            return jsonify({
                "status": "partial_failure",
                "failed_servers": failed_servers,
                "count": len(failed_servers),
                "message": "Some decommissions failed. Try again."
            })

    except Exception as e:
        return jsonify({"status": "error", "message": f"Decommission failed: {str(e)}"}), 500



# @app.route('/decommission', methods=['POST'])
# def decommission():
#     status = check_session(session, "decommission")
#     if status != True:
#         return jsonify({"status": "error", "message": str(status)}), 401

#     try:
#         data = request.get_json()
#         server_list = data.get('server_list', [])
#         deployment_server_password = data.get('deployment_server_password')
#         tag = data.get('tag')
#         port = ports.get(tag)

#         if not all([server_list, deployment_server_password, tag, port]):
#             return jsonify({"status": "error", "message": "Missing required parameters"}), 400

#         for server in server_list:
#             # Stop the running application
#             command_stop = (
#                 f'pkill -f "gunicorn.*:{port}" && '
#                 f'rm -rf /home/guest/www/{tag}'
#             )
#             cmd_stop = f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} "{command_stop}"'
#             data_stop = subprocess.run(cmd_stop, shell=True, capture_output=True, text=True)
#             if data_stop.returncode != 0:
#                 return jsonify({"status": "error", "message": f"Failed to decommission server {server}: {data_stop.stderr.strip()}"}), 500

#         return jsonify({"status": "success", "message": "Decommission completed successfully!"})

#     except Exception as e:
#         return jsonify({"status": "error", "message": f"Decommission failed: {str(e)}"}), 500



@app.route('/deploy', methods=['POST'])
def deploy():
    status = check_session(session, "deploy")
    if status != True:
        return jsonify({"status": "error", "message": str(status)}), 401

    try:
        data = request.get_json()
        server_list = data.get('server_list', [])
        build_cid = data.get('build_cid')
        artifact_password = data.get('artifact_password')
        deployment_server_password = data.get('deployment_server_password') 
        tag = data.get('tag')
        port = ports.get(tag)

        if not all([server_list, build_cid, artifact_password, deployment_server_password, tag, port]):
            return jsonify({"status": "error", "message": "Missing required parameters"}), 400

        failed_servers = []
        success_servers = []

        for server in server_list:
            try:
                # 1. Download via IPFS
                cmd = (
                    f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} '
                    f'"mkdir -p /home/guest/www/{tag}/{build_cid}/webapp/ && '
                    f'ipfs get {build_cid} -o /home/guest/www/{tag}/{build_cid}/webapp/"'
                )
                data = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                if data.returncode != 0:
                    failed_servers.append({"server": server, "step": 1, "stderr": data.stderr.strip()})
                    continue

                # 2. Decrypt artifact
                cmd1 = (
                    f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} '
                    f'"openssl enc -d -aes-256-cbc -pbkdf2 '
                    f'-in /home/guest/www/{tag}/{build_cid}/webapp/{build_cid} '
                    f'-out /home/guest/www/{tag}/{build_cid}/webapp/{build_cid}.zip '
                    f'-pass pass:{artifact_password}"'
                )
                data1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True, timeout=60)
                if data1.returncode != 0:
                    if "bad decrypt" in data1.stderr or "bad password" in data1.stderr:
                        return jsonify({"status": "failed", "message": "Incorrect password for the artifact!"})
                    failed_servers.append({"server": server, "step": 2, "stderr": data1.stderr.strip()})
                    continue

                # 3. Unzip, start gunicorn, check port
                project_dir = f"/home/guest/www/{tag}/{build_cid}/webapp"
                zip_file = f"{project_dir}/{build_cid}.zip"
                run_command = (
                    f'unzip -o "{zip_file}" -d "{project_dir}" || (echo "Unzip failed"; exit 1); '
                    f'cd "{project_dir}" || exit 1; '
                    f'if [ ! -f app.py ]; then echo "app.py not found"; exit 1; fi; '
                    f'nohup gunicorn app:app --bind 0.0.0.0:{port} > app.log 2>&1 & '
                    f'sleep 3; '
                    f'(ss -ltn | grep ":{port} " || netstat -ltn 2>/dev/null | grep ":{port} ") && echo "__DEPLOY_SUCCESS__"'
                )
                cmd2 = (
                    f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} "{run_command}"'
                )
                data2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True, timeout=90)

                if "__DEPLOY_SUCCESS__" in data2.stdout:
                    success_servers.append(server)
                else:
                    # Get last 50 lines of app.log for diagnostics
                    log_cmd = (
                        f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} '
                        f'"tail -n 50 {project_dir}/app.log 2>/dev/null"'
                    )
                    log_data = subprocess.run(log_cmd, shell=True, capture_output=True, text=True, timeout=10)
                    failed_servers.append({
                        "server": server,
                        "step": 3,
                        "stderr": data2.stderr.strip(),
                        "app_log": log_data.stdout.strip() or "(no app.log found)"
                    })

            except subprocess.TimeoutExpired:
                failed_servers.append({"server": server, "step": "timeout"})
                continue
            except Exception as ex:
                failed_servers.append({"server": server, "step": "exception", "exception": str(ex)})
                continue

        if len(success_servers) == len(server_list):
            return jsonify({"status": "success", "message": "Deployment done!"})
        elif len(success_servers) == 0:
            return jsonify({
                "status": "error",
                "message": "Deployment failed on all servers.",
                "failed_servers": failed_servers
            })
        else:
            return jsonify({
                "status": "partial_failure",
                "failed_servers": failed_servers,
                "count": len(failed_servers),
                "message": "Some deployments failed. Try to deploy again."
            })

    except Exception as e:
        return jsonify({"status": "error", "message": f"Deployment failed: {str(e)}"}), 500



# @app.route('/deploy', methods=['POST'])
# def deploy():
#     status = check_session(session, "deploy")
#     if status != True:
#         return jsonify({"status": "error", "message": str(status)}), 401

#     try:
#         data = request.get_json()
#         server_list = data.get('server_list', [])
#         build_cid = data.get('build_cid')
#         artifact_password = data.get('artifact_password')
#         deployment_server_password = data.get('deployment_server_password') 
#         tag = data.get('tag')
#         port = ports.get(tag)

#         if not all([server_list, build_cid, artifact_password, deployment_server_password, tag, port]):
#             return jsonify({"status": "error", "message": "Missing required parameters"}), 400

#         for server in server_list:
#             command = f'mkdir -p /home/guest/www/{tag}/{build_cid}/webapp/ && ipfs get {build_cid} -o /home/guest/www/{tag}/{build_cid}/webapp/'
#             cmd = f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} "{command}"'
#             data = subprocess.run(cmd, shell=True, capture_output=True, text=True)
#             if data.returncode != 0:
#                 return jsonify({"status": "error", "message": f"Failed to fetch artifact for server {server}: {data.stderr.strip()}"}), 500

#             command1 = f'openssl enc -d -aes-256-cbc -pbkdf2 -in /home/guest/www/{tag}/{build_cid}/webapp/{build_cid} -out /home/guest/www/{tag}/{build_cid}/webapp/{build_cid}.zip -pass pass:{artifact_password}'
#             cmd1 = f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} "{command1}"'
#             data1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
#             if data1.returncode != 0:
#                 return jsonify({"status": "error", "message": f"Failed to decrypt artifact for server {server}: {data1.stderr.strip()}"}), 500

#             zip_file = f'/home/guest/www/{tag}/{build_cid}/webapp/{build_cid}.zip'
#             root_install = f"/home/guest/www/{tag}/{build_cid}/webapp"
#             command2 = (
#                 f'unzip -o "{zip_file}" -d "{root_install}" && '
#                 f'cd "{root_install}" && '
#                 f'found=$(find . -type f -name app.py | head -n 1) && '
#                 f'dir=$(dirname "$found") && '
#                 f'nohup gunicorn app:app --bind 0.0.0.0:{port} > app.log 2>&1 & '
#                 f'echo "Application deployed on {server} on port {port}"'
#             )
#             cmd2 = f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} "{command2}"'
#             data2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)
#             sleep(5)
#             if data2.returncode != 0:
#                 print(f"Deployment failed on server {server}: {data2.stderr.strip()}")

#         return jsonify({"status": "success", "message": "Deployment done!"})

#     except Exception as e:
#         return jsonify({"status": "error", "message": f"Deployment failed: {str(e)}"}), 500


# @app.route('/deploy', methods=['POST'])
# def deploy():
#     status = check_session( session,"deploy")
#     if status != True:
#         flash(status)
#         return redirect(url_for("login"))
#     try:
        
#         data = request.get_json()
#         server_list = data.get('server_list',[])
#         build_cid = data.get('build_cid')
#         artifact_password = data.get('artifact_password')
#         deployment_server_password = data.get('deployment_server_password') 
#         tag = data.get('tag')
#         port = ports.get(tag)
#         print("Part 1")
#         print(f"{data}")

#         for server in server_list:
#             print("Part 2")
#             print(f"{server}")
#             command = f'mkdir /home/guest/www/{tag}/{build_cid}/webapp/ && ipfs get {build_cid} -o /home/guest/www/{tag}/{build_cid}/webapp/'
#             cmd = f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} {command}'
#             data = subprocess.run(cmd, shell=True, capture_output=True, text=True)
#             print(data.stdout.strip().replace('\n',''))
#             if data.returncode == 0:
#                 print("Part 3")
#                 command1 = f'openssl enc -d -aes-256-cbc -pbkdf2 -in {build_cid} -out /home/guest/www/{tag}/{build_cid}/webapp/{build_cid}.zip -pass pass:{artifact_password}'
#                 cmd1 = f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} {command1}'
#                 data1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
#                 print("PArt 4")
#                 print(data1.stdout.strip().replace('\n',''))
#                 if data1.returncode == 0:
#                     zip_file = f'/home/guest/www/{tag}/{build_cid}/webapp/{build_cid}.zip'
#                     root_install = f"/home/guest/www/{tag}/{build_cid}/webapp"
#                     command2 = ( 
#                         f'unzip -o "{zip_file}" -d "{root_install}" && '
#                         f'cd "{root_install}" && '
#                         f'found=$(find . -type f -name app.py | head -n 1) &&'
#                         f'dir=$(dirname "$found") && '
#                         f'nohup gunicorn app:app --bind 0.0.0.0:{port} > app.log 2>&1 & '
#                         f'echo "Application deployed on {server} on port {port}"'
#                     )
#                     cmd2 = f'sshpass -p {deployment_server_password} ssh -o StrictHostKeyChecking=no guest@{server} "{command2}"'
#                     data2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)
#                     if data2.returncode != 0:
#                         raise("Deployment failed.")

#         flash("Deployment done!")
#         return render_template('deploy.html')

#     except Exception as e:
#         print(f"str({e})")
#         flash(f"Deployment Failed!. Message: {str(e)}")
#         return render_template('deploy.html')



@app.route('/check-port-availability', methods=['POST'])
def check_port():
    status = check_session( session,"build")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    results = {}
    data = request.get_json()
    port = ports[data.get('tag')]
    ips = data.get('ips',[])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('localhost', port))

    for ip in ips:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        
        if result != 0:
            results[ip] = "Available"
        else:
            results[ip] = "Not Available"

    sock.close()
    return jsonify(results), 200


    
     

@app.route('/list-active-server', methods=['GET'])
def available_servers():
    status = check_session( session,"list_all_servers")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    try:
        # cmd = 'ipfs swarm peers'
        # data = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        # ip_list = re.findall(r'/ip[46]/([^\s/]+)/', data.stdout)
        # unique_ips = set(ip_list)  # remove duplicates here

        cmd = 'ipfs-cluster-ctl peers ls'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        ip_list = re.findall(r'/ip4/([0-9.]+)', result.stdout)
        unique_ips = sorted(set(ip for ip in ip_list if not ip.startswith('127.')))


        servers = []
        for ip in unique_ips:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = None
            display_name = f"{hostname or 'unknown'} ({ip})" if hostname else ip
            servers.append({"id": ip, "name": display_name})
        return {"servers": servers}
    except Exception as e:
        return {"servers": [], "error": str(e)}, 500



@app.route('/download_project', methods=['POST'])
def download_project():
    status = check_session(session, "pullfrom_ipfs")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    try:
        data = request.get_json()
        cid = data['cid']
        project_name = data['project_name']

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "output")
            # Download from IPFS; will create a file or folder
            subprocess.run(['ipfs', 'get', cid, '-o', out_path], check=True)

            # Check if it's a file or folder
            if os.path.isdir(out_path):
                # Zip the directory
                zip_path = os.path.join(tmpdir, f"{project_name}.zip")
                shutil.make_archive(zip_path[:-4], 'zip', out_path)
                return send_file(
                    zip_path,
                    as_attachment=True,
                    download_name=f"{project_name}.zip"
                )
            elif os.path.isfile(out_path):
                # If the file is already a zip, just send
                return send_file(
                    out_path,
                    as_attachment=True,
                    download_name=f"{project_name}.zip"
                )
            else:
                raise Exception("Downloaded content not found or unrecognized.")

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# @app.route('/download_project', methods=['POST'])
# def download_project():
#     status = check_session( session,"pullfrom_ipfs")
#     if status != True:
#         flash(status)
#         return redirect(url_for("login"))
#     try:
#         data = request.get_json()
#         cid = data['cid']
#         project_name = data['project_name']

#         with tempfile.TemporaryDirectory() as tmpdir:
#             # Download ZIP file from IPFS directly
#             zip_path = os.path.join(tmpdir, f"{project_name}.zip")
#             cmd = f"ipfs get {cid} -o {zip_path}"
#             out = os.system(cmd)
#             if out != 0 or not os.path.exists(zip_path):
#                 raise Exception("Failed to download ZIP from IPFS")
#             # Send the zip file as a download
#             return send_file(zip_path, as_attachment=True, download_name=f"{project_name}.zip")



#     except Exception as e:
#         return jsonify({'error': str(e)}), 500


@app.route('/project_info', methods=['POST'])
def get_all_projects():
    status = check_session( session,"ci")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    try:
        cmd = f"ipfs name resolve --nocache -r {ipns_key_projects}"
        new_ipfs_output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        resolved = new_ipfs_output.stdout.strip()

        cmd1 = f"ipfs cat {resolved}"
        data = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
        final_data = data.stdout.strip()
        json_data = json.loads(final_data)
        return jsonify(json_data.get('projects', []))
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/trigger-build-ci', methods=['POST'])
def trigger_ci_build():
    status = check_session(session, "ci")
    if status != True:
        flash(status)
        return redirect(url_for("login"))

    data = request.get_json()
    cid = data.get('cid')
    tag = data.get('tag')
    zip_password = data.get("zip_password")
    project_name = data.get("project_name")

    # Step 1: Download from IPFS
    cmd = f"cd /tmp/ && ipfs get {cid}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        return jsonify({"success": False, "message": "Unable to retrieve the requested project from CID for build."})

    # Step 2: Find .py file and zip
    zipped = False
    for root, dirs, files in os.walk(f'/tmp/{cid}'):
        for file in files:
            if file.lower().endswith(".py"):
                subprocess.run(['zip', '-r', f'{cid}.zip', '.'], cwd=root)
                zipped = True
                break
        if zipped:
            break
    if not zipped:
        return jsonify({"success": False, "message": "No .py file found in project, nothing to zip."})

    zip_path = os.path.join(root, f"{cid}.zip")
    enc_path = os.path.join(root, f"{cid}.zip.enc")

    # Step 3: Encrypt the zip
    enc = f'openssl enc -aes-256-cbc -pbkdf2 -salt -in "{zip_path}" -out "{enc_path}" -pass pass:{zip_password}'
    result = subprocess.run(enc, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        return jsonify({"success": False, "message": "Encrypting the build failed!"})

    # Step 4: Push encrypted zip to IPFS Cluster
    cmd = f'ipfs-cluster-ctl add -q "{enc_path}"'
    ipfs_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if ipfs_result.returncode != 0:
        return jsonify({"success": False, "message": "Unable to add the new build info to IPFS Cluster."})
    new_cid = ipfs_result.stdout.strip()

    # Step 5: Get current build records from IPNS
    cmd = f'ipfs name resolve --nocache -r {ipns_key_project_builds}'
    resolve_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if resolve_result.returncode != 0:
        return jsonify({"success": False, "message": "Unable to resolve the IPNS Key for latest CID."})
    current_builds_cid = resolve_result.stdout.strip()

    cat_cmd = f'ipfs cat {current_builds_cid}'
    cat_result = subprocess.run(cat_cmd, shell=True, capture_output=True, text=True)
    if cat_result.returncode != 0:
        return jsonify({"success": False, "message": "Unable to read the build records from IPNS and IPFS."})

    # Step 6: Prepare new build entry, auto-increment version
    try:
        builds_data = json.loads(cat_result.stdout.strip().replace('\n', ''))
    except Exception:
        builds_data = {"project_builds": []}
    builds_list = builds_data.get("project_builds", [])
    matching_builds = [b for b in builds_list if b.get("project_name") == project_name]
    if matching_builds:
        try:
            max_version = max(int(b.get("version", 0)) for b in matching_builds)
            version = str(max_version + 1)
        except Exception:
            version = "1"
    else:
        version = "1"

    new_entry = {
        "project_name": project_name,
        "build_cid": new_cid,
        "built_by": session.get("username"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": version,
        "tag": tag
    }

    if "project_builds" not in builds_data or not isinstance(builds_data["project_builds"], list):
        builds_data["project_builds"] = []
    builds_data["project_builds"].append(new_entry)

    # Step 7: Add updated build records to IPFS Cluster
    with tempfile.NamedTemporaryFile("w", delete=False) as tmpf:
        json.dump(builds_data, tmpf, indent=2)
        tmpf_path = tmpf.name

    cmd = f'ipfs-cluster-ctl add -q "{tmpf_path}"'
    ipfs_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if ipfs_result.returncode != 0:
        os.remove(tmpf_path)
        return jsonify({"success": False, "message": "Unable to add the new build info to IPFS Cluster."})

    updated_cid = ipfs_result.stdout.strip()

    # Step 8: Publish updated build records to IPNS
    cmd = f'ipfs name publish --key=project_builds {updated_cid}'
    publish_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    os.remove(tmpf_path)
    if publish_result.returncode != 0:
        return jsonify({"success": False, "message": "Unable to publish the new build info to IPNS."})

    return jsonify({
        "success": True,
        "message": f"Project build for tag '{tag}' completed successfully.",
        "build_cid": new_cid
    })
    
# @app.route('/trigger-build-ci', methods=['POST'])
# def trigger_ci_build():
#     status = check_session( session,"ci")
#     if status != True:
#         flash("Session expired!")
#         return redirect(url_for("login"))
#     data = request.get_json()
#     cid = data.get('cid')
#     tag = data.get('tag')
#     zip_password = data.get("zip_password")
#     project_name = data.get("project_name")

#     print(data)
#     print(cid)
#     print(tag)
#     print(zip_password)
#     print(project_name)
    


#     cmd = f"cd /tmp/ ipfs get {cid}"
#     result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
#     if result.returncode != 0:
#         return jsonify({
#             "success": False,
#             "message": "Unable to retrieve the requested project from CID for build."
#         })
#     zipped = False

#     for root, dir, files in os.walk(f'/tmp/{cid}'):
#         for file in files:
#             if file.endswith(".py"):
#                 subprocess.run(['zip','-r',f'{cid}.zip','.'],cwd=root)
#                 zipped = True
#                 break
#         if zipped:
#             break
#     if not zipped:
#         return jsonify({
#             "success": False,
#             "message": "No .py file found in project, nothing to zip."
#         })
#     zip_path = os.path.join(root, f"{cid}.zip")
#     enc_path = os.path.join(root, f"{cid}.zip.enc")
#     enc = f'openssl enc -aes-256-cbc -pbkdf2 -salt -in "{zip_path}" -out "{enc_path}" -pass pass:{zip_password}'
#     result = subprocess.run(enc, shell=True, capture_output=True, text=True)
#     if result.returncode != 0:
#         return jsonify({
#             "success": False,
#             "message": "Encrypting the build failed!"
#         })

#     cmd = f'ipfs-cluster-ctl add -q "{enc_path}"'
#     ipfs_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
#     if ipfs_result.returncode != 0:
#         return jsonify({
#             "success": False,
#             "message": "Unable to add the new build info to IPFS Cluster."
#         })
#     new_cid = ipfs_result.stdout.strip()

#     cmd = f'ipfs name resolve --nocache -r {ipns_key_project_builds}'
#     resolve_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
#     if resolve_result.returncode != 0:
#         return jsonify({
#             "success": False,
#             "message": "Unable to resolve the IPNS Key for latest CID."
#         })
#     current_builds_cid = resolve_result.stdout.strip()

#     cat_cmd = f'ipfs cat {current_builds_cid}'
#     cat_result = subprocess.run(cat_cmd, shell=True, capture_output=True, text=True)
#     if cat_result.returncode != 0:
#         return jsonify({
#             "success": False,
#             "message": "Unable to read the build records from IPNS and IPFS."
#         })
#     builds_data = json.loads(cat_result.stdout.strip().replace('\n', ''))
#     builds_list = builds_data.get("project_builds", [])
#     matching_builds = [b for b in builds_list if b["project_name"] == project_name and b["tag"] == tag]
#     if matching_builds:
#         # Find the max version, handle as int if possible
#         try:
#             max_version = max(int(b.get("version", 0)) for b in matching_builds)
#             version = str(max_version + 1)
#         except Exception:
#             version = "1"
#     else:
#         version = "1"

#     new_entry = {
#         "project_name": project_name,
#         "build_cid": new_cid,
#         "built_by": session.get("username"),
#         "timestamp": datetime.now(timezone.utc).isoformat(),
#         "version": version,
#         "tag": tag
#     }

#     if "project_builds" not in builds_data or not isinstance(builds_data["project_builds"], list):
#         builds_data["project_builds"] = []
    
#     builds_data["project_builds"].append(new_entry)

#     with tempfile.NamedTemporaryFile("w", delete=False) as tmpf:
#         json.dump(builds_data, tmpf, indent=2)
#         tmpf_path = tmpf.name
    
#     cmd = f'ipfs-cluster-ctl add -q "{tmpf_path}"'

#     ipfs_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

#     if ipfs_result.returncode != 0:
#         return jsonify({
#             "success": False,
#             "message": "Unable to add the new build info to IPFS Cluster."
#         })
    
#     updated_cid = ipfs_result.stdout.strip()

#     cmd = f'ipfs name publish --key=project_builds {updated_cid}'
#     publish_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
#     if publish_result.returncode != 0:
#         return jsonify({
#             "success": False,
#             "message": "Unable to publish the new build info to IPNS."
#         })
#     os.remove(tmpf_path)
#     return jsonify({
#         "success": True,
#         "message": f"Project build for tag '{tag}' completed successfully."
#     })





    
    

@app.route("/deploy-page", methods=['POST'])
def deploy_page():
    status = str(check_session(session, "deploy"))
    if "Session expired" in status:
        flash(status)
        return redirect(url_for("login"))
    elif status == "True":
        return render_template("deploy.html")
    elif "Unauthorized" in status:
        flash(status)
        return render_template("cicd_operations.html")
    elif "Unknown" in status:
        flash(status)
        return render_template("cicd_operations.html")




@app.route("/user-management", methods=['GET'])
def reg_user():
    status = check_session( session,"user_management")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("user_management.html")


@app.route("/registration_parameter", methods=['GET'])
def reg_parameters():
    status = check_session( session,"user_management")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    
    access_info = session.get("access_info")
    if not access_info:
        flash(status)
        return redirect(url_for("login"))
    
    operations = access_info.get("operations", [])
    return jsonify({"operations": operations})


@app.route("/registration_parameter_pages", methods=['GET'])
def reg_parameters_pages():
    status = check_session( session,"user_management")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    
    access_info = session.get("access_info")
    if not access_info:
        flash(status)
        return redirect(url_for("login"))
    
    pages = access_info.get("pages", [])
    return jsonify({"page_access": pages})



@app.route("/register", methods=['POST'])
def register():
    status = check_session( session,"user_management")
    if status != True:
        flash(status)
        return jsonify({"success": False, "message": status}), 401
    data = request.get_json()
    formatted = {
        "username": data.get('username', ''),
        "first_name": data.get('first_name', ''),
        "last_name": data.get('last_name', ''),
        "role": data.get('role', ''),
        "organization": data.get('organization',''), 
        "email": data.get('email', ''),
        "contact": data.get('contact', ''),
        "operations": data.get('operations', []),
        "pages": data.get('page_access', [])
    }
    print("Part 1")
    print(formatted)
    password = data.get('password','')

    with tempfile.NamedTemporaryFile('w', delete=False) as tmp:
        json.dump(formatted, tmp, indent=2)
        tmp.flush()
        tmp_path = tmp.name

    print("Part 1.1")
    print(tmp_path)
    
    try:
        result = subprocess.run(['ipfs', 'add', tmp_path, '-q'], capture_output=True, text=True)
        cid = result.stdout.strip()
        print("Part 1.2")
        print(cid)
        if result.returncode != 0 or not cid:
            return jsonify({"success": False, "message": "Unable to register the user."})
        cmd = f'echo -n {cid} | openssl enc -aes-256-cbc -a -salt -pbkdf2 -pass pass:{password}'
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        encrypted_info = res.stdout.strip()
        print("Part 1.3")
        print(encrypted_info)
        username = data.get('username', '')
        access_control = {
            username : encrypted_info
        }

        print("Part2")
        print(access_control)

        cmd = f'ipfs name resolve --nocache -r {ipns_key_access_control}'
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        latest_cid = res.stdout.strip()

        print("part 3")
        print(latest_cid)

        cmd = f'ipfs cat {latest_cid}'
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        latest_record = res.stdout.strip().replace('\n', '')

        print("part 4")
        print(latest_record)
        
        datas = json.loads(latest_record)
        print("part 5")
        
        username = data.get('username', '')
        existing_user = False

        if "access_control" in datas and isinstance(datas["access_control"], list):
            for entry in datas["access_control"]:
                if isinstance(entry, dict):
                    if username in entry:
                        existing_user = True
                        break
        if existing_user:
             return jsonify({"success": False, "message": f"Username '{username}' already exists."}), 400

        if "access_control" in datas and isinstance(datas["access_control"], list):
            datas["access_control"].append(access_control)
            print("part 6")
            print(datas)
        else:
            # if not present or not a list, initialize it as a list
            datas["access_control"] = [formatted]
        updated_json_str = json.dumps(datas, indent=2)
        print("part 7")
        print(updated_json_str)
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tmp_file:
            tmp_file.write(updated_json_str)
            tmp_file_path = tmp_file.name
        ipfs_add_cmd = f"ipfs-cluster-ctl add {tmp_file_path} -q"
        new_ipfs_output = subprocess.run(ipfs_add_cmd, shell=True, capture_output=True, text=True)
        new_ipfs_output = new_ipfs_output.stdout.strip()

        print("part 8")
        print(new_ipfs_output)

        cmd_publish = f"ipfs name publish --key=access_control {new_ipfs_output}"
        new_ipfs_output = subprocess.run(cmd_publish, shell=True, capture_output=True, text=True)


        passphrase = data.get('password','')
        username = data.get('username', '')

        print(f"Username: {username}")
        print(f"Password: {passphrase}")

        key_path = f"/home/guest/.ssh/{username}.pvt"


        

        cmd = [
            "ssh-keygen",
            "-t", "ed25519",
            "-f", key_path,
            "-N", passphrase
        ]

        

        result = subprocess.run(cmd, capture_output=True, text=True)

        print("PArt 8.2")
        print(result)
        if result.returncode != 0:
            return jsonify({"success": False, "message": "Unable to generate SSH key."}), 400
        

        print("part 9")
        if result.returncode == 0:
            try:
                return send_file(
                    key_path,
                    as_attachment=True,
                    download_name=f"{username}.pvt"
                )
            except:
                return jsonify({"success": False, "message": "Error in generating the keys or registration not successful"}), 400
               





        
    except:
        return jsonify({"success": False, "message": "Unable to register the user."}), 500

    finally:
        # Remove temp file
        import os
        os.remove(tmp_path)
    


    


@app.route('/pushto_ipfs', methods=['POST'])
def pushto_ipfs():
    status = check_session(session, "pushto_ipfs")
    if status != True:
        flash(status)
        return redirect(url_for("login"))

    access_info = session.get("access_info")
    if not access_info:
        return jsonify(success=False, error="Session invalid, please re-login."), 401

    f = request.files.get('zipfile')
    if not f or not f.filename.lower().endswith('.zip'):
        return jsonify(success=False, error='Please upload a .zip'), 400

    # Save zip file
    filename = secure_filename(f.filename)
    project_name, _ = os.path.splitext(filename)
    zip_path = os.path.join(TEMP_DIR, filename)
    f.save(zip_path)

    # Extract to unique subdirectory
    extract_dir = os.path.join(TEMP_DIR, project_name)
    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir)
    os.makedirs(extract_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

    try:
        # Add the extracted folder (not the zip file) to IPFS Cluster
        cmd = f"ipfs-cluster-ctl add -r {extract_dir} | tail -n1 | cut -d' ' -f2"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if res.returncode != 0:
            return jsonify(success=False, error=res.stderr.strip()), 500

        new_cid = res.stdout.strip()

        print(f"Hello, Part3 done: {new_cid}")
        print("Invoking the update method")

        status = update_project_record(new_cid, None, ipns_key_projects, project_name, access_info)

        if status == True:
            return jsonify(success=True, cid="Successfully pushed to IPFS Cluster.")
        else:
            return jsonify(success=False, error="Failed to push the project to the repo."), 500

    except Exception as e:
        import traceback
        print("Exception in /pushto_ipfs:", traceback.format_exc())
        return jsonify(success=False, error=str(e)), 500
    finally:
        # Clean up files
        try:
            os.remove(zip_path)
            shutil.rmtree(extract_dir)
        except OSError:
            pass




# @app.route('/pushto_ipfs', methods=['POST'])
# def pushto_ipfs():
#     status = check_session( session,"pushto_ipfs")
#     if status != True:
#         flash(status)
#         return redirect(url_for("login"))

#     access_info = session.get("access_info")
#     if not access_info:
#         return jsonify(success=False, error="Session invalid, please re-login."), 401

#     f = request.files.get('zipfile')
#     if not f or not f.filename.lower().endswith('.zip'):
#         return jsonify(success=False, error='Please upload a .zip'), 400

#     # ensure temp dir exists
#     os.makedirs(TEMP_DIR, exist_ok=True)

#     filename = secure_filename(f.filename)
#     project_name, _ = os.path.splitext(filename)
#     zip_path = os.path.join(TEMP_DIR, filename)
#     f.save(zip_path)
#     extract_dir = TEMP_DIR


#     os.makedirs(extract_dir, exist_ok=True)
#     with zipfile.ZipFile(zip_path, 'r') as zip_ref:
#         zip_ref.extractall(extract_dir)


#     try:
#         cmd = f"ipfs-cluster-ctl add -r {zip_path} | tail -n1 | cut -d' ' -f2"
#         res = subprocess.run(cmd, shell=True, capture_output=True, text=True)

#         if res.returncode != 0:
#             return jsonify(success=False, error=res.stderr.strip()), 500

#         new_cid = res.stdout.strip()

#         print(f"Hello, Part3 done: {new_cid}")
#         print("Invoking the update method")

#         status = update_project_record(new_cid, None, ipns_key_projects, project_name, access_info)

#         if status == True:
#             return jsonify(success=True, cid=new_cid)
#         else:
#             return jsonify(success=False, error="Failed to push the project to the repo."), 500

#     except Exception as e:
#         import traceback
#         print("Exception in /pushto_ipfs:", traceback.format_exc())
#         return jsonify(success=False, error=str(e)), 500
#     finally:
#         try:
#             os.remove(zip_path)
#         except OSError:
#             pass

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=1000)
