from datetime import datetime, timedelta, timezone
import os
import re
import socket
import subprocess
import tempfile
from time import sleep
import time
import zipfile
from flask import Flask, json, jsonify, make_response, render_template, request, redirect, send_file, url_for, flash, session
from services.ipfs import ipfs_connect, remove_user_info, republish_ipfs_keys, retrieve_access_control, get_document_ipfs_cid, update_project_record, ipns_keys, list_all_users
from services.crypto import decrypt_openssl_subprocess
from services.session import check_session
from werkzeug.utils import secure_filename
from services.logs import get_logs, immutable_application_log
import os
import subprocess
import tempfile
import zipfile
import json
from datetime import datetime, timezone
from flask import request, jsonify, session, flash, redirect, url_for



ports = {
    "dev": 1001,
    "qa": 1002,
    "prod": 1003
}



status, keys = ipns_keys()
if status != True:
    exit()
ipns_key_access_control = keys.get("access_control")
ipns_key_projects = keys.get("projects")
ipns_key_project_builds = keys.get("project_builds")
ipns_key_misc = keys.get("misc")
ipns_key_logs = keys.get("logs")
ipns_key_roles = keys.get("roles")
ipns_key_userpublickey = keys.get("user_publickey")



def resolve_ipns():
    try:
        result = subprocess.run(
            ["ipfs", "name", "resolve", "--nocache", "-r", f'{ipns_key_misc}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        cid = result.stdout.strip().replace("/ipfs/", "")
        repub = subprocess.run(
            ["ipfs", "name", "publish", "--key=misc", f'/ipfs/{cid}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True
        )
        repub.stdout.strip().replace("\n", "")
        
    except:
        pass


    

time.sleep(30)

app = Flask(__name__)




app.secret_key = os.urandom(32)





app.permanent_session_lifetime = timedelta(minutes=10)



app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  

app.config['SESSION_COOKIE_HTTPONLY'] = True  


app.config['SESSION_COOKIE_SECURE'] = True       


app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'     



TEMP_DIR = '/tmp'

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

def get_client_ip():
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip



@app.route('/get_logs', methods=['GET'])
def get_all_logs():
    status = check_session(session, "logs")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    logs = get_logs(ipns_key_logs)  
    response = make_response(render_template("logs_table.html", logs=logs))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


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

        success, message = remove_user_info(ipns_key_access_control, username, ipns_key_userpublickey)
        if success != True:
            return jsonify({"success": success, "message": message})

        immutable_application_log(session, "remove_user", "user-management", f"User removed.",ipns_key_logs)
        
            
            
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
            flash("Invalid username. Use 3 to 32 characters: letters, numbers and underscores only.")
            return redirect(url_for("login"))

        if not (6 <= len(password) <= 32):
            flash("Invalid password length found. Must be 6 to 32 characters.")
            return redirect(url_for('login'))

        ipfs_conn_status = ipfs_connect()

        if ipfs_conn_status == True:
            try:
                cid = retrieve_access_control(ipns_key_access_control, username)
                if cid == 1:
                    flash("User not exists!")
                    return redirect(url_for("login"))
                elif cid == 2:
                    flash("Error to fetch IPFS Data.")
                    return redirect(url_for("login"))

                enc_user_info = get_document_ipfs_cid(cid)
                access_infos = decrypt_openssl_subprocess(enc_user_info, password)
                access_info = json.loads(access_infos)
                
                

                session.clear()
                resolve_ipns()

                session.permanent = True
                session["username"] = access_info.get("username")
                session["role"] = access_info.get("role")
                expiry_time = datetime.now(timezone.utc) + timedelta(minutes=10)
                session['expiry'] = expiry_time.timestamp()
                session["page_access"] = access_info.get("pages", [])
                session["access_info"] = access_info
                session["organization"] = access_info.get("organization", [])
                session["start_time"] = datetime.now(timezone.utc).isoformat()
                resolve_ipns()
                s,m = immutable_application_log(session, "login", "login_page", "Login successful", ipns_key_logs)
                if s == False:
                    print(f"Login logger failed: {m}")
                 
                
                

                if access_info.get("role") == "admin":
                    
                    return redirect(url_for('admin_dashboard'))
                elif access_info.get("role") == "developer":
                    return redirect(url_for('developer_dashboard'))
                elif access_info.get("role") == "qa":
                    return redirect(url_for('qa_dashboard'))

                flash("Role not recognized.")
                return redirect(url_for("login"))

            except Exception as e:
                flash("Login failed: Invalid Credentials")
                return redirect(url_for("login"))

        else:
            flash("Connection to IPFS API node failed!")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/sync_nodes", methods=["POST"])
def syncing_nodes():
    try:
        status = check_session( session,"admin_dashboard")
        if status != True:
            flash(status)
            return redirect(url_for("login"))
        password = request.form.get("password", "")
        status = republish_ipfs_keys("guest", password)

        if status == False:
            return jsonify({"status": False, "Message": "Unable to update the nodes."}), 500
        return jsonify({"status": True, "Message": "All node available are updated."}), 200

    except Exception as msg:
        return jsonify({"status": False, "Message": msg}), 500

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
        return jsonify({"message":"Unable to retrieve roles from the IPFS Cluster."})



@app.route("/roles", methods=["GET"])
def list_roles():
    try:
        status = check_session(session,"user_management")
        if status != True:
            flash(status)
            return redirect(url_for("login"))
        result = subprocess.run(
            ["ipfs", "name", "resolve", "--nocache", "-r", f'/ipns/{ipns_key_roles}'],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return jsonify({"message":"Unable to retrieve the roles from the IPNS Records."})
        role_cid = result.stdout.strip().replace('\n','')

        
        result = subprocess.run(
            ["ipfs", "cat", role_cid],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return jsonify({"message":"Unable to retrieve the roles from the IPFS Cluster."})
        role_info = result.stdout.strip().replace('\n','')
        roles = json.loads(role_info)
        return roles["roles"]
    except Exception as e:
        return jsonify({"message":"Unable to retrieve the roles from IPFS Cluster."})

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
        new_ipfs_output = subprocess.run(
            ["ipfs", "name", "resolve", "--nocache", "-r", f'/ipns/{ipns_key_projects}'],
            capture_output=True,
            text=True
        )

        resolved = new_ipfs_output.stdout.strip()

        data = subprocess.run(
            ["ipfs", "cat", resolved],
            capture_output=True,
            text=True
        )

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
    result = subprocess.run(
        ["ipfs", "name", "resolve", "--nocache", "-r", f'/ipns/{ipns_key_project_builds}'],
        capture_output=True,
        text=True
    )

    result = result.stdout.strip().replace('\n','')

    result1 = subprocess.run(
        ["ipfs", "cat", result],
        capture_output=True,
        text=True
    )

    result1 = result1.stdout.strip().replace('\n','')
    json_result = json.loads(result1)
    return jsonify(json_result), 200


@app.route('/logout')
def logout():
    immutable_application_log(session, "logout", "login", f"Logged out",ipns_key_logs)
    
    session.clear()
      
    return redirect(url_for('login')) 

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

        port = ports.get(tag) 
        if not all([server_list, deployment_server_password, tag, port]):
            return jsonify({"status": "error", "message": "Missing some parameters"}), 400

        failed_servers = []
        success_servers = []

        for server in server_list:
            try:
                stop_cmd = f'fuser -k {port}/tcp || true'
                ssh_cmd = [
                    "sshpass", "-p", deployment_server_password,

                    "ssh", "-o", "StrictHostKeyChecking=no",

                    f"guest@{server}",

                    stop_cmd
                ]
                stop_data = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                
                project_dir = f"/home/guest/www/{tag}"
                cleanup_cmd = f'rm -rf {project_dir}'
                cleanup_full_cmd = [
                    "sshpass", "-p", deployment_server_password,

                    "ssh", "-o", "StrictHostKeyChecking=no",
                    
                    
                    f"guest@{server}",
                    
                    cleanup_cmd
                ]
                cleanup_data = subprocess.run(cleanup_full_cmd, capture_output=True, text=True, timeout=30)


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
            immutable_application_log(session, "decommission", "trigger-cd", f"Decommission done for all server.",ipns_key_logs)
            
                
            return jsonify({"status": "success", "message": "Decommission done!"})
        elif len(success_servers) == 0:
            immutable_application_log(session, "decommission", "trigger-cd", f"Decommission failed for all server.",ipns_key_logs)
            
                
            return jsonify({
                "status": "error",
                "message": "Decommission failed on all servers.",
                "failed_servers": failed_servers
            })
        else:
            immutable_application_log(session, "decommission", "trigger-cd", f"Decommission failed for some server.",ipns_key_logs)
            
                
                
            return jsonify({
                "status": "partial_failure",
                "failed_servers": failed_servers,
                "count": len(failed_servers),
                "message": "Some decommissions failed. Try again."
            })

    except Exception as e:
        return jsonify({"status": "error", "message": f"Decommission failed: {str(e)}"}), 500





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
            return jsonify({"status": "error", "message": "Missing some parameters"}), 400

        failed_servers = []
        success_servers = []

        for server in server_list:
            try:
                remote_cmd = (
                    f'mkdir -p /home/guest/www/{tag}/{build_cid}/webapp/ && '
                    f'ipfs get {build_cid} -o /home/guest/www/{tag}/{build_cid}/webapp/'
                )
                cmd = [
                    "sshpass", "-p", deployment_server_password,
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    f"guest@{server}",
                    remote_cmd
                ]
                data = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                if data.returncode != 0:
                    failed_servers.append({"server": server, "step": 1, "stderr": data.stderr.strip()})
                    continue

                remote_cmd = (
                    f'openssl enc -d -aes-256-cbc -pbkdf2 '
                    f'-in /home/guest/www/{tag}/{build_cid}/webapp/{build_cid} '
                    f'-out /home/guest/www/{tag}/{build_cid}/webapp/{build_cid}.zip '
                    f'-pass pass:{artifact_password}'
                )
                cmd1 = [
                    "sshpass", "-p", deployment_server_password,
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    f"guest@{server}",
                    remote_cmd
                ]
                data1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=60)

                if data1.returncode != 0:
                    if "bad decrypt" in data1.stderr or "bad password" in data1.stderr:
                        return jsonify({"status": "failed", "message": "Incorrect password for artifact!"})
                    failed_servers.append({"server": server, "step": 2, "stderr": data1.stderr.strip()})
                    continue

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
                cmd2 = [
                    "sshpass", "-p", deployment_server_password,
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    f"guest@{server}",
                    run_command
                ]
                data2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=90)


                if "__DEPLOY_SUCCESS__" in data2.stdout:
                    success_servers.append(server)
                else:
                    log_cmd = [
                        "sshpass", "-p", deployment_server_password,
                        "ssh", "-o", "StrictHostKeyChecking=no",
                        f"guest@{server}",
                        f"tail -n 50 {project_dir}/app.log 2>/dev/null"
                    ]
                    log_data = subprocess.run(log_cmd, capture_output=True, text=True, timeout=10)

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
            immutable_application_log(session, "trigger_cd", "deploy", f"Deployment done for all the server.",ipns_key_logs)
            
                
                
            return jsonify({"status": "success", "message": "Deployment done!"})
        elif len(success_servers) == 0:
            immutable_application_log(session, "trigger_cd", "deploy", f"Deployment failed for all the server.",ipns_key_logs)
            
                
                
            return jsonify({
                "status": "error",
                "message": "Deployment failed on all the servers.",
                "failed_servers": failed_servers
            })
        else:
            immutable_application_log(session, "trigger_cd", "deploy", f"Deployment failed for some server.",ipns_key_logs)
             
                
                
            return jsonify({
                "status": "partial_failure",
                "failed_servers": failed_servers,
                "count": len(failed_servers),
                "message": "Some deployments failed. Please Try to deploy again."
            })

    except Exception as e:
        return jsonify({"status": "error", "message": f"Deployment failed: {str(e)}"}), 500




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
       

        result = subprocess.run(
            ['ipfs-cluster-ctl', 'peers', 'ls'],
            capture_output=True,
            text=True
        )

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
        zip_password = data.get('zip_password')

        if not zip_password:
            return jsonify({'error': 'Password required'}), 400

        with tempfile.TemporaryDirectory() as tmpdir:
            enc_path = os.path.join(tmpdir, f"{project_name}.zip.enc")
            dec_path = os.path.join(tmpdir, f"{project_name}.zip")

            subprocess.run(['ipfs', 'get', cid, '-o', enc_path], check=True)

            dec_cmd = [
                'openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-in', enc_path,
                '-out', dec_path, '-pass', f'pass:{zip_password}'
            ]
            dec_result = subprocess.run(dec_cmd, capture_output=True, text=True)

            if dec_result.returncode != 0:
                if "bad decrypt" in dec_result.stderr.lower() or "error" in dec_result.stderr.lower():
                    return jsonify({'error': 'wrong password'}), 403
                else:
                    return jsonify({'error': dec_result.stderr.strip() or "Decryption failed"}), 500

            immutable_application_log(session, "download_project", "pull_from_ipfs", "Download the Project.",ipns_key_logs)
            
                
                
            return send_file(
                dec_path,
                as_attachment=True,
                download_name=f"{project_name}.zip"
            )

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/project_info', methods=['POST'])
def get_all_projects():
    status = check_session( session,"ci")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    try:
        new_ipfs_output = subprocess.run(
            ["ipfs", "name", "resolve", "--nocache", "-r", f'/ipns/{ipns_key_projects}'],
            capture_output=True,
            text=True
        )

        resolved = new_ipfs_output.stdout.strip()

        data = subprocess.run(
            ["ipfs", "cat", resolved],
            capture_output=True,
            text=True
        )

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
    project_zip_password = data.get("zip_password")         
    build_zip_password = data.get("build_zip_password")     
    project_name = data.get("project_name")

    if not build_zip_password:
        return jsonify({"success": False, "message": "Build zip password is required."})

    with tempfile.TemporaryDirectory() as tmpdir:
        enc_zip_path = os.path.join(tmpdir, f"{cid}.zip.enc")
        dec_zip_path = os.path.join(tmpdir, f"{cid}.zip")
        extract_dir = os.path.join(tmpdir, "extracted")

        result = subprocess.run(
            ["ipfs", "get", cid, "-o", enc_zip_path],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return jsonify({"success": False, "message": "Unable to retrieve the requested project from CID for the build."})

        dec_cmd = [
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
            "-in", enc_zip_path,
            "-out", dec_zip_path,
            "-pass", f"pass:{project_zip_password}"
        ]
        dec_result = subprocess.run(dec_cmd, capture_output=True, text=True)

        if dec_result.returncode != 0:
            return jsonify({"success": False, "message": "Decryption failed. Wrong project password or file is corrupt."})

        os.makedirs(extract_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(dec_zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        except Exception as e:
            return jsonify({"success": False, "message": f"Failed to extract zip: {e}"})

        zipped = False
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.lower().endswith(".py"):
                    subprocess.run(['zip', '-r', f'{cid}_build.zip', '.'], cwd=root)
                    zipped = True
                    break
            if zipped:
                break
        if not zipped:
            return jsonify({"success": False, "message": "No .py file found in project. So nothing to zip."})

        zip_path = os.path.join(root, f"{cid}_build.zip")
        enc_build_path = os.path.join(root, f"{cid}_build.zip.enc")

        enc = [
            "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
            "-in", zip_path,
            "-out", enc_build_path,
            "-pass", f"pass:{build_zip_password}"
        ]
        result = subprocess.run(enc, capture_output=True, text=True)

        if result.returncode != 0:
            return jsonify({"success": False, "message": "Encrypting the build failed!"})

        ipfs_result = subprocess.run(
            ["ipfs-cluster-ctl", "add", "-q", enc_build_path],
            capture_output=True,
            text=True
        )

        if ipfs_result.returncode != 0:
            return jsonify({"success": False, "message": "Unable to add the new build info to the IPFS Cluster."})
        new_cid = ipfs_result.stdout.strip()

        resolve_result = subprocess.run(
            ["ipfs", "name", "resolve", "--nocache", "-r", f'/ipns/{ipns_key_project_builds}'],
            capture_output=True,
            text=True
        )

        if resolve_result.returncode != 0:
            return jsonify({"success": False, "message": "Unable to resolve the IPNS Key for the latest CID."})
        current_builds_cid = resolve_result.stdout.strip()

        cat_result = subprocess.run(
            ["ipfs", "cat", current_builds_cid],
            capture_output=True,
            text=True
        )

        if cat_result.returncode != 0:
            return jsonify({"success": False, "message": "Unable to read the build records from the IPNS and the IPFS."})

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

        with tempfile.NamedTemporaryFile("w", delete=False) as tmpf:
            json.dump(builds_data, tmpf, indent=2)
            tmpf_path = tmpf.name

        ipfs_result = subprocess.run(
            ["ipfs-cluster-ctl", "add", "-q", tmpf_path],
            capture_output=True,
            text=True
        )

        if ipfs_result.returncode != 0:
            os.remove(tmpf_path)
            return jsonify({"success": False, "message": "Unable to add new build info to Cluster."})

        updated_cid = ipfs_result.stdout.strip()

        publish_result = subprocess.run(
            ["ipfs", "name", "publish",  "--key=project_builds", '--lifetime=17520h', f'/ipfs/{updated_cid}'],
            capture_output=True,
            text=True
        )

        os.remove(tmpf_path)
        if publish_result.returncode != 0:
            return jsonify({"success": False, "message": "Unable to publish the new build info to the IPNS."})

        immutable_application_log(session, "trigger_ci", "trigger-ci", "Build triggered",ipns_key_logs)
        
            
            
        return jsonify({
            "success": True,
            "message": f"Project build for tag '{tag}' completed successfully.",
            "build_cid": new_cid
        })



    
    

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
    status = check_session(session, "user_management")
    if status != True:
        flash(status)
        return jsonify({"success": False, "message": status}), 401

    data = request.get_json()
    public_key = data.get('public_key')
    if not public_key:
        return jsonify({"success": False, "message": "Public key missing"}), 400

    public_key = str(public_key).replace('\n', '').replace('\r', '')

    pub_key_info_check = public_key.strip()
    uname = data.get('username', '')
    if not pub_key_info_check.endswith(' ' + uname):
        return jsonify({"success": False, "message": "Username does not match comment in the public key"}), 400

    res01 = subprocess.run(
        ["ipfs", "name", "resolve", "--nocache", "-r", f'/ipns/{ipns_key_userpublickey}'],
        capture_output=True,
        text=True
    )
    if res01.returncode != 0:
        return jsonify({"success": False, "message": "Failed to resolve IPNS for public key."}), 500

    cid = res01.stdout.strip()

    res02 = subprocess.run(
        ["ipfs", "cat", cid],
        capture_output=True,
        text=True
    )
    if res02.returncode != 0:
        return jsonify({"success": False, "message": "Failed to fetch the public key record."}), 500

    ipns_pubkey_record_str = res02.stdout.strip().replace('\n', '').replace('\r', '')

    try:
        ipns_pubkey_record = json.loads(ipns_pubkey_record_str)
    except Exception:
        return jsonify({"success": False, "message": "Invalid JSON in public key record."}), 500

    ipns_pubkey_record.setdefault("records", []).append(public_key)

    json_string = json.dumps(ipns_pubkey_record)

    with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp_pubkey_file:
        tmp_pubkey_file.write(json_string)
        tmp_pubkey_path = tmp_pubkey_file.name

    tmp_user_path = None
    tmp_enc_user_path = None
    tmp_acc_file_path = None

    try:
        res03 = subprocess.run(
            ["ipfs-cluster-ctl", "add", "-q", tmp_pubkey_path],
            capture_output=True,
            text=True
        )
        if res03.returncode != 0:
            return jsonify({"success": False, "message": "Failed to add public key record."}), 500

        cid = res03.stdout.strip()

        res04 = subprocess.run(
            ["ipfs", "name", "publish",  "--key=user_publickey", '--lifetime=17520h', f'/ipfs/{cid}'],
            capture_output=True,
            text=True
        )
        if res04.returncode != 0:
            return jsonify({"success": False, "message": "Unable to register the public key."}), 400

        formatted = {
            "username": data.get('username', ''),
            "first_name": data.get('first_name', ''),
            "last_name": data.get('last_name', ''),
            "role": data.get('role', ''),
            "organization": data.get('organization', ''),
            "email": data.get('email', ''),
            "contact": data.get('contact', ''),
            "operations": data.get('operations', []),
            "pages": data.get('page_access', [])
        }
        password = data.get('password', '')
        if not password:
            return jsonify({"success": False, "message": "Password missing."}), 400

        user_info_json = json.dumps(formatted, indent=2)

        openssl_proc = subprocess.Popen(
            ['openssl', 'enc', '-aes-256-cbc', '-a', '-salt', '-pbkdf2', '-pass', f'pass:{password}'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        out, err = openssl_proc.communicate(input=user_info_json)
        if openssl_proc.returncode != 0:
            return jsonify({"success": False, "message": f"OpenSSL encryption failed: {err.strip()}"}), 500

        encrypted_user_info = out.strip()

        with tempfile.NamedTemporaryFile('w', delete=False) as tmp_enc_user_file:
            tmp_enc_user_file.write(encrypted_user_info)
            tmp_enc_user_file.flush()
            tmp_enc_user_path = tmp_enc_user_file.name

        result = subprocess.run(['ipfs-cluster-ctl', 'add', '-q', tmp_enc_user_path], capture_output=True, text=True)
        if result.returncode != 0:
            return jsonify({"success": False, "message": "Unable to register the user."}), 500

        cid = result.stdout.strip()

        username = data.get('username', '')
        access_control = {username: cid}

        res = subprocess.run(
            ["ipfs", "name", "resolve", "--nocache", "-r", f'/ipns/{ipns_key_access_control}'],
            capture_output=True,
            text=True
        )
        if res.returncode != 0:
            return jsonify({"success": False, "message": "Failed to resolve access control record."}), 500

        latest_cid = res.stdout.strip()

        res = subprocess.run(
            ["ipfs", "cat", latest_cid],
            capture_output=True,
            text=True
        )
        if res.returncode != 0:
            return jsonify({"success": False, "message": "Failed to fetch access control record."}), 500

        latest_record_str = res.stdout.strip().replace('\n', '')

        datas = json.loads(latest_record_str)

        existing_user = False
        if "access_control" in datas and isinstance(datas["access_control"], list):
            for entry in datas["access_control"]:
                if isinstance(entry, dict) and username in entry:
                    existing_user = True
                    break

        if existing_user:
            return jsonify({"success": False, "message": f"Username '{username}' already exists."}), 400

        if "access_control" in datas and isinstance(datas["access_control"], list):
            datas["access_control"].append(access_control)
        else:
            datas["access_control"] = [access_control]

        updated_json_str = json.dumps(datas, indent=2)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as tmp_acc_file:
            tmp_acc_file.write(updated_json_str)
            tmp_acc_file_path = tmp_acc_file.name

        new_ipfs_output = subprocess.run(
            ["ipfs-cluster-ctl", "add", tmp_acc_file_path, "-q"],
            capture_output=True,
            text=True
        )
        if new_ipfs_output.returncode != 0:
            return jsonify({"success": False, "message": "Failed to add updated access control file."}), 500

        new_cid = new_ipfs_output.stdout.strip()

        publish_res = subprocess.run(
            ["ipfs", "name", "publish",  "--key=access_control", '--lifetime=17520h', f'/ipfs/{new_cid}'],
            capture_output=True,
            text=True
        )
        if publish_res.returncode != 0:
            return jsonify({"success": False, "message": "Unable to register the user. IPNS publish error. Contact Admin."}), 500

        immutable_application_log(session, "user_registration", "user-management", f"New user was registered.", ipns_key_logs)
        
            
        
        return jsonify({"success": True, "message": "Registration complete."}), 200

    except Exception as e:
        return jsonify({"success": False, "message": f"Unable to register the user. Error: {str(e)}"}), 500

    finally:
        for path in [tmp_pubkey_path, tmp_user_path, tmp_enc_user_path, tmp_acc_file_path]:
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass







@app.errorhandler(413)
def too_large(e):
    if request.accept_mimetypes['application/json'] or request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':

        return jsonify(success=False, error='File is too large. The Maximum upload size is 100 MB.'), 413
    else:
        flash('File is too large. Max uploading size is 100 MB.')
        return redirect(request.url)

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
    zip_password = request.form.get('zip_password') 

    if not f or not f.filename.lower().endswith('.zip'):
        return jsonify(success=False, error='Please upload a .zip'), 400

    if not zip_password:
        return jsonify(success=False, error="Password required to encrypt the file."), 400

    filename = secure_filename(f.filename)
    zip_path = os.path.join(TEMP_DIR, filename)
    f.save(zip_path)

    enc_zip_path = zip_path + ".enc"
    enc_cmd = [
        "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
        "-in", zip_path,
        "-out", enc_zip_path,
        "-pass", f"pass:{zip_password}"
    ]
    enc_res = subprocess.run(enc_cmd, capture_output=True, text=True)

    if enc_res.returncode != 0:
        return jsonify(success=False, error="Encryption failed: " + enc_res.stderr.strip()), 500

    try:
        p1 = subprocess.Popen(
            ["ipfs-cluster-ctl", "add", enc_zip_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        p2 = subprocess.Popen(
            ["tail", "-n1"],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        p1.stdout.close()

        p3 = subprocess.Popen(
            ["cut", "-d", " ", "-f2"],
            stdin=p2.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        p2.stdout.close()

        out, err = p3.communicate()

        if p1.wait() != 0 or p2.wait() != 0 or p3.returncode != 0:
            return jsonify(success=False, error=err.strip()), 500

        new_cid = out.strip()



        project_name, _ = os.path.splitext(filename)
        status = update_project_record(new_cid, None, ipns_key_projects, project_name, access_info)

        if status == True:
            immutable_application_log(session, "push_project", "pushto_ipfs", "Project Pushed",ipns_key_logs)
            
                
                
            return jsonify(success=True, cid=new_cid)
        else:
            return jsonify(success=False, error="Failed to push the project to the repo."), 500

    except Exception as e:
        return jsonify(success=False, error=str(e)), 500
    finally:
        for path in [zip_path, enc_zip_path]:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass



if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=1000)
