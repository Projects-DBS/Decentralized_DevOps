from datetime import datetime, timedelta, timezone
import os
import shutil
import subprocess
import tempfile
import zipfile
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from services.ipfs import ipfs_connect, retrieve_access_control, get_document_ipfs_cid, update_repo_ipns
from services.crypto import decrypt_openssl
from werkzeug.utils import secure_filename


import sys


if len(sys.argv) > 1:
    ACCESS_CONTROL_KEY = sys.argv[1]
    
else:
    raise ValueError("You must pass the ACCESS_CONTROL_KEY as an argument.")

app = Flask(__name__)
app.secret_key = "change_this_secret"  # Change this for production
app.permanent_session_lifetime = timedelta(minutes=10)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit

TEMP_DIR = '/home/guest'


IPFS_URL = "http://127.0.0.1:5001"

def check_session(page):
    try:
        username = session.get("username")
        role = session.get("role")
        expiry = session.get("expiry")
        page_access = session.get("page_access", [])

        if not username or not role or not expiry:
            return "Unauthorized access!"

        if datetime.now(timezone.utc).timestamp() > expiry:
            session.clear()
            return "Session expired. Please log in again."

        if role not in ["admin", "developer", "qa"]:
            session.clear()
            return "Unauthorized access."

        if page not in page_access:
            return "Unauthorized page access."

        return True

    except Exception:
        return "Unknown error occurred!"

@app.route("/login", methods=["GET", "POST"])
def login():
    global access_info
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        pvtkey = request.files.get("pvtkey")

        if not username or not password or not pvtkey:
            flash("All fields are required.")
            return redirect(url_for("login"))

        if not (3 <= len(username) <= 32) or not username.replace('_', '').isalnum():
            flash("Invalid username. Use 3-32 characters: letters, numbers, and underscores only.")
            return redirect(url_for("login"))

        if not (6 <= len(password) <= 32):
            flash("Invalid password length. Must be 6-32 characters.")
            return redirect(url_for('login'))

        if not pvtkey.filename.endswith(".pvt"):
            flash("Private key file must have .pvt extension.")
            return redirect(url_for('login'))

        ipfs_conn_status = ipfs_connect(IPFS_URL)

        if ipfs_conn_status == True:
            try:
                user_access = retrieve_access_control(ACCESS_CONTROL_KEY, IPFS_URL, username)
                access_control_cid = decrypt_openssl(user_access, password).decode()
                access_info = get_document_ipfs_cid(access_control_cid, IPFS_URL)

                session.permanent = True
                session["username"] = access_info.get("username")
                session["role"] = access_info.get("role")
                expiry_time = datetime.now(timezone.utc) + timedelta(minutes=10)
                session['expiry'] = expiry_time.timestamp()
                session["page_access"] = access_info.get("pages", [])

                if access_info.get("role") == "admin":
                    return redirect(url_for('admin_dashboard'))
                elif access_info.get("role") == "developer":
                    return redirect(url_for('developer_dashboard'))
                elif access_info.get("role") == "qa":
                    return redirect(url_for('qa_dashboard'))

                flash("Role not recognized.")
                return redirect(url_for("login"))

            except Exception as e:
                flash(f"Login failed: {str(e)}")
                return redirect(url_for("login"))

        else:
            flash("Connection to IPFS API node failed!")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/admin-dashboard", methods=["GET","POST"])
def admin_dashboard():
    status = check_session("admin_dashboard")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html", username=session.get("username"))


# Add developer and QA dashboard routes similarly if you have them
@app.route("/developer-dashboard", methods=["GET", "POST"])
def developer_dashboard():
    status = check_session("developer_dashboard")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("developer_dashboard.html", username=session.get("username"))

@app.route("/qa-dashboard", methods=["GET", "POST"])
def qa_dashboard():
    status = check_session("qa_dashboard")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("qa_dashboard.html", username=session.get("username"))

@app.route("/ipfs-repo-operation", methods=["GET", "POST"])
def push_pull():
    status = check_session("ipfs-repo-operation")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("ipfs-repo-operation.html")


@app.route('/pushto_ipfs', methods=['GET'])
def push_to_ipfs():
    status = check_session("pushto_ipfs")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    return render_template("pushto_ipfs.html")

@app.route('/pushto_ipfs', methods=['POST'])
def pushto_ipfs():
    print("Started")
    status = check_session("pushto_ipfs")
    if status != True:
        flash(status)
        return redirect(url_for("login"))
    
    print("Session checked")

    f = request.files.get('zipfile')
    if not f or not f.filename.lower().endswith('.zip'):
        return jsonify(success=False, error='Please upload a .zip'), 400

    # ensure temp dir exists
    os.makedirs(TEMP_DIR, exist_ok=True)
    print("Part 1 done")
    # save to /home/guest/temp/<secure-filename>.zip
    filename = secure_filename(f.filename)
    project_name, _ = os.path.splitext(filename)  
    zip_path = os.path.join(TEMP_DIR, filename)
    f.save(zip_path)
    extract_dir = "/home/guest/temp"
    print("Reached here.")
    print("Hello, Part1 done")

    os.makedirs(extract_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)


    print(f"Hello, Part2 done: {zip_path}")
    
    
    
    try:
        cmd = f"ipfs-cluster-ctl add -r {zip_path} | tail -n1 | cut -d' ' -f2"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)


        if res.returncode != 0:
            flash(res.stderr.strip())
            return render_template("pushto_ipfs.html")

        new_cid = res.stdout.strip()
      
      
        print(f"Hello, Part3 done: {new_cid}")


        status = update_repo_ipns(new_cid, None, ACCESS_CONTROL_KEY, project_name, access_info)
        
        if status == True:
            return jsonify(success=True, cid=new_cid)
        else:
            return jsonify(success=False, error="Failed to push the project to the repo."), 500





    finally:
        try: os.remove(zip_path)
        except OSError: pass


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=1000)




# from datetime import datetime, timedelta, timezone
# from flask import Flask, render_template, request, redirect, url_for, flash, session, app
# import requests
# from services.ipfs import ipfs_connect, retrieve_access_control, get_document_ipfs_cid
# from services.crypto import decrypt_openssl


# app = Flask(__name__)
# app.permanent_session_lifetime = timedelta(minutes=1)

# app = Flask(__name__)
# app.secret_key = "change_this_secret"  # Use a random value for production
# IPFS_URL = "http://127.0.0.1:5001"

# def check_session(page):
#     try:
#         if access_info.get("username") == session.get("username"):
#             expiry = session.get("expiry")
#             role = session.get("role")
#             if expiry and datetime.now(timezone.utc).timestamp() > expiry:
#                 session.clear()
#                 return "Session expired. Please log in again."

#             if role != access_info.get("role"):
#                 session.clear()
#                 return "Unauthorized access."
            
#             if page in session.get("page_access"):
#                 return True
            
#             return "Service not working!"
                

#         else:

#             return "Unauthorized access!"
#     except:
#         return "Unknown error occured!"


# @app.route("/login", methods=["GET", "POST"])
# def login():
#     global access_info
#     if request.method == "POST":
#         username = request.form.get("username", "").strip()
#         password = request.form.get("password", "")
#         pvtkey = request.files.get("pvtkey")

#         if not username or not password or not pvtkey:
#             flash("All fields are required.")
#             return redirect(url_for("login"))

#         if not (3 <= len(username) <= 32) or not username.replace('_', '').isalnum():
#             flash("Invalid username. Use 3-32 characters: letters, numbers, and underscores only.")
#             return redirect(url_for("login"))

#         if not (6 <= len(password) <= 32):
#             flash("Invalid password length. Must be 6-32 characters.")
#             return redirect(url_for('login'))

#         if not pvtkey.filename.endswith(".pvt"):
#             flash("Private key file must have .pvt extension.")
#             return redirect(url_for('login'))
        
#         ipfs_conn_status = ipfs_connect(IPFS_URL)

#         if ipfs_conn_status == True:
#             user_access = retrieve_access_control("k51qzi5uqu5dm00522qrtatvmscklsvtyg5sna2q0w7ha0cmsyj7v4qrc9iecg",IPFS_URL, username) 
#             access_control_cid = decrypt_openssl(user_access ,password).decode()
#             try:
#                 access_info = get_document_ipfs_cid(access_control_cid, IPFS_URL)
                
#                 session.permanent = True
#                 session["username"] = access_info.get("username")
#                 session["role"] = access_info.get("role")
#                 print(datetime.now(timezone.utc).isoformat())
#                 session["issued_at"] = datetime.now(timezone.utc).isoformat()
#                 print(datetime.now(timezone.utc) + timedelta(minutes=1))
#                 expiry_time = datetime.now(timezone.utc) + timedelta(minutes=1)
#                 session['expiry'] = expiry_time.timestamp() 
#                 session["page_access"] = access_info.get("pages", [])


#                 if access_info.get("role") == "admin":
#                     return redirect(url_for('admin_dashboard'))
                    
#                 elif access_info.get("role") == "developer":
#                     return redirect(url_for('developer_dashboard'))
#                 elif access_info.get("role") == "qa":
#                     return redirect(url_for('qa_dashboard'))

#             except Exception as msg:
#                 flash(f'{msg.__cause__}')
#                 return redirect(url_for("login"))

                    

#         else:
#             flash("Connection to IPFS API node failed!")

#     return redirect(url_for("login"))



# @app.route("/admin-dashboard", methods=["GET","POST"])
# def admin_dashboard():
#     status = check_session("admin_dashboard.html")
#     if status != True:
#         flash(f"{status}")
#         return redirect(url_for("login"))
#     return render_template("admin_dashboard.html", username=session.get("username"))



# if __name__ == "__main__":
#     app.run(debug=True)
