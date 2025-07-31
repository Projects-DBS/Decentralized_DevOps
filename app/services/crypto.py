import subprocess

def decrypt_openssl_subprocess(enc_b64_content, password):
    cmd = ["openssl", "enc", "-d", "-aes-256-cbc", "-a", "-salt", "-pbkdf2", "-pass", f"pass:{password}"]
    result = subprocess.run(cmd, input=enc_b64_content.encode(), capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode().strip())
    return result.stdout.decode('utf-8')

