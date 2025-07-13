import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def openssl_key_iv_gen(password, salt, key_len=32, iv_len=16):
    """
    Mimics OpenSSL's EVP_BytesToKey with MD5.
    Only needed for files not using -pbkdf2.
    """
    d = d_i = b''
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len+iv_len]

def decrypt_openssl(enc_b64, password):
    data = base64.b64decode(enc_b64)
    assert data[:8] == b"Salted__", "Missing OpenSSL salt header"
    salt = data[8:16]
    ciphertext = data[16:]

    # PBKDF2 (OpenSSL defaults: 10000 iterations, sha256, 32 byte key + 16 byte IV)
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,  # 32 bytes key + 16 bytes IV
        salt=salt,
        iterations=10000,  # OpenSSL default for -pbkdf2
        backend=default_backend()
    )
    key_iv = kdf.derive(password.encode())
    key = key_iv[:32]
    iv = key_iv[32:]

    # AES decryption (CBC)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    pad_len = padded_plain[-1]
    return padded_plain[:-pad_len]