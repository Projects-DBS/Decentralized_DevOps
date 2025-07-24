import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



def decrypt_openssl(enc_b64, password):
    data = base64.b64decode(enc_b64)
    assert data[:8] == b"Salted__", "Missing OpenSSL salt header"
    salt = data[8:16]
    ciphertext = data[16:]

    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,
        salt=salt,
        iterations=10000,
        backend=default_backend()
    )
    key_iv = kdf.derive(password.encode())
    key = key_iv[:32]
    iv = key_iv[32:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    pad_len = padded_plain[-1]
    return padded_plain[:-pad_len]
