import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_salt():
    return os.urandom(16)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

def generate_master_key():
    return Fernet.generate_key()

def encrypt_master_key(master_key: bytes, password: str, salt: bytes) -> bytes:
    derived_key = derive_key(password, salt)
    f = Fernet(derived_key)
    return f.encrypt(master_key)

def decrypt_master_key(encrypted_master_key: bytes, password: str, salt: bytes) -> bytes:
    derived_key = derive_key(password, salt)
    f = Fernet(derived_key)
    return f.decrypt(encrypted_master_key)

def encrypt_data(data: str, master_key: bytes) -> bytes:
    f = Fernet(master_key)
    return f.encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data: bytes, master_key: bytes) -> str:
    f = Fernet(master_key)
    return f.decrypt(encrypted_data).decode('utf-8')
