# biovault/crypto.py
# Password-based encryption for BioVault

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def password_to_key(password: str, salt: bytes) -> bytes:
    """Password + Salt → Encryption Key"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def generate_salt() -> bytes:
    return os.urandom(16)


def encrypt_data(data: bytes, password: str) -> tuple[bytes, bytes]:
    """Returns (encrypted_data, salt)"""
    salt = generate_salt()
    key = password_to_key(password, salt)
    f = Fernet(key)
    return f.encrypt(data), salt


def decrypt_data(encrypted: bytes, password: str, salt: bytes) -> bytes:
    """Wrong password → returns None (no crash, no error)"""
    try:
        key = password_to_key(password, salt)
        f = Fernet(key)
        return f.decrypt(encrypted)
    except Exception:
        return None