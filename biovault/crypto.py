# biovault/crypto.py
# Password-based encryption for BioVault
#
# Fernet is AES-128-CBC + HMAC-SHA256: it splits the 32-byte key it is given
# into a 16-byte signing key and a 16-byte AES key. It is *authenticated*,
# so a wrong password or a tampered ciphertext fails on decrypt — no separate
# plaintext checksum is needed to detect either.

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet

# scrypt is memory-hard, so GPU and ASIC cracking gain far less against it
# than against PBKDF2. n=2**15 with r=8 costs roughly 32 MiB per guess.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

# Legacy vaults only. OWASP's floor for PBKDF2-HMAC-SHA256 is 600,000
# iterations; vaults written before the scrypt switch used 100,000, and
# still need to open.
PBKDF2_LEGACY_ITERATIONS = 100_000

DEFAULT_KDF = 'scrypt'


def password_to_key(password: str, salt: bytes, kdf: str = DEFAULT_KDF) -> bytes:
    """Password + salt -> 32-byte Fernet key"""
    if kdf == 'scrypt':
        derived = Scrypt(
            salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
        ).derive(password.encode())
    elif kdf == 'pbkdf2':
        derived = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_LEGACY_ITERATIONS,
        ).derive(password.encode())
    else:
        raise ValueError(f"Unknown KDF: {kdf!r}")

    return base64.urlsafe_b64encode(derived)


def generate_salt() -> bytes:
    return os.urandom(16)


def encrypt_data(data: bytes, password: str) -> tuple[bytes, bytes, str]:
    """Returns (encrypted_data, salt, kdf_name)"""
    salt = generate_salt()
    key = password_to_key(password, salt, DEFAULT_KDF)
    f = Fernet(key)
    return f.encrypt(data), salt, DEFAULT_KDF


def decrypt_data(encrypted: bytes, password: str, salt: bytes,
                 kdf: str = DEFAULT_KDF) -> bytes:
    """Wrong password or tampered ciphertext -> returns None (no crash, no error)"""
    try:
        key = password_to_key(password, salt, kdf)
        f = Fernet(key)
        return f.decrypt(encrypted)
    except Exception:
        return None
