# biovault/crypto.py
# Password-based encryption for BioVault
#
# v5 layers use AES-256-GCM directly:
#
#     payload = nonce (12 bytes) || ciphertext || tag (16 bytes)
#
# with a 32-byte key from scrypt. GCM is authenticated, so a wrong password or
# a tampered ciphertext fails on decrypt — no plaintext checksum is needed to
# detect either. Each layer's identity (format version, reading mode, KDF,
# cipher and salt) is bound in as associated data, so an encrypted layer cannot
# be relabelled as a different reading key without failing authentication.
#
# v4 layers used Fernet (AES-128-CBC + HMAC-SHA256). Fernet was replaced
# because its token format:
#   - stores the encryption time as a cleartext 8-byte timestamp,
#   - is base64 text, inflating every encrypted layer by roughly 40%,
#   - always begins with the bytes "gAAAAA", identifying the cipher,
#   - uses AES-128 (it splits its 32-byte key into two 16-byte halves).
# Fernet decryption is kept so existing v4 vaults still open.

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet

# scrypt is memory-hard, so GPU and ASIC cracking gain far less against it
# than against PBKDF2. n=2**15 with r=8 costs roughly 32 MiB per guess.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

# Legacy v4 vaults only. OWASP's floor for PBKDF2-HMAC-SHA256 is 600,000
# iterations; vaults written before the scrypt switch used 100,000, and
# still need to open.
PBKDF2_LEGACY_ITERATIONS = 100_000

DEFAULT_KDF = 'scrypt'

CIPHER_AES_GCM = 'aes-256-gcm'
CIPHER_FERNET = 'fernet'          # v4, decrypt only
DEFAULT_CIPHER = CIPHER_AES_GCM

SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16

# Bytes an encrypted v5 layer adds on top of its compressed size.
AES_GCM_OVERHEAD = NONCE_LEN + TAG_LEN


def _derive(password: str, salt: bytes, kdf: str) -> bytes:
    """Password + salt -> 32 raw key bytes."""
    if kdf == 'scrypt':
        return Scrypt(
            salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
        ).derive(password.encode())
    if kdf == 'pbkdf2':
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_LEGACY_ITERATIONS,
        ).derive(password.encode())
    raise ValueError(f"Unknown KDF: {kdf!r}")


def password_to_key(password: str, salt: bytes, kdf: str = DEFAULT_KDF) -> bytes:
    """Password + salt -> base64 Fernet key. Kept for v4 compatibility."""
    return base64.urlsafe_b64encode(_derive(password, salt, kdf))


def generate_salt() -> bytes:
    return os.urandom(SALT_LEN)


def layer_aad(version: int, mode: str, kdf: str, cipher: str, salt: bytes) -> bytes:
    """
    Associated data binding an encrypted layer to its own metadata.

    Changing any of these fields in the vault — most importantly the reading
    mode — makes decryption fail, even in an unsigned vault.
    """
    return f"BioVault/v{version}/layer/{mode}/{kdf}/{cipher}/".encode('ascii') + salt


def encrypt_data(data: bytes, password: str, aad: bytes = b'',
                 salt: bytes = None) -> tuple[bytes, bytes, str]:
    """
    Encrypt with AES-256-GCM. Returns (payload, salt, kdf_name), where
    payload is nonce || ciphertext || tag.
    """
    if salt is None:
        salt = generate_salt()
    key = _derive(password, salt, DEFAULT_KDF)
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, data, aad), salt, DEFAULT_KDF


def decrypt_data(encrypted: bytes, password: str, salt: bytes,
                 kdf: str = DEFAULT_KDF, cipher: str = DEFAULT_CIPHER,
                 aad: bytes = b'') -> bytes:
    """Wrong password or tampered ciphertext -> returns None (no crash, no error)"""
    try:
        if cipher == CIPHER_AES_GCM:
            if len(encrypted) < AES_GCM_OVERHEAD:
                return None
            key = _derive(password, salt, kdf)
            nonce, body = encrypted[:NONCE_LEN], encrypted[NONCE_LEN:]
            return AESGCM(key).decrypt(nonce, body, aad)
        if cipher == CIPHER_FERNET:
            return Fernet(password_to_key(password, salt, kdf)).decrypt(encrypted)
        return None
    except Exception:
        return None
