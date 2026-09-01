# biovault/signing.py
# V4 — Ed25519 signing for whole-vault authenticity
#
# The container checksum is a plain SHA-256: it catches corruption, but anyone
# can edit a vault and recompute it. A signature closes that gap — only the
# holder of the private key can produce one, and anyone with the public key can
# verify it without holding any secret.
#
# The public key is embedded in the vault for convenience (so `info` can show a
# fingerprint), but that alone proves nothing: an attacker can re-sign a
# modified vault with their own key and swap the embedded public key too. Real
# verification requires the caller to supply the public key they expect, which
# is why `--verify` takes a key file.

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

SIGNATURE_LEN = 64      # Ed25519 signature
PUBLIC_KEY_LEN = 32     # Ed25519 raw public key


def generate_keypair(password: str = None) -> tuple[bytes, bytes]:
    """
    Create a new signing keypair.
    Returns (private_pem, public_pem). A password encrypts the private key.
    """
    private_key = Ed25519PrivateKey.generate()

    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        encryption = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_private_key(path: str, password: str = None) -> Ed25519PrivateKey:
    with open(path, 'rb') as f:
        data = f.read()
    key = serialization.load_pem_private_key(
        data, password=password.encode() if password else None
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: str) -> bytes:
    """Load a public key file and return its raw 32 bytes."""
    with open(path, 'rb') as f:
        data = f.read()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return public_key_raw(key)


def public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign(private_key: Ed25519PrivateKey, message: bytes) -> tuple[bytes, bytes]:
    """Returns (signature, raw_public_key)."""
    signature = private_key.sign(message)
    return signature, public_key_raw(private_key.public_key())


def verify(raw_public_key: bytes, signature: bytes, message: bytes) -> bool:
    """True if the signature is valid for this message under this key."""
    try:
        Ed25519PublicKey.from_public_bytes(raw_public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def fingerprint(raw_public_key: bytes) -> str:
    """Short human-comparable id for a public key."""
    digest = hashlib.sha256(raw_public_key).hexdigest()
    return ':'.join(digest[i:i + 4] for i in range(0, 16, 4))
