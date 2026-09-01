# biovault/encoder.py
# V4 — Full pipeline: compress -> encrypt(optional) -> base4 -> pack

import os
import json
import struct
import hashlib
from .frames import READING_MODES
from .transform import payload_to_packed
from .crypto import encrypt_data
from .compression import compress_data
from .signing import sign, SIGNATURE_LEN, PUBLIC_KEY_LEN, fingerprint
from .output import safe_print

MAGIC = b'BVLT'
VERSION = 4
FOOTER_MAGIC = b'TLVB'

# Full SHA-256, not truncated. The old 64-bit prefix was birthday-weak, and
# this checksum is unkeyed anyway, so there is no reason to spend collision
# resistance to save 48 bytes.
CHECKSUM_HEX_LEN = 64


def compute_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_layer(data: bytes, mode: str, password: str = None):
    """
    Full pipeline for one layer.
    data -> compress -> encrypt(if password) -> base4 -> frame offset -> pack

    Returns: (packed_bytes, sequence_length, payload_length, encrypted, salt, kdf)
    """
    compressed = compress_data(data)

    salt = None
    kdf = None
    encrypted = False
    payload = compressed

    if password:
        payload, salt, kdf = encrypt_data(compressed, password)
        encrypted = True

    payload_length = len(payload)  # exact byte length — needed to trim padding later

    packed, sequence_length = payload_to_packed(payload, mode)
    return packed, sequence_length, payload_length, encrypted, salt, kdf


class BioVaultEncoder:
    def __init__(self):
        self.layers = []  # (mode, filename, data, password)

    def add_layer(self, mode: str, filename: str, data: bytes, password: str = None):
        if mode not in READING_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Valid: {list(READING_MODES.keys())}")

        existing = [l[0] for l in self.layers]
        if mode in existing:
            raise ValueError(f"Mode '{mode}' already used. Each layer needs a unique mode.")

        self.layers.append((mode, filename, data, password))
        tag = "🔐 encrypted" if password else "plain"
        safe_print(f"  Layer {mode} queued: {filename} ({len(data):,} bytes) [{tag}]")

    def save(self, output_path: str, sign_key=None):
        if not self.layers:
            raise ValueError("No layers added. Use add_layer() first.")
        if not output_path.endswith('.bvault'):
            output_path += '.bvault'

        safe_print(f"\n🧬 Building BioVault v{VERSION}: {output_path}")

        metadata = {'version': VERSION, 'layer_count': len(self.layers), 'layers': []}
        packed_blobs = []

        for mode, filename, data, password in self.layers:
            safe_print(f"  🔄 Encoding layer {mode}...")
            packed, seq_len, payload_len, encrypted, salt, kdf = encode_layer(data, mode, password)

            layer_meta = {
                'mode': mode,
                'sequence_length': seq_len,     # ATGC symbol count (for unpacking)
                'payload_length': payload_len,  # exact compressed(+encrypted) byte length
                'packed_length': len(packed),   # bytes this layer occupies in the blob
                'encrypted': encrypted,
                'salt': salt.hex() if salt else None,
                'kdf': kdf,
            }

            if encrypted:
                # Deliberately absent for encrypted layers: metadata is
                # readable without the password, so a plaintext hash would let
                # anyone confirm a guessed plaintext, and the exact plaintext
                # size is itself a leak. Fernet's HMAC already authenticates
                # the layer when it is decrypted.
                layer_meta['checksum'] = None
                layer_meta['original_size'] = None
            else:
                layer_meta['checksum'] = compute_checksum(data)
                layer_meta['original_size'] = len(data)

            # No 'filename' field: the decoder must never take an output path
            # from the file it is reading.
            metadata['layers'].append(layer_meta)
            packed_blobs.append(packed)

        layers_blob = b''.join(packed_blobs)
        meta_bytes = json.dumps(metadata).encode('utf-8')
        meta_length = struct.pack('>I', len(meta_bytes))
        final_checksum = compute_checksum(meta_bytes + layers_blob).encode()

        # Everything the signature covers, assembled first.
        body = MAGIC + bytes([VERSION]) + meta_length + meta_bytes + layers_blob + final_checksum

        if sign_key is not None:
            signature, raw_pub = sign(sign_key, body)
            trailer = bytes([1]) + raw_pub + signature
        else:
            trailer = bytes([0])

        with open(output_path, 'wb') as f:
            f.write(body)
            f.write(trailer)
            f.write(FOOTER_MAGIC)

        original_total = sum(len(d) for _, _, d, _ in self.layers)
        file_size = os.path.getsize(output_path)
        ratio = file_size / original_total if original_total else 0

        safe_print(f"\n✅ BioVault created: {output_path}")
        safe_print(f"   Layers: {len(self.layers)}")
        safe_print(f"   Original total: {original_total:,} bytes")
        safe_print(f"   Vault size:     {file_size:,} bytes  ({ratio:.2f}x original)")
        safe_print(f"   Keys: {[l[0] for l in self.layers]}")
        if sign_key is not None:
            safe_print(f"   Signed by: {fingerprint(sign_key.public_key().public_bytes_raw())}")
