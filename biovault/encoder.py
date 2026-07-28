# biovault/encoder.py
# V2.0 — Full pipeline: compress -> encrypt(optional) -> base4 -> pack

import os
import json
import struct
import hashlib
from .frames import bytes_to_base4, get_antisense, READING_MODES
from .crypto import encrypt_data
from .compression import compress_data
from .packer import pack_sequence

MAGIC = b'BVLT'
VERSION = 2
FOOTER_MAGIC = b'TLVB'


def compute_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def encode_layer(data: bytes, mode: str, password: str = None):
    """
    Full v2 pipeline for one layer.
    data -> compress -> encrypt(if password) -> base4 -> frame offset -> pack

    Returns: (packed_bytes, sequence_length, payload_length, encrypted, salt)
    """
    compressed = compress_data(data)

    salt = None
    encrypted = False
    payload = compressed

    if password:
        payload, salt = encrypt_data(compressed, password)
        encrypted = True

    payload_length = len(payload)  # exact byte length — needed to trim padding later

    base4 = bytes_to_base4(payload)
    mode_type = mode[0]
    frame_num = int(mode[1])

    if mode_type == 'A':
        sequence = ('A' * frame_num) + base4
    else:
        sequence = ('A' * frame_num) + get_antisense(base4)

    packed = pack_sequence(sequence)
    return packed, len(sequence), payload_length, encrypted, salt


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
        print(f"  Layer {mode} queued: {filename} ({len(data):,} bytes) [{tag}]")

    def save(self, output_path: str):
        if not self.layers:
            raise ValueError("No layers added. Use add_layer() first.")
        if not output_path.endswith('.bvault'):
            output_path += '.bvault'

        print(f"\n🧬 Building BioVault v{VERSION}: {output_path}")

        metadata = {'version': VERSION, 'layer_count': len(self.layers), 'layers': []}
        packed_blobs = []

        for mode, filename, data, password in self.layers:
            print(f"  🔄 Encoding layer {mode}...")
            packed, seq_len, payload_len, encrypted, salt = encode_layer(data, mode, password)
            checksum = compute_checksum(data)

            metadata['layers'].append({
                'mode': mode,
                'filename': filename,
                'original_size': len(data),
                'sequence_length': seq_len,     # ATGC symbol count (for unpacking)
                'payload_length': payload_len,  # exact compressed(+encrypted) byte length
                'packed_length': len(packed),   # bytes this layer occupies in the blob
                'checksum': checksum,
                'encrypted': encrypted,
                'salt': salt.hex() if salt else None
            })
            packed_blobs.append(packed)

        layers_blob = b''.join(packed_blobs)
        meta_bytes = json.dumps(metadata).encode('utf-8')
        meta_length = struct.pack('>I', len(meta_bytes))
        final_checksum = compute_checksum(meta_bytes + layers_blob).encode()

        with open(output_path, 'wb') as f:
            f.write(MAGIC)
            f.write(bytes([VERSION]))
            f.write(meta_length)
            f.write(meta_bytes)
            f.write(layers_blob)
            f.write(final_checksum)
            f.write(FOOTER_MAGIC)

        original_total = sum(len(d) for _, _, d, _ in self.layers)
        file_size = os.path.getsize(output_path)
        ratio = file_size / original_total if original_total else 0

        print(f"\n✅ BioVault created: {output_path}")
        print(f"   Layers: {len(self.layers)}")
        print(f"   Original total: {original_total:,} bytes")
        print(f"   Vault size:     {file_size:,} bytes  ({ratio:.2f}x original)")
        print(f"   Keys: {[l[0] for l in self.layers]}")
