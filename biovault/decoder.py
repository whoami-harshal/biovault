# biovault/decoder.py
# V2.0 — Full pipeline: unpack -> remove frame offset -> base4_to_bytes ->
#         trim to payload_length -> decrypt(if needed) -> decompress

import json
import struct
import hashlib
from .frames import base4_to_bytes, get_antisense
from .crypto import decrypt_data
from .compression import decompress_data
from .packer import unpack_sequence

MAGIC = b'BVLT'
FOOTER_MAGIC = b'TLVB'


def compute_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


class BioVaultDecoder:
    def __init__(self, vault_path: str):
        self.vault_path = vault_path
        self.metadata = None
        self.layers_blob = None
        self._load()

    def _load(self):
        with open(self.vault_path, 'rb') as f:
            magic = f.read(4)
            if magic != MAGIC:
                raise ValueError("Not a valid BioVault file")

            version = f.read(1)[0]
            if version == 1:
                raise ValueError(
                    "This is a v1.x file. This decoder is v2-only. "
                    "Re-encode it with the v2 encoder to use this tool."
                )

            meta_length = struct.unpack('>I', f.read(4))[0]
            meta_bytes = f.read(meta_length)
            self.metadata = json.loads(meta_bytes.decode('utf-8'))

            blob_length = sum(l['packed_length'] for l in self.metadata['layers'])
            self.layers_blob = f.read(blob_length)

            stored_checksum = f.read(16).decode()
            footer = f.read(4)
            if footer != FOOTER_MAGIC:
                raise ValueError("BioVault file corrupted — invalid footer")

            computed = compute_checksum(meta_bytes + self.layers_blob)
            if computed != stored_checksum:
                raise ValueError("BioVault file corrupted — checksum mismatch")

        print(f"✅ BioVault loaded: {self.vault_path}")
        print(f"   Version: {self.metadata['version']}")
        print(f"   Layers: {self.metadata['layer_count']}")

    def info(self):
        print(f"\n📋 BioVault Info: {self.vault_path}")
        print(f"   Version: {self.metadata['version']}")
        print(f"   Total layers: {self.metadata['layer_count']}")
        keys = [l['mode'] for l in self.metadata['layers']]
        encrypted_keys = [l['mode'] for l in self.metadata['layers'] if l['encrypted']]
        print(f"   Available keys: {keys}")
        print(f"   Encrypted layers: {encrypted_keys if encrypted_keys else 'none'}")
        print()

    def extract(self, mode: str, output_path: str = None, password: str = None) -> bytes:
        layer_meta = None
        offset = 0
        for layer in self.metadata['layers']:
            if layer['mode'] == mode:
                layer_meta = layer
                break
            offset += layer['packed_length']

        if layer_meta is None:
            raise ValueError(f"Mode '{mode}' not found in vault")

        print(f"\n🔓 Extracting layer {mode}...")

        # ── Pull this layer's packed bytes out of the blob ──
        packed = self.layers_blob[offset: offset + layer_meta['packed_length']]
        sequence = unpack_sequence(packed, layer_meta['sequence_length'])

        # ── Remove frame offset ──
        mode_type = mode[0]
        frame_num = int(mode[1])
        if mode_type == 'A':
            clean_sequence = sequence[frame_num:]
        else:
            clean_sequence = get_antisense(sequence[frame_num:])

        # ── Back to bytes, trimmed to exact payload length ──
        payload = base4_to_bytes(clean_sequence)[:layer_meta['payload_length']]

        # ── Decrypt if this layer was encrypted ──
        if layer_meta.get('encrypted'):
            if not password:
                print(f"  ❌ Layer {mode} is encrypted — password required")
                return None
            salt = bytes.fromhex(layer_meta['salt'])
            decrypted = decrypt_data(payload, password, salt)
            if decrypted is None:
                print(f"  ⚠️  Wrong password — nothing recovered")
                return None
            payload = decrypted

        # ── Decompress ──
        try:
            extracted = decompress_data(payload)
        except Exception:
            print(f"  ⚠️  Decompression failed — wrong password or corrupted data")
            return None

        extracted = extracted[:layer_meta['original_size']]

        # ── Verify ──
        computed = compute_checksum(extracted)
        if computed != layer_meta['checksum']:
            print(f"  ⚠️  Checksum mismatch — data may be corrupted")
        else:
            print(f"  ✅ Checksum verified")

        if output_path is None:
            output_path = layer_meta['filename']

        with open(output_path, 'wb') as f:
            f.write(extracted)

        print(f"  ✅ Extracted: {output_path} ({len(extracted):,} bytes)")
        return extracted
