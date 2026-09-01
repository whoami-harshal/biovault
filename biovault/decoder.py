# biovault/decoder.py
# V4 — Full pipeline: unpack -> remove frame offset -> base4_to_bytes ->
#       trim to payload_length -> decrypt(if needed) -> decompress
#
# Everything in a vault's metadata is attacker-controlled: the trailing
# checksum is unkeyed, so anyone can edit a vault and recompute it. This
# module therefore treats metadata as untrusted input and validates it
# before use.

import json
import struct
import hashlib
from .frames import READING_MODES
from .transform import packed_to_payload
from .crypto import decrypt_data, DEFAULT_KDF
from .compression import decompress_data, DEFAULT_MAX_DECOMPRESSED
from .signing import verify, fingerprint, SIGNATURE_LEN, PUBLIC_KEY_LEN
from .output import safe_print

MAGIC = b'BVLT'
FOOTER_MAGIC = b'TLVB'
CHECKSUM_HEX_LEN = 64
SUPPORTED_VERSION = 4


def compute_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_exact(f, count: int, what: str) -> bytes:
    data = f.read(count)
    if len(data) != count:
        raise ValueError(f"BioVault file truncated — incomplete {what}")
    return data


def _require_size(layer: dict, field: str, mode: str) -> int:
    value = layer.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"BioVault metadata: layer {mode} has invalid '{field}'")
    return value


class BioVaultDecoder:
    def __init__(self, vault_path: str,
                 max_decompressed: int = DEFAULT_MAX_DECOMPRESSED):
        self.vault_path = vault_path
        self.max_decompressed = max_decompressed
        self.metadata = None
        self.layers_blob = None
        self.signed = False
        self.signature = None
        self.public_key = None
        self._signed_body = None
        self._load()

    def _load(self):
        with open(self.vault_path, 'rb') as f:
            magic = _read_exact(f, 4, 'magic header')
            if magic != MAGIC:
                raise ValueError("Not a valid BioVault file")

            version = _read_exact(f, 1, 'version byte')[0]
            if version < SUPPORTED_VERSION:
                raise ValueError(
                    f"This is a v{version}.x file. This decoder is v{SUPPORTED_VERSION}-only. "
                    f"Re-encode it with the v{SUPPORTED_VERSION} encoder to use this tool."
                )
            if version > SUPPORTED_VERSION:
                raise ValueError(
                    f"This vault is v{version}, newer than this decoder "
                    f"(v{SUPPORTED_VERSION}). Upgrade BioVault to open it."
                )

            meta_length = struct.unpack('>I', _read_exact(f, 4, 'metadata length'))[0]
            meta_bytes = _read_exact(f, meta_length, 'metadata')

            try:
                self.metadata = json.loads(meta_bytes.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise ValueError(f"BioVault metadata is unreadable — {e}")

            self._validate_metadata()

            blob_length = sum(l['packed_length'] for l in self.metadata['layers'])
            self.layers_blob = _read_exact(f, blob_length, 'layer data')

            stored = _read_exact(f, CHECKSUM_HEX_LEN, 'checksum')
            stored_checksum = stored.decode('ascii', 'replace')

            # Signature trailer: 1 flag byte, then key + signature when present.
            sig_flag = _read_exact(f, 1, 'signature flag')[0]
            if sig_flag == 1:
                self.public_key = _read_exact(f, PUBLIC_KEY_LEN, 'public key')
                self.signature = _read_exact(f, SIGNATURE_LEN, 'signature')
                self.signed = True
            elif sig_flag != 0:
                raise ValueError("BioVault file corrupted — bad signature flag")

            footer = _read_exact(f, 4, 'footer')
            if footer != FOOTER_MAGIC:
                raise ValueError("BioVault file corrupted — invalid footer")

            computed = compute_checksum(meta_bytes + self.layers_blob)
            if computed != stored_checksum:
                raise ValueError("BioVault file corrupted — checksum mismatch")

            self._signed_body = (
                MAGIC + bytes([version]) + struct.pack('>I', meta_length)
                + meta_bytes + self.layers_blob + stored
            )

        if self.signed and not verify(self.public_key, self.signature, self._signed_body):
            raise ValueError(
                "BioVault signature is invalid — the file has been modified "
                "since it was signed"
            )

        safe_print(f"✅ BioVault loaded: {self.vault_path}")
        safe_print(f"   Version: {self.metadata['version']}")
        safe_print(f"   Layers: {self.metadata['layer_count']}")
        if self.signed:
            safe_print(f"   Signed by: {fingerprint(self.public_key)} (identity not yet checked)")

    def _validate_metadata(self):
        """Reject malformed metadata up front so later code can trust its shape."""
        meta = self.metadata
        if not isinstance(meta, dict):
            raise ValueError("BioVault metadata is not an object")

        layers = meta.get('layers')
        if not isinstance(layers, list) or not layers:
            raise ValueError("BioVault metadata contains no layers")
        if len(layers) > len(READING_MODES):
            raise ValueError(
                f"BioVault metadata declares {len(layers)} layers "
                f"(maximum is {len(READING_MODES)})"
            )

        seen = set()
        for layer in layers:
            if not isinstance(layer, dict):
                raise ValueError("BioVault metadata layer is not an object")

            mode = layer.get('mode')
            if mode not in READING_MODES:
                raise ValueError(f"BioVault metadata has unknown reading mode {mode!r}")
            if mode in seen:
                raise ValueError(f"BioVault metadata repeats reading mode {mode!r}")
            seen.add(mode)

            for field in ('sequence_length', 'payload_length', 'packed_length'):
                _require_size(layer, field, mode)

            if layer.get('encrypted'):
                salt = layer.get('salt')
                if not isinstance(salt, str):
                    raise ValueError(
                        f"BioVault metadata: layer {mode} is encrypted but has no salt"
                    )
                try:
                    bytes.fromhex(salt)
                except ValueError:
                    raise ValueError(
                        f"BioVault metadata: layer {mode} has a malformed salt"
                    )

        meta['layer_count'] = len(layers)

    def info(self):
        safe_print(f"\n📋 BioVault Info: {self.vault_path}")
        safe_print(f"   Version: {self.metadata['version']}")
        safe_print(f"   Total layers: {self.metadata['layer_count']}")
        keys = [l['mode'] for l in self.metadata['layers']]
        encrypted_keys = [l['mode'] for l in self.metadata['layers'] if l['encrypted']]
        safe_print(f"   Available keys: {keys}")
        safe_print(f"   Encrypted layers: {encrypted_keys if encrypted_keys else 'none'}")
        if self.signed:
            safe_print(f"   Signature: present, key {fingerprint(self.public_key)}")
            safe_print(f"              (run 'verify --key <file>' to confirm who signed it)")
        else:
            safe_print(f"   Signature: none — authenticity cannot be verified")
        safe_print()

    def require_signature(self, expected_public_key: bytes) -> bool:
        """
        Confirm this vault was signed by the holder of expected_public_key.

        Loading already rejects a signature that does not match the file's own
        embedded key, but that only proves internal consistency — an attacker
        can re-sign a modified vault with their own key. Checking against a key
        the caller supplies out of band is what actually proves authorship.
        """
        if not self.signed:
            raise ValueError(
                "This vault is not signed — its authenticity cannot be verified"
            )
        if self.public_key != expected_public_key:
            raise ValueError(
                "Vault was signed by a different key than expected.\n"
                f"    expected: {fingerprint(expected_public_key)}\n"
                f"    found:    {fingerprint(self.public_key)}"
            )
        if not verify(self.public_key, self.signature, self._signed_body):
            raise ValueError("Signature is invalid — the file has been modified")
        return True

    def layer_meta(self, mode: str):
        """Metadata for one reading mode, or None if the vault has no such layer."""
        for layer in self.metadata['layers']:
            if layer['mode'] == mode:
                return layer
        return None

    def extract(self, mode: str, output_path: str = None, password: str = None) -> bytes:
        if not isinstance(mode, str) or mode.upper() not in READING_MODES:
            raise ValueError(f"Invalid mode {mode!r}. Valid: {list(READING_MODES.keys())}")
        mode = mode.upper()

        layer_meta = None
        offset = 0
        for layer in self.metadata['layers']:
            if layer['mode'] == mode:
                layer_meta = layer
                break
            offset += layer['packed_length']

        if layer_meta is None:
            raise ValueError(f"Mode '{mode}' not found in vault")

        safe_print(f"\n🔓 Extracting layer {mode}...")

        # ── Pull this layer's packed bytes out of the blob ──
        packed = self.layers_blob[offset: offset + layer_meta['packed_length']]

        # ── Undo frame offset, strand, and packing in one pass ──
        payload = packed_to_payload(
            packed,
            layer_meta['sequence_length'],
            mode,
            layer_meta['payload_length'],
        )

        # ── Decrypt if this layer was encrypted ──
        if layer_meta.get('encrypted'):
            if not password:
                safe_print(f"  ❌ Layer {mode} is encrypted — password required")
                return None
            salt = bytes.fromhex(layer_meta['salt'])
            kdf = layer_meta.get('kdf') or DEFAULT_KDF
            decrypted = decrypt_data(payload, password, salt, kdf)
            if decrypted is None:
                safe_print(f"  ⚠️  Wrong password — nothing recovered")
                return None
            payload = decrypted

        # ── Decompress, bounded ──
        # original_size is untrusted, so it may only tighten the cap, never raise it.
        declared = layer_meta.get('original_size')
        has_declared = isinstance(declared, int) and not isinstance(declared, bool) and declared >= 0

        limit = self.max_decompressed
        if has_declared and declared < limit:
            limit = declared

        try:
            extracted = decompress_data(payload, max_output_size=limit)
        except Exception as e:
            safe_print(f"  ⚠️  Decompression failed — wrong password or corrupted data ({e})")
            return None

        if has_declared:
            extracted = extracted[:declared]

        # ── Verify BEFORE writing anything ──
        expected = layer_meta.get('checksum')
        if expected:
            if compute_checksum(extracted) != expected:
                raise ValueError(
                    f"Layer {mode} failed its integrity check — refusing to write output. "
                    f"The vault is corrupted or has been tampered with."
                )
            safe_print(f"  ✅ Checksum verified")
        elif layer_meta.get('encrypted'):
            # Fernet already authenticated this layer during decrypt.
            safe_print(f"  ✅ Authenticated on decrypt (HMAC-SHA256)")

        # The output path is never taken from vault metadata — a crafted vault
        # would otherwise choose where these bytes land on disk.
        if output_path is None:
            output_path = f'layer_{mode}.bin'

        with open(output_path, 'wb') as f:
            f.write(extracted)

        safe_print(f"  ✅ Extracted: {output_path} ({len(extracted):,} bytes)")
        return extracted
