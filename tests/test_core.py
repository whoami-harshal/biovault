# tests/test_core.py

import sys
import os
import io
import json
import struct
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import zstandard as zstd

from biovault.frames import bytes_to_base4, base4_to_bytes, get_antisense
from biovault.encoder import BioVaultEncoder
from biovault.decoder import BioVaultDecoder
from biovault.packer import pack_sequence, unpack_sequence
from biovault.signing import generate_keypair, load_private_key, sign as ed_sign
from biovault.frames import READING_MODES, get_antisense
from biovault.transform import payload_to_packed, packed_to_payload
from biovault.compression import compress_data
from biovault.crypto import password_to_key, generate_salt, AES_GCM_OVERHEAD

MAGIC = b'BVLT'
FOOTER = b'TLVB'


# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def _quiet(fn, *args, **kwargs):
    """Run something without its progress chatter."""
    buf, real = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        return fn(*args, **kwargs)
    finally:
        sys.stdout = real


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _read_vault(path):
    raw = open(path, 'rb').read()
    meta_len = struct.unpack('>I', raw[5:9])[0]
    meta = json.loads(raw[9:9 + meta_len])
    start = 9 + meta_len
    blob = raw[start:start + sum(l['packed_length'] for l in meta['layers'])]
    return meta, blob


def _write_vault(path, meta, blob, version=None):
    """Rebuild a vault the way an attacker would — recomputing the checksum."""
    if version is None:
        version = meta.get('version', 5)
    meta_bytes = json.dumps(meta).encode()
    with open(path, 'wb') as f:
        f.write(MAGIC)
        f.write(bytes([version]))
        f.write(struct.pack('>I', len(meta_bytes)))
        f.write(meta_bytes)
        f.write(blob)
        f.write(_sha(meta_bytes + blob).encode())
        f.write(bytes([0]))          # no signature
        f.write(FOOTER)


def _cleanup(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


# ─────────────────────────────────────────
# CORE ROUND-TRIP
# ─────────────────────────────────────────

def test_base4_roundtrip():
    """Encode then decode should give same bytes"""
    original = b"Hello BioVault! This is a test."
    encoded = bytes_to_base4(original)
    decoded = base4_to_bytes(encoded)[:len(original)]
    assert decoded == original, f"Roundtrip failed: {decoded} != {original}"
    print("✅ test_base4_roundtrip passed")


def test_antisense():
    """Antisense of antisense should give original"""
    sequence = "ATGCATGC"
    double_antisense = get_antisense(get_antisense(sequence))
    assert double_antisense == sequence
    print("✅ test_antisense passed")


def test_base4_rejects_junk():
    """Non-ATGC input must fail loudly rather than be silently dropped"""
    try:
        base4_to_bytes("ATGXC")
        raise AssertionError("base4_to_bytes accepted a non-ATGC symbol")
    except ValueError:
        pass
    print("✅ test_base4_rejects_junk passed")


def test_full_vault(tmp_path="."):
    """Full encode/decode cycle"""
    data_a0 = b"Secret file A0 content here"
    data_a1 = b"Decoy file A1 content here"
    data_b0 = b"Hidden file B0 content here"

    encoder = BioVaultEncoder()
    encoder.add_layer('A0', 'file_a0.txt', data_a0)
    encoder.add_layer('A1', 'file_a1.txt', data_a1)
    encoder.add_layer('B0', 'file_b0.txt', data_b0)
    encoder.save('test_vault.bvault')

    decoder = BioVaultDecoder('test_vault.bvault')

    decoder.extract('A0', 'out_a0.txt')
    decoder.extract('A1', 'out_a1.txt')
    decoder.extract('B0', 'out_b0.txt')

    assert open('out_a0.txt', 'rb').read() == data_a0
    assert open('out_a1.txt', 'rb').read() == data_a1
    assert open('out_b0.txt', 'rb').read() == data_b0

    print("✅ test_full_vault passed")
    _cleanup('test_vault.bvault', 'out_a0.txt', 'out_a1.txt', 'out_b0.txt')


def test_encrypted_roundtrip():
    """Password layers decrypt with the right password and refuse the wrong one"""
    secret = b"encrypted payload for A0"
    encoder = BioVaultEncoder()
    _quiet(encoder.add_layer, 'A0', 'secret.txt', secret, 'correct-horse')
    _quiet(encoder.save, 'enc_vault.bvault')

    decoder = _quiet(BioVaultDecoder, 'enc_vault.bvault')
    assert _quiet(decoder.extract, 'A0', 'enc_out.bin', password='correct-horse') == secret
    assert _quiet(decoder.extract, 'A0', 'wrong_out.bin', password='nope') is None
    assert not os.path.exists('wrong_out.bin'), "wrong password still wrote output"
    assert _quiet(decoder.extract, 'A0', 'nopw_out.bin') is None

    print("✅ test_encrypted_roundtrip passed")
    _cleanup('enc_vault.bvault', 'enc_out.bin', 'wrong_out.bin', 'nopw_out.bin')


# ─────────────────────────────────────────
# SECURITY REGRESSIONS
# ─────────────────────────────────────────

def test_output_path_never_from_metadata():
    """A crafted vault must not be able to choose where bytes land on disk."""
    encoder = BioVaultEncoder()
    _quiet(encoder.add_layer, 'A0', 'a.txt', b'public data')
    _quiet(encoder.save, 'trav.bvault')

    meta, blob = _read_vault('trav.bvault')
    assert 'filename' not in meta['layers'][0], "encoder stored a filename in metadata"

    # Inject the field anyway, exactly as a malicious vault would.
    meta['layers'][0]['filename'] = '../../PWNED.txt'
    _write_vault('trav.bvault', meta, blob)

    target = os.path.abspath(os.path.join('.', '..', '..', 'PWNED.txt'))
    decoder = _quiet(BioVaultDecoder, 'trav.bvault')
    _quiet(decoder.extract, 'A0')  # no output_path given

    assert not os.path.exists(target), f"path traversal wrote to {target}"
    assert os.path.exists('layer_A0.bin'), "expected the safe generated filename"

    print("✅ test_output_path_never_from_metadata passed")
    _cleanup('trav.bvault', 'layer_A0.bin')


def test_tampered_layer_is_rejected():
    """A checksum mismatch must raise and write nothing, not warn and continue."""
    encoder = BioVaultEncoder()
    _quiet(encoder.add_layer, 'A0', 'a.txt', b'ORIGINAL PUBLIC DATA')
    _quiet(encoder.save, 'tamper.bvault')

    meta, blob = _read_vault('tamper.bvault')
    meta['layers'][0]['checksum'] = 'de' * 32
    _write_vault('tamper.bvault', meta, blob)

    decoder = _quiet(BioVaultDecoder, 'tamper.bvault')
    try:
        _quiet(decoder.extract, 'A0', 'tampered.bin')
        raise AssertionError("tampered layer extracted without error")
    except ValueError:
        pass
    assert not os.path.exists('tampered.bin'), "wrote output despite failed integrity check"

    print("✅ test_tampered_layer_is_rejected passed")
    _cleanup('tamper.bvault', 'tampered.bin')


def test_encrypted_layer_leaks_no_plaintext_fingerprint():
    """Metadata is readable without the password, so it must not fingerprint the plaintext."""
    encoder = BioVaultEncoder()
    _quiet(encoder.add_layer, 'A0', 'payroll.csv', b'SALARY DATA: alice=200000', 'pw')
    _quiet(encoder.save, 'leak.bvault')

    layer = _read_vault('leak.bvault')[0]['layers'][0]
    assert layer.get('checksum') is None, "plaintext hash exposed in metadata"
    assert layer.get('original_size') is None, "plaintext size exposed in metadata"

    print("✅ test_encrypted_layer_leaks_no_plaintext_fingerprint passed")
    _cleanup('leak.bvault')


def test_decompression_bomb_is_capped():
    """A tiny vault must not be able to force a huge allocation."""
    for label, cctx in (
        ("declared size", zstd.ZstdCompressor(level=19)),
        ("hidden size", zstd.ZstdCompressor(level=19, write_content_size=False)),
    ):
        bomb = cctx.compress(b'\x00' * (50 * 1024 * 1024))
        seq = bytes_to_base4(bomb)
        packed = pack_sequence(seq)
        meta = {'version': 4, 'layer_count': 1, 'layers': [{
            'mode': 'A0', 'sequence_length': len(seq), 'payload_length': len(bomb),
            'packed_length': len(packed), 'encrypted': False, 'salt': None,
            'kdf': None, 'checksum': None, 'original_size': None,
        }]}
        _write_vault('bomb.bvault', meta, packed)

        decoder = _quiet(BioVaultDecoder, 'bomb.bvault', max_decompressed=1024 * 1024)
        assert _quiet(decoder.extract, 'A0', 'bomb.bin') is None, f"{label} bomb not blocked"
        assert not os.path.exists('bomb.bin'), f"{label} bomb wrote output"

    print("✅ test_decompression_bomb_is_capped passed")
    _cleanup('bomb.bvault', 'bomb.bin')


def test_malformed_vaults_raise_valueerror():
    """Corrupt input should produce a clean error, not a stray IndexError/KeyError."""
    encoder = BioVaultEncoder()
    _quiet(encoder.add_layer, 'A0', 'a.txt', b'some data')
    _quiet(encoder.save, 'good.bvault')
    raw = open('good.bvault', 'rb').read()

    cases = {
        'empty file': b'',
        'truncated header': raw[:6],
        'truncated body': raw[:len(raw) // 2],
    }
    for label, payload in cases.items():
        open('bad.bvault', 'wb').write(payload)
        try:
            _quiet(BioVaultDecoder, 'bad.bvault')
            raise AssertionError(f"{label}: no error raised")
        except ValueError:
            pass

    meta, blob = _read_vault('good.bvault')
    meta['layers'][0]['mode'] = 'ZZ'
    _write_vault('bad.bvault', meta, blob)
    try:
        _quiet(BioVaultDecoder, 'bad.bvault')
        raise AssertionError("invalid mode: no error raised")
    except ValueError:
        pass

    meta, blob = _read_vault('good.bvault')
    meta['layers'][0]['packed_length'] = -5
    _write_vault('bad.bvault', meta, blob)
    try:
        _quiet(BioVaultDecoder, 'bad.bvault')
        raise AssertionError("negative length: no error raised")
    except ValueError:
        pass

    print("✅ test_malformed_vaults_raise_valueerror passed")
    _cleanup('good.bvault', 'bad.bvault')



def test_packer_is_one_to_one():
    """4 symbols per byte: packed output must match the original byte count."""
    for n in (16, 1000, 50000):
        data = os.urandom(n)
        packed = pack_sequence(bytes_to_base4(data))
        assert len(packed) == n, f"{n} bytes packed to {len(packed)} (expected 1:1)"

    # every remainder class must survive the round trip
    import random
    for n in range(1, 40):
        seq = ''.join(random.choice('ATGC') for _ in range(n))
        assert unpack_sequence(pack_sequence(seq), len(seq)) == seq, f"len {n} failed"

    print("✅ test_packer_is_one_to_one passed")



def test_fast_path_matches_reference():
    """
    transform.py must produce byte-identical output to the readable
    frames.py + packer.py implementation, for every mode and length class.
    """
    def reference_encode(payload, mode):
        base4 = bytes_to_base4(payload)
        body = base4 if mode[0] == 'A' else get_antisense(base4)
        seq = ('A' * int(mode[1])) + body
        return pack_sequence(seq), len(seq)

    checked = 0
    for mode in READING_MODES:
        for n in list(range(0, 24)) + [255, 256, 1000, 4097]:
            payload = os.urandom(n)

            ref = reference_encode(payload, mode)
            fast = payload_to_packed(payload, mode)
            assert ref == fast, f"encode mismatch: mode={mode} n={n}"

            back = packed_to_payload(fast[0], fast[1], mode, n)
            assert back == payload, f"decode mismatch: mode={mode} n={n}"
            checked += 1

    assert checked == len(READING_MODES) * 28
    print(f"✅ test_fast_path_matches_reference passed ({checked} combinations)")


def _make_signed_vault(path, key_path):
    private_pem, public_pem = generate_keypair()
    open(key_path, 'wb').write(private_pem)
    open(key_path + '.pub', 'wb').write(public_pem)

    key = load_private_key(key_path)
    encoder = BioVaultEncoder()
    _quiet(encoder.add_layer, 'A0', 'a.txt', b'signed payload')
    _quiet(encoder.save, path, sign_key=key)
    return key


def test_signature_roundtrip():
    """A signed vault verifies against the key that signed it."""
    from biovault.signing import load_public_key
    key = _make_signed_vault('signed.bvault', 'sk')

    decoder = _quiet(BioVaultDecoder, 'signed.bvault')
    assert decoder.signed, "vault did not record a signature"
    assert decoder.require_signature(load_public_key('sk.pub'))

    print("✅ test_signature_roundtrip passed")
    _cleanup('signed.bvault', 'sk', 'sk.pub')


def test_signature_detects_tampering():
    """Editing the vault and recomputing the checksum must not pass."""
    _make_signed_vault('signed.bvault', 'sk')

    raw = bytearray(open('signed.bvault', 'rb').read())
    meta, blob = _read_vault('signed.bvault')
    meta_bytes = json.dumps(meta).encode()
    start = 9 + len(meta_bytes)

    tampered = bytearray(blob)
    tampered[-2] ^= 0xFF
    body = (MAGIC + bytes([raw[4]]) + struct.pack('>I', len(meta_bytes)) + meta_bytes
            + bytes(tampered) + _sha(meta_bytes + bytes(tampered)).encode())
    trailer = raw[start + len(blob) + 64:-4]        # keep the original signature
    open('signed.bvault', 'wb').write(body + bytes(trailer) + FOOTER)

    try:
        _quiet(BioVaultDecoder, 'signed.bvault')
        raise AssertionError("tampered signed vault loaded without error")
    except ValueError as e:
        assert 'signature' in str(e).lower(), f"unexpected error: {e}"

    print("✅ test_signature_detects_tampering passed")
    _cleanup('signed.bvault', 'sk', 'sk.pub')


def test_signature_wrong_key_rejected():
    """A vault re-signed by someone else must fail against the expected key."""
    from biovault.signing import load_public_key
    _make_signed_vault('signed.bvault', 'sk')
    other_private, other_public = generate_keypair()
    open('other.pub', 'wb').write(other_public)

    decoder = _quiet(BioVaultDecoder, 'signed.bvault')
    try:
        decoder.require_signature(load_public_key('other.pub'))
        raise AssertionError("wrong public key was accepted")
    except ValueError:
        pass

    print("✅ test_signature_wrong_key_rejected passed")
    _cleanup('signed.bvault', 'sk', 'sk.pub', 'other.pub')


def test_unsigned_vault_cannot_be_verified():
    """An unsigned vault must not silently pass verification."""
    from biovault.signing import load_public_key
    _, public_pem = generate_keypair()
    open('lone.pub', 'wb').write(public_pem)

    encoder = BioVaultEncoder()
    _quiet(encoder.add_layer, 'A0', 'a.txt', b'unsigned')
    _quiet(encoder.save, 'plain.bvault')

    decoder = _quiet(BioVaultDecoder, 'plain.bvault')
    assert not decoder.signed
    try:
        decoder.require_signature(load_public_key('lone.pub'))
        raise AssertionError("unsigned vault passed verification")
    except ValueError:
        pass

    print("✅ test_unsigned_vault_cannot_be_verified passed")
    _cleanup('plain.bvault', 'lone.pub')


# ─────────────────────────────────────────
# V5 ENCRYPTION (AES-256-GCM)
# ─────────────────────────────────────────

def _layer_payload(meta, blob, mode):
    """Recover one layer's raw (compressed+encrypted) payload from a vault."""
    offset = 0
    for layer in meta['layers']:
        if layer['mode'] == mode:
            packed = blob[offset:offset + layer['packed_length']]
            return packed_to_payload(packed, layer['sequence_length'], mode,
                                     layer['payload_length'])
        offset += layer['packed_length']
    raise KeyError(mode)


def _encrypted_vault(path, mode='A0', data=b'top secret layer', password='pw'):
    encoder = BioVaultEncoder()
    _quiet(encoder.add_layer, mode, 'secret.txt', data, password)
    _quiet(encoder.save, path)
    return _read_vault(path)


def test_v5_layer_has_no_timestamp_or_base64_overhead():
    """AES-GCM payload = nonce + ciphertext + tag: 28 bytes over compressed size, no Fernet token."""
    data = b'quarterly numbers ' * 200
    meta, blob = _encrypted_vault('gcm.bvault', data=data)
    layer = meta['layers'][0]

    assert meta['version'] == 5
    assert layer['cipher'] == 'aes-256-gcm' and layer['kdf'] == 'scrypt'
    assert layer['payload_length'] == len(compress_data(data)) + AES_GCM_OVERHEAD, \
        "encrypted layer is larger than compressed size + nonce + tag"

    payload = _layer_payload(meta, blob, 'A0')
    assert not payload.startswith(b'gAAAAA'), "layer still looks like a Fernet token"

    # Same data, same password -> different bytes (fresh salt and nonce).
    meta2, blob2 = _encrypted_vault('gcm2.bvault', data=data)
    assert _layer_payload(meta2, blob2, 'A0') != payload

    print("✅ test_v5_layer_has_no_timestamp_or_base64_overhead passed")
    _cleanup('gcm.bvault', 'gcm2.bvault')


def test_encrypted_layer_cannot_be_relabelled():
    """Moving an encrypted layer to another reading key must fail, even unsigned."""
    secret = b'ops credentials: api_key=sk-live-1234'
    meta, blob = _encrypted_vault('relabel.bvault', mode='B0', data=secret)
    payload = _layer_payload(meta, blob, 'B0')

    # Re-encode the identical ciphertext under A1, exactly as an attacker could.
    packed, seq_len = payload_to_packed(payload, 'A1')
    layer = meta['layers'][0]
    layer.update(mode='A1', sequence_length=seq_len, packed_length=len(packed))
    _write_vault('relabel.bvault', meta, packed)

    decoder = _quiet(BioVaultDecoder, 'relabel.bvault')
    out = _quiet(decoder.extract, 'A1', 'relabel_out.bin', password='pw')
    assert out is None, "relabelled layer decrypted under a different reading key"
    assert not os.path.exists('relabel_out.bin')

    print("✅ test_encrypted_layer_cannot_be_relabelled passed")
    _cleanup('relabel.bvault', 'relabel_out.bin')


def test_cipher_and_kdf_downgrade_rejected():
    """A v5 vault cannot be edited to claim Fernet or legacy PBKDF2."""
    for field, value in (('cipher', 'fernet'), ('cipher', None), ('kdf', 'pbkdf2')):
        meta, blob = _encrypted_vault('down.bvault')
        meta['layers'][0][field] = value
        _write_vault('down.bvault', meta, blob)
        try:
            _quiet(BioVaultDecoder, 'down.bvault')
            raise AssertionError(f"{field}={value!r} accepted in a v5 vault")
        except ValueError:
            pass

    print("✅ test_cipher_and_kdf_downgrade_rejected passed")
    _cleanup('down.bvault')


def test_metadata_version_must_match_header():
    meta, blob = _encrypted_vault('mismatch.bvault')
    meta['version'] = 4
    _write_vault('mismatch.bvault', meta, blob, version=5)
    try:
        _quiet(BioVaultDecoder, 'mismatch.bvault')
        raise AssertionError("header/metadata version mismatch accepted")
    except ValueError:
        pass

    print("✅ test_metadata_version_must_match_header passed")
    _cleanup('mismatch.bvault')


def test_legacy_v4_vault_still_opens():
    """Vaults written by v4 (Fernet layers) must still decrypt."""
    from cryptography.fernet import Fernet

    plain = b'public memo from v4'
    secret = b'v4 secret encrypted with Fernet'

    comp_plain = compress_data(plain)
    packed_a0, seq_a0 = payload_to_packed(comp_plain, 'A0')

    salt = generate_salt()
    token = Fernet(password_to_key('pw', salt, 'scrypt')).encrypt(compress_data(secret))
    packed_b0, seq_b0 = payload_to_packed(token, 'B0')

    meta = {'version': 4, 'layer_count': 2, 'layers': [
        {'mode': 'A0', 'sequence_length': seq_a0, 'payload_length': len(comp_plain),
         'packed_length': len(packed_a0), 'encrypted': False, 'salt': None,
         'kdf': None, 'checksum': _sha(plain), 'original_size': len(plain)},
        {'mode': 'B0', 'sequence_length': seq_b0, 'payload_length': len(token),
         'packed_length': len(packed_b0), 'encrypted': True, 'salt': salt.hex(),
         'kdf': 'scrypt', 'checksum': None, 'original_size': None},
    ]}
    _write_vault('legacy.bvault', meta, packed_a0 + packed_b0, version=4)

    decoder = _quiet(BioVaultDecoder, 'legacy.bvault')
    assert decoder.version == 4
    assert _quiet(decoder.extract, 'A0', 'legacy_a0.bin') == plain
    assert _quiet(decoder.extract, 'B0', 'legacy_b0.bin', password='pw') == secret
    assert _quiet(decoder.extract, 'B0', 'legacy_bad.bin', password='nope') is None
    assert not os.path.exists('legacy_bad.bin')

    print("✅ test_legacy_v4_vault_still_opens passed")
    _cleanup('legacy.bvault', 'legacy_a0.bin', 'legacy_b0.bin', 'legacy_bad.bin')


if __name__ == '__main__':
    print("\n🧪 Running BioVault Tests...\n")
    test_base4_roundtrip()
    test_antisense()
    test_base4_rejects_junk()
    test_full_vault()
    test_encrypted_roundtrip()
    test_packer_is_one_to_one()
    test_fast_path_matches_reference()

    print("\n🔒 Security regressions...\n")
    test_output_path_never_from_metadata()
    test_tampered_layer_is_rejected()
    test_encrypted_layer_leaks_no_plaintext_fingerprint()
    test_decompression_bomb_is_capped()
    test_malformed_vaults_raise_valueerror()

    print("\n✍️  Signing...\n")
    test_signature_roundtrip()
    test_signature_detects_tampering()
    test_signature_wrong_key_rejected()
    test_unsigned_vault_cannot_be_verified()

    print("\n🔐 v5 encryption...\n")
    test_v5_layer_has_no_timestamp_or_base64_overhead()
    test_encrypted_layer_cannot_be_relabelled()
    test_cipher_and_kdf_downgrade_rejected()
    test_metadata_version_must_match_header()
    test_legacy_v4_vault_still_opens()

    print("\n🎉 All tests passed!")
