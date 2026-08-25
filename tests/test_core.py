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
from biovault.packer import pack_sequence

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


def _write_vault(path, meta, blob, version=3):
    """Rebuild a vault the way an attacker would — recomputing the checksum."""
    meta_bytes = json.dumps(meta).encode()
    with open(path, 'wb') as f:
        f.write(MAGIC)
        f.write(bytes([version]))
        f.write(struct.pack('>I', len(meta_bytes)))
        f.write(meta_bytes)
        f.write(blob)
        f.write(_sha(meta_bytes + blob).encode())
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
        meta = {'version': 3, 'layer_count': 1, 'layers': [{
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


if __name__ == '__main__':
    print("\n🧪 Running BioVault Tests...\n")
    test_base4_roundtrip()
    test_antisense()
    test_base4_rejects_junk()
    test_full_vault()
    test_encrypted_roundtrip()

    print("\n🔒 Security regressions...\n")
    test_output_path_never_from_metadata()
    test_tampered_layer_is_rejected()
    test_encrypted_layer_leaks_no_plaintext_fingerprint()
    test_decompression_bomb_is_capped()
    test_malformed_vaults_raise_valueerror()

    print("\n🎉 All tests passed!")
