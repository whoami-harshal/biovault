# tests/test_core.py

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from biovault.frames import bytes_to_base4, base4_to_bytes, get_antisense
from biovault.encoder import BioVaultEncoder
from biovault.decoder import BioVaultDecoder

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

def test_full_vault(tmp_path="."):
    """Full encode/decode cycle"""
    # Create test data
    data_a0 = b"Secret file A0 content here"
    data_a1 = b"Decoy file A1 content here"
    data_b0 = b"Hidden file B0 content here"

    # Encode
    encoder = BioVaultEncoder()
    encoder.add_layer('A0', 'file_a0.txt', data_a0)
    encoder.add_layer('A1', 'file_a1.txt', data_a1)
    encoder.add_layer('B0', 'file_b0.txt', data_b0)
    encoder.save('test_vault.bvault')

    # Decode
    decoder = BioVaultDecoder('test_vault.bvault')

    decoder.extract('A0', 'out_a0.txt')
    decoder.extract('A1', 'out_a1.txt')
    decoder.extract('B0', 'out_b0.txt')

    assert open('out_a0.txt', 'rb').read() == data_a0
    assert open('out_a1.txt', 'rb').read() == data_a1
    assert open('out_b0.txt', 'rb').read() == data_b0

    print("✅ test_full_vault passed")

    # Cleanup
    for f in ['test_vault.bvault', 'out_a0.txt', 'out_a1.txt', 'out_b0.txt']:
        try: os.remove(f)
        except: pass

if __name__ == '__main__':
    print("\n🧪 Running BioVault Tests...\n")
    test_base4_roundtrip()
    test_antisense()
    test_full_vault()
    print("\n🎉 All tests passed!")