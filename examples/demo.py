# examples/demo.py
# BioVault demo — 3 files in 1 vault

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from biovault import BioVaultEncoder, BioVaultDecoder

print("=" * 50)
print("🧬 BioVault Demo")
print("=" * 50)

#  Create test files 
print("\n📝 Creating test files...")

with open("secret_message.txt", "wb") as f:
    f.write(b"This is TOP SECRET. Only key A0 reveals this.")

with open("decoy_file.txt", "wb") as f:
    f.write(b"Nothing secret here. Just a normal text file.")

with open("hidden_note.txt", "wb") as f:
    f.write(b"Third hidden layer. Only key B0 can find this.")

print("  ✅ secret_message.txt created")
print("  ✅ decoy_file.txt created")
print("  ✅ hidden_note.txt created")

# Encode into single vault 
print("\n🔒 Encoding 3 files into 1 vault...")
encoder = BioVaultEncoder()
encoder.add_layer('A0', 'secret_message.txt', open('secret_message.txt', 'rb').read())
encoder.add_layer('A1', 'decoy_file.txt',     open('decoy_file.txt', 'rb').read())
encoder.add_layer('B0', 'hidden_note.txt',    open('hidden_note.txt', 'rb').read())
encoder.save('demo.bvault')

# Show vault info 
print("\n📋 Vault info (what attacker sees):")
decoder = BioVaultDecoder('demo.bvault')
decoder.info()

# Extract each layer 
print("\n🔑 Extracting with key A0:")
decoder.extract('A0', 'out_A0.txt')
print("   Content:", open('out_A0.txt').read())

print("\n🔑 Extracting with key A1:")
decoder.extract('A1', 'out_A1.txt')
print("   Content:", open('out_A1.txt').read())

print("\n🔑 Extracting with key B0:")
decoder.extract('B0', 'out_B0.txt')
print("   Content:", open('out_B0.txt').read())

print("\n" + "=" * 50)
print("✅ Demo complete!")
print("   Same file. Different keys. Different outputs.")
print("   That's BioVault. 🧬")
print("=" * 50)

#  Cleanup 
for f in ['secret_message.txt', 'decoy_file.txt', 'hidden_note.txt',
          'out_A0.txt', 'out_A1.txt', 'out_B0.txt']:
    try: os.remove(f)
    except: pass