# examples/demo.py
# BioVault v3 demo — one vault, three files, three different keys.
#
# Passwords are hardcoded here so the demo runs unattended. Real usage should
# use `biovault encode --prompt-password` so nothing lands in your shell history.

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from biovault import BioVaultEncoder, BioVaultDecoder
from biovault.output import safe_print

LINE = "=" * 58

BOARD_PASS = "board-only-2026"
VAULT_PASS = "ops-team-2026"

FILES = {
    "board_notes.txt": b"Q4 revenue: $2.4M\nRunway: 18 months\nAcquisition talks: ongoing\n",
    "team_memo.txt": b"Team offsite is on the 14th.\nLunch will be catered.\n",
    "credentials.env": b"api_key=sk-live-4f9a2b\ndb_password=correcthorse\n",
}


def header(title):
    safe_print(f"\n{LINE}\n{title}\n{LINE}")


header("🧬 BioVault v3 Demo")

# ── Create the source files ──
safe_print("\n📝 Creating three files with different sensitivities...\n")
for name, content in FILES.items():
    with open(name, "wb") as f:
        f.write(content)
    safe_print(f"  ✅ {name} ({len(content)} bytes)")

# ── Pack them into a single vault ──
header("🔒 Packing 3 files into 1 vault")
safe_print("")

encoder = BioVaultEncoder()
encoder.add_layer("A0", "board_notes.txt", FILES["board_notes.txt"], BOARD_PASS)
encoder.add_layer("A1", "team_memo.txt", FILES["team_memo.txt"])          # no password
encoder.add_layer("B0", "credentials.env", FILES["credentials.env"], VAULT_PASS)
encoder.save("demo.bvault")

# ── What someone holding the file can see ──
header("👁️  What an attacker sees without any password")

decoder = BioVaultDecoder("demo.bvault")
decoder.info()

safe_print("  Note: BioVault does NOT hide that encrypted layers exist.")
safe_print("  It protects their contents, not their existence.")

# ── Same file, different keys, different content ──
header("🔑 Same vault file, three different keys")

safe_print("\n── Key A0 (board password) ──")
board = decoder.extract("A0", "out_A0.txt", password=BOARD_PASS)
safe_print(f"\n{board.decode()}")

safe_print("── Key A1 (no password needed) ──")
memo = decoder.extract("A1", "out_A1.txt")
safe_print(f"\n{memo.decode()}")

safe_print("── Key B0 (ops password, antisense strand) ──")
creds = decoder.extract("B0", "out_B0.txt", password=VAULT_PASS)
safe_print(f"\n{creds.decode()}")

# ── Wrong password ──
header("🚫 Wrong password recovers nothing")

safe_print("")
result = decoder.extract("A0", "stolen.txt", password="definitely-wrong")
safe_print(f"\n  Returned:            {result}")
safe_print(f"  stolen.txt written?  {'YES' if os.path.exists('stolen.txt') else 'NO'}")
safe_print("  A failed decrypt writes no partial output.")

# ── Tampering ──
header("🛡️  Tampered vaults are rejected, not silently trusted")

with open("demo.bvault", "rb") as f:
    raw = bytearray(f.read())
raw[-40] ^= 0xFF          # flip one bit inside the layer data
with open("tampered.bvault", "wb") as f:
    f.write(raw)

safe_print("")
try:
    BioVaultDecoder("tampered.bvault")
    safe_print("  ❌ tampering went undetected")
except ValueError as e:
    safe_print(f"  ✅ Rejected on load: {e}")

header("✅ Demo complete")
safe_print("   One file. Six possible keys. Different content per key.")
safe_print("   That's BioVault. 🧬\n")

# ── Cleanup ──
for name in list(FILES) + ["demo.bvault", "tampered.bvault",
                           "out_A0.txt", "out_A1.txt", "out_B0.txt", "stolen.txt"]:
    try:
        os.remove(name)
    except OSError:
        pass
