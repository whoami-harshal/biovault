# examples/demo.py
# BioVault v4 demo — one vault, three files, three keys, one signature.
#
# Passwords are hardcoded here so the demo runs unattended. Real usage should
# use `biovault encode --prompt-password` so nothing lands in your shell history.

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from biovault import BioVaultEncoder, BioVaultDecoder
from biovault.signing import generate_keypair, load_private_key, load_public_key, fingerprint
from biovault.output import safe_print

LINE = "=" * 60

BOARD_PASS = "board-only-2026"
VAULT_PASS = "ops-team-2026"

FILES = {
    "board_notes.txt": b"Q4 revenue: $2.4M\nRunway: 18 months\nAcquisition talks: ongoing\n",
    "team_memo.txt": b"Team offsite is on the 14th.\nLunch will be catered.\n",
    "credentials.env": b"api_key=sk-live-4f9a2b\ndb_password=correcthorse\n",
}

CLEANUP = list(FILES) + [
    "demo.bvault", "tampered.bvault", "resigned.bvault",
    "demo_key", "demo_key.pub", "attacker_key", "attacker_key.pub",
    "out_A0.txt", "out_A1.txt", "out_B0.txt", "stolen.txt",
]


def header(title):
    safe_print(f"\n{LINE}\n{title}\n{LINE}")


header("🧬 BioVault v4 Demo")

# ── Create the source files ──
safe_print("\n📝 Creating three files with different sensitivities...\n")
for name, content in FILES.items():
    with open(name, "wb") as f:
        f.write(content)
    safe_print(f"  ✅ {name} ({len(content)} bytes)")

# ── Make a signing key ──
header("🔑 Creating a signing key")

private_pem, public_pem = generate_keypair()
with open("demo_key", "wb") as f:
    f.write(private_pem)
with open("demo_key.pub", "wb") as f:
    f.write(public_pem)

signing_key = load_private_key("demo_key")
my_pubkey = load_public_key("demo_key.pub")
safe_print(f"\n  Private key: demo_key      (secret)")
safe_print(f"  Public key:  demo_key.pub  (share freely)")
safe_print(f"  Fingerprint: {fingerprint(my_pubkey)}")

# ── Pack them into a single signed vault ──
header("🔒 Packing 3 files into 1 signed vault")
safe_print("")

encoder = BioVaultEncoder()
encoder.add_layer("A0", "board_notes.txt", FILES["board_notes.txt"], BOARD_PASS)
encoder.add_layer("A1", "team_memo.txt", FILES["team_memo.txt"])          # no password
encoder.add_layer("B0", "credentials.env", FILES["credentials.env"], VAULT_PASS)
encoder.save("demo.bvault", sign_key=signing_key)

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

# ── Passwords are per-layer ──
header("🚫 A0's password is useless against B0")

safe_print("")
crossover = decoder.extract("B0", "stolen.txt", password=BOARD_PASS)
safe_print(f"\n  Returned:            {crossover}")
safe_print(f"  stolen.txt written?  {'YES' if os.path.exists('stolen.txt') else 'NO'}")
safe_print("  Every layer derives its own key from its own salt.")

# ── Signature verification ──
header("✍️  Signature proves who made this file")

safe_print("")
decoder.require_signature(my_pubkey)
safe_print(f"  ✅ Signed by {fingerprint(my_pubkey)} — untouched since signing")

# ── Attack 1: edit the vault and recompute the checksum ──
header("🛡️  Attack 1 — edit the file, recompute the checksum")

with open("demo.bvault", "rb") as f:
    raw = bytearray(f.read())
raw[-80] ^= 0xFF                      # flip a bit inside the signed body
with open("tampered.bvault", "wb") as f:
    f.write(raw)

safe_print("")
try:
    BioVaultDecoder("tampered.bvault")
    safe_print("  ❌ tampering went undetected")
except ValueError as e:
    safe_print(f"  ✅ Rejected: {e}")

# ── Attack 2: re-sign the modified file with the attacker's own key ──
header("🛡️  Attack 2 — attacker re-signs with their own key")

attacker_private, attacker_public = generate_keypair()
with open("attacker_key", "wb") as f:
    f.write(attacker_private)
with open("attacker_key.pub", "wb") as f:
    f.write(attacker_public)

# Rebuild a valid, self-consistent vault signed by the attacker.
attacker_encoder = BioVaultEncoder()
attacker_encoder.add_layer("A1", "team_memo.txt", b"TROJAN CONTENT, not the real memo\n")
attacker_encoder.save("resigned.bvault", sign_key=load_private_key("attacker_key"))

safe_print("\n  The forged vault loads fine — its signature is self-consistent.")
forged = BioVaultDecoder("resigned.bvault")
safe_print(f"  But its key fingerprint is {fingerprint(forged.public_key)},")
safe_print(f"  and yours is             {fingerprint(my_pubkey)}\n")

try:
    forged.require_signature(my_pubkey)
    safe_print("  ❌ forged vault passed verification")
except ValueError:
    safe_print("  ✅ Rejected — signed by a different key than expected")
    safe_print("     This is why --verify takes YOUR public key, not the file's.")

header("✅ Demo complete")
safe_print("   One file. Six possible keys. Different content per key.")
safe_print("   Signed, so anyone can prove where it came from.")
safe_print("   That's BioVault. 🧬\n")

# ── Cleanup ──
for name in CLEANUP:
    try:
        os.remove(name)
    except OSError:
        pass
