<div align="center">

# 🧬 BioVault

**One file. Six keys. Six different answers.**

A DNA-inspired multi-layer file format — the same vault yields completely
different content depending on which reading key you open it with.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Format](https://img.shields.io/badge/format-v3.0.0-purple.svg)](SPEC.md)
[![Status](https://img.shields.io/badge/status-experimental-orange.svg)](#status)

</div>

---

## The idea

DNA stores different proteins in the same strand depending on where you start
reading and which direction you read it. BioVault does that with files.

Pack up to six files into one vault. Each is addressed by a **reading key** —
three forward frames (`A0`, `A1`, `A2`) and three antisense frames (`B0`, `B1`,
`B2`) — and each carries its own independent password.

```
                    ┌─────────────────┐
   board_notes.txt ─┤                 ├─ A0 ─→ Q4 revenue: 2.4M
      team_memo.txt ┤  company.bvault ├─ A1 ─→ Offsite is on the 14th
    credentials.env ┤                 ├─ B0 ─→ api_key=sk-live-4f9a2b
                    └─────────────────┘
                         one file
```

## Install

```bash
git clone https://github.com/whoami-harshal/biovault.git
cd biovault
pip install -e .
```

Python 3.9+. Dependencies: `cryptography`, `zstandard`.

## See it work

```bash
python examples/demo.py
```

One command. It builds a vault from three files, opens each with a different
key, shows what an attacker sees without a password, and proves that a wrong
password and a tampered file both recover nothing.

## Using the CLI

**Pack three files into one vault** — two encrypted with separate passwords,
one left plain:

```bash
biovault encode --input "board.txt:A0" "memo.txt:A1" "creds.env:B0" --prompt-password --output company.bvault
```

```
  Layer A0 queued: board.txt (37 bytes) [🔐 encrypted]
  Layer A1 queued: memo.txt (25 bytes) [plain]
  Layer B0 queued: creds.env (24 bytes) [🔐 encrypted]

🧬 Building BioVault v3: company.bvault
✅ BioVault created: company.bvault
   Keys: ['A0', 'A1', 'B0']
```

**Open one layer:**

```bash
biovault decode --input company.bvault --key A0 --output board.txt
```

```
🔓 Extracting layer A0...
  ✅ Authenticated on decrypt (HMAC-SHA256)
  ✅ Extracted: board.txt (37 bytes)

Q4 revenue: 2.4M
Runway: 18 months
```

**Same file, different key, different content:**

```bash
biovault decode --input company.bvault --key B0 --output creds.env
```

```
api_key=sk-live-4f9a2b
```

**See what's inside without any password:**

```bash
biovault info --input company.bvault
```

```
   Total layers: 3
   Available keys: ['A0', 'A1', 'B0']
   Encrypted layers: ['A0', 'B0']
```

## Prove it yourself

Delete the originals, then try to get them back. Every layer is independent:

```bash
biovault decode --input company.bvault --key B0 --password "boardpass" --output out.env
```

```
  ⚠️  Wrong password — nothing recovered
```

`boardpass` is the *correct* password — for layer `A0`. Against `B0` it is
worthless, and no partial file is written. Each layer derives its own key from
its own password and its own random salt.

```bash
biovault decode --input company.bvault --key B0 --password "opspass" --output out.env
```

```
  ✅ Authenticated on decrypt (HMAC-SHA256)
api_key=sk-live-4f9a2b
```

And the vault holds no readable plaintext:

```bash
grep -i "api_key" company.bvault      # findstr /i "api_key" on Windows
```

Returns nothing.

## Reading keys

| Key | Strand | Frame | Reads |
|-----|--------|-------|-------|
| `A0` `A1` `A2` | Forward (sense) | 0, 1, 2 | Left to right |
| `B0` `B1` `B2` | Reverse (antisense) | 0, 1, 2 | Reverse complement |

Six keys, six layers, one per vault — the same number of reading frames a real
double-stranded sequence has.

Reading keys are **addresses, not credentials.** All six are public and
enumerable. Confidentiality comes from the per-layer password, not the key.

## How it works

Each layer runs an independent pipeline:

```mermaid
flowchart LR
    A[File bytes] --> B[ZSTD<br/>compress]
    B --> C[Encrypt<br/>Fernet]
    C --> D[Base-4<br/>ATGC]
    D --> E[Frame<br/>offset]
    E --> F[Bit-pack]
    F --> G[(Vault)]
```

1. **Compress** — ZSTD level 9
2. **Encrypt** — Fernet (AES-128-CBC + HMAC-SHA256), scrypt-derived key, random salt per layer
3. **Base-4 encode** — every 2 bits becomes a nucleotide: `A=00 T=01 G=10 C=11`
4. **Frame offset** — the reading key sets the strand and offset
5. **Bit-pack** — symbols packed back into bytes

Decoding runs it backwards. Full details in [SPEC.md](SPEC.md).

## Security

**What holds:**

- Encrypted layers use **authenticated** encryption — a tampered layer fails to decrypt rather than returning corrupted bytes
- **scrypt** key derivation (n=2¹⁵, ~32 MiB per guess) resists GPU and ASIC cracking
- Independent random salt per layer, so the same password on two layers still produces different keys
- A wrong password produces **no output and no partial file**
- Untrusted vaults are handled defensively: metadata is validated, decompression is capped, and output paths are never read from the file

**What does not hold — read this before trusting it with anything:**

- **This is not a hidden-volume system.** A vault openly states how many layers it holds and which are encrypted; `biovault info` prints exactly that. It protects the *contents* of your data, not the *fact that it exists*. Don't rely on it for plausible deniability.
- **Unencrypted layers are not tamper-proof.** The vault-level checksum is plain SHA-256, not a MAC — anyone can edit a vault and recompute it. It catches corruption, not attackers. Only encrypted layers are cryptographically authenticated.
- **Ciphertext length leaks a little.** Layers are compressed before encryption, so stored size correlates with how compressible the plaintext was.

Keep passwords off the command line:

```bash
biovault encode --input "secret.txt:A0" --prompt-password --output vault.bvault
```

```bash
echo "$PASSWORD" | biovault decode --input vault.bvault --key A0 --password-stdin --output out.txt
```

`--password` still works but warns — it's visible to any other user on the
machine through the process list, and it lands in your shell history.

## Security audit

v3 followed a full review of v2. Five real vulnerabilities were found and
fixed, each with a working proof-of-concept and a regression test:

| Severity | Issue | Fix |
|----------|-------|-----|
| **Critical** | Arbitrary file write — vault metadata chose the output path, so a crafted vault could write to `~/.ssh/authorized_keys` | Output paths are generated locally, never read from the file |
| **Critical** | Encrypted layers stored a SHA-256 of their **plaintext** in cleartext metadata, letting anyone confirm a guessed plaintext without the password | Removed for encrypted layers; Fernet's HMAC already authenticates them |
| **High** | Integrity failures printed a warning, then wrote the file anyway | Raises and writes nothing |
| **High** | Decompression bombs — 1.6 KB expanded to 50 MB unchecked | Streaming decompression with a hard output cap |
| **Medium** | PBKDF2 at 100k iterations, below the OWASP floor | Switched to scrypt (memory-hard) |

Plus: 64-bit truncated checksums replaced with full SHA-256, metadata
validation on untrusted input, secure password entry, and corrected docs — v2
advertised "AES-256" when Fernet is AES-128, and claimed a plausible
deniability the format never provided.

```bash
python tests/test_core.py
```

Ten tests, five of which replay the original exploits.

## Roadmap

- [ ] **Halve vault size** — the packer stores 2 symbols per byte where 4 fit
- [ ] **Vault-level MAC** — authenticate the whole container, not just encrypted layers
- [ ] **Streaming pipeline** — the whole file currently loads into memory
- [ ] **Deniable mode** — fixed-size, random-filled containers where layer count is genuinely unknowable
- [ ] CI, pytest runner, type hints

## Status

**Experimental.** A research and portfolio project, not independently audited.
The cryptographic primitives are standard and correctly used, but the format
itself is young. Don't protect anything irreplaceable with it yet.

## License

MIT © 2026 Harshal
