# 🧬 BioVault

Store up to 6 files in one. Each is unlocked by a different key
and password. An incorrect password leaves no trace.

DNA-inspired multi-layer file format — same file, different keys
extract completely different content.

## Features

- 🔐 AES-256 encryption, independent password per layer
- 🗜️ ZSTD compression
- 🎭 Plausible deniability — wrong password fails silently
- 🧬 6 reading modes per vault (3 forward, 3 antisense)
- ✅ SHA-256 integrity check
- ⌨️ Installable CLI — works from any directory

## Installation

```bash
git clone https://github.com/[yourusername]/biovault.git
cd biovault
pip install -e .
```

## Quick Start

```bash
biovault encode --input "secret.txt:A0" "photo.png:B0" --password "pass1" "pass2" --output vault.bvault

biovault decode --input vault.bvault --key A0 --password "pass1" --output recovered.txt

biovault info --input vault.bvault
```

## Reading Mode Keys

| Key | Strand | Frame |
|-----|--------|-------|
| A0, A1, A2 | Forward | 0, 1, 2 |
| B0, B1, B2 | Antisense | 0, 1, 2 |

## Status

Experimental — v2.0, research/portfolio project. Not security-audited.

## License

MIT — Copyright (c) 2026 Harshal