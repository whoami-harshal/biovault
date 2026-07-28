# BioVault Format Specification v2.0

**Author:** Harshal — 2026 — MIT License

## Overview

DNA-inspired multi-layer file format. Multiple files stored in one
vault, each extracted with a different reading key. Optional
per-layer password encryption with plausible deniability — wrong
passwords fail silently.

## Core Concepts

- **Base-4 encoding:** A=00, T=01, G=10, C=11
- **Reading frames:** A0/A1/A2 (forward), B0/B1/B2 (antisense)
- **Pipeline:** compress (ZSTD) → encrypt (AES-256, optional) →
  base-4 encode → frame offset → binary pack

## File Structure
[MAGIC 4B "BVLT"] [VERSION 1B] [META_LENGTH 4B] [METADATA JSON]
[LAYERS_BLOB] [CHECKSUM 16B] [FOOTER 4B "TLVB"]

Layer offsets in LAYERS_BLOB come from `packed_length` in metadata —
no delimiter needed.

## Security

- AES-256 (Fernet), independent password + salt per layer
- PBKDF2-HMAC-SHA256, 100,000 iterations
- Wrong password → no output, no error

## Limitations

- Max 6 layers per vault
- Small files may end up larger post-encryption
- No streaming — full file loaded into memory
- Not evaluated for post-quantum resistance

## Reference Implementation

github.com/whoami-harshal/biovault