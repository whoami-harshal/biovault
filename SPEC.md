# BioVault Format Specification v3.0

**Author:** Harshal — 2026 — MIT License

## Overview

DNA-inspired multi-layer file format. Multiple files stored in one
vault, each extracted with a different reading key. Optional
per-layer password encryption.

## Core Concepts

- **Base-4 encoding:** A=00, T=01, G=10, C=11
- **Reading frames:** A0/A1/A2 (forward), B0/B1/B2 (antisense)
- **Pipeline:** compress (ZSTD) → encrypt (Fernet, optional) →
  base-4 encode → frame offset → binary pack

## File Structure

```
[MAGIC 4B "BVLT"] [VERSION 1B] [META_LENGTH 4B] [METADATA JSON]
[LAYERS_BLOB] [CHECKSUM 64B] [FOOTER 4B "TLVB"]
```

Layer offsets in LAYERS_BLOB come from `packed_length` in metadata —
no delimiter needed. CHECKSUM is a full SHA-256 hex digest of
`METADATA || LAYERS_BLOB`.

## Layer Metadata

| Field | Meaning |
|-------|---------|
| `mode` | Reading key (A0–B2) |
| `sequence_length` | ATGC symbol count, for unpacking |
| `payload_length` | Exact compressed(+encrypted) byte length |
| `packed_length` | Bytes this layer occupies in the blob |
| `encrypted` | Whether a password was used |
| `salt` | Per-layer random salt (hex), or null |
| `kdf` | `scrypt`, or `pbkdf2` for legacy vaults |
| `checksum` | SHA-256 of the plaintext — **null for encrypted layers** |
| `original_size` | Plaintext length — **null for encrypted layers** |

There is deliberately no `filename` field. Metadata is unauthenticated, and
a decoder that took an output path from it would let a crafted vault choose
where bytes land on disk.

`checksum` and `original_size` are omitted for encrypted layers because
metadata is readable without the password: a plaintext hash would let anyone
confirm a guessed plaintext, and the exact size is itself a leak. Fernet's
HMAC already authenticates those layers on decrypt.

## Security

- Fernet: AES-128-CBC + HMAC-SHA256. Fernet splits the 32-byte key it is
  given into a 16-byte signing key and a 16-byte AES key — hence AES-128,
  not AES-256.
- scrypt key derivation, n=2^15, r=8, p=1 (~32 MiB per guess), independent
  random salt per layer. Legacy `pbkdf2` vaults (PBKDF2-HMAC-SHA256,
  100,000 iterations) still decrypt.
- Wrong password → no output, no partial write.

## Threat Model

**In scope.** Confidentiality and integrity of encrypted layer *contents*
against someone holding the vault file. Safe handling of untrusted vaults:
malformed metadata, decompression bombs, and attacker-chosen output paths.

**Out of scope.**

- **Hiding that data exists.** Layer count, reading keys, and per-layer
  `encrypted` flags are cleartext. This format offers no hidden volumes and
  no plausible deniability.
- **Tamper-proofing unencrypted layers.** The trailing checksum is unkeyed;
  anyone can modify a vault and recompute it. It catches corruption, not
  attackers. Encrypted layers are protected by Fernet's HMAC.
- **Traffic analysis.** Compress-then-encrypt means ciphertext length
  correlates with plaintext compressibility.

## Limitations

- Max 6 layers per vault
- Small files may end up larger post-encryption
- No streaming — full file loaded into memory
- Layers decompress to at most 256 MiB each by default (`max_decompressed`)
- Not evaluated for post-quantum resistance

## Reference Implementation

github.com/whoami-harshal/biovault
