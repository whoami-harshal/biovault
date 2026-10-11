# BioVault Format Specification v5.0

**Author:** Harshal — 2026 — MIT License

## Overview

DNA-inspired multi-layer file format. Multiple files stored in one
vault, each extracted with a different reading key. Optional
per-layer password encryption.

## Core Concepts

- **Base-4 encoding:** A=00, T=01, G=10, C=11
- **Reading frames:** A0/A1/A2 (forward), B0/B1/B2 (antisense)
- **Pipeline:** compress (ZSTD) → encrypt (AES-256-GCM, optional) →
  base-4 encode → frame offset → binary pack

The base-4 and frame stages are a public, reversible addressing scheme. They
provide no confidentiality; only the encryption stage does.

## File Structure

```
[MAGIC 4B "BVLT"] [VERSION 1B] [META_LENGTH 4B] [METADATA JSON]
[LAYERS_BLOB] [CHECKSUM 64B] [SIG_FLAG 1B]
[PUBKEY 32B + SIGNATURE 64B, only when SIG_FLAG = 1]
[FOOTER 4B "TLVB"]
```

VERSION is 5 for this specification. The metadata `version` field must equal
the header byte. META_LENGTH is a big-endian uint32.

Layer offsets in LAYERS_BLOB come from `packed_length` in metadata —
no delimiter needed. CHECKSUM is a full SHA-256 hex digest of
`METADATA || LAYERS_BLOB`.

Base-4 symbols are packed **four per byte** (2 bits each), so the DNA
representation is size-neutral. v3 and earlier packed only two per byte,
doubling every vault.

Because packing is the exact inverse of base-4 encoding, the whole symbol
stage is expressible on bytes: mode A0 is the identity, a frame offset is a
right shift of 2*frame bits, complementing is XOR 0x55, and reversing the
strand is a byte reversal plus a 256-entry table. `transform.py` implements
this; `frames.py` and `packer.py` remain the reference implementation, and the
two are asserted equal in the test suite.

When SIG_FLAG is 1, the Ed25519 signature covers every byte from MAGIC
through CHECKSUM inclusive. The embedded public key is a convenience for
displaying a fingerprint — it proves nothing on its own, since an attacker
can re-sign modified content with their own key and swap it. Verification
requires a public key supplied out of band.

## Layer Metadata

| Field | Meaning |
|-------|---------|
| `mode` | Reading key (A0–B2) |
| `sequence_length` | ATGC symbol count, for unpacking |
| `payload_length` | Exact compressed(+encrypted) byte length |
| `packed_length` | Bytes this layer occupies in the blob |
| `encrypted` | Whether a password was used (boolean) |
| `salt` | Per-layer random 16-byte salt (hex), or null |
| `kdf` | `scrypt` for encrypted layers, else null |
| `cipher` | `aes-256-gcm` for encrypted layers, else null |
| `checksum` | SHA-256 of the plaintext — **null for encrypted layers** |
| `original_size` | Plaintext length — **null for encrypted layers** |

There is deliberately no `filename` field. Metadata is unauthenticated, and
a decoder that took an output path from it would let a crafted vault choose
where bytes land on disk.

`checksum` and `original_size` are omitted for encrypted layers because
metadata is readable without the password: a plaintext hash would let anyone
confirm a guessed plaintext, and the exact size is itself a leak. AES-GCM
authenticates those layers on decrypt.

## Encrypted Layers

```
key     = scrypt(password, salt, n=2^15, r=8, p=1, length=32)
aad     = "BioVault/v{version}/layer/{mode}/{kdf}/{cipher}/" (ASCII) || salt
payload = nonce (12 bytes) || AES-256-GCM(key, nonce, compressed, aad)
```

The GCM output is ciphertext followed by a 16-byte tag, so an encrypted layer
is exactly 28 bytes larger than its compressed plaintext. Salt and nonce are
fresh random bytes for every layer.

Binding the version, reading mode, KDF, cipher and salt as associated data
means an encrypted layer cannot be moved to a different reading key, or have
its parameters edited, without failing authentication — even in an unsigned
vault.

The cipher and KDF are fixed by the format version, not chosen by metadata:

| Version | Cipher | KDF |
|---------|--------|-----|
| 5 | `aes-256-gcm` | `scrypt` |
| 4 | Fernet (no `cipher` field) | `scrypt`, or legacy `pbkdf2` |

A decoder rejects any other combination, so a v5 vault cannot be downgraded
by editing its metadata.

### v4 compatibility

v4 vaults are identical in structure but use version byte 4 and encrypt with
Fernet (AES-128-CBC + HMAC-SHA256, key = base64url of the 32-byte KDF output,
no associated data). v5 decoders read them; v5 encoders never write them.

v5 replaced Fernet because a Fernet token carries a cleartext creation
timestamp, is base64 text (about 40% larger than the ciphertext), begins with
a constant prefix identifying the cipher, and uses AES-128.

## Security

- AES-256-GCM authenticated encryption, scrypt key derivation (~32 MiB per
  guess), independent random salt and nonce per layer.
- Layer metadata bound as associated data; cipher and KDF pinned by version.
- Wrong password or modified layer → no output, no partial write.
- Ed25519 signing (optional) authenticates the whole container, including
  unencrypted layers and all metadata.

## Threat Model

**In scope.** Confidentiality and integrity of encrypted layer *contents*
against someone holding the vault file, including relabelling an encrypted
layer to a different reading key. Safe handling of untrusted vaults:
malformed metadata, decompression bombs, and attacker-chosen output paths.

**Out of scope.**

- **Hiding that data exists.** Layer count, reading keys, and per-layer
  `encrypted` flags are cleartext. This format offers no hidden volumes and
  no plausible deniability.
- **Tamper-proofing *unsigned* vaults.** Without a signature the trailing
  checksum is unkeyed; anyone can modify unencrypted layers or metadata, or
  replace an encrypted layer with one from another vault, and recompute it.
  Sign anything you distribute. Encrypted layer contents remain protected by
  GCM either way.
- **Traffic analysis.** Compress-then-encrypt means ciphertext length
  correlates with plaintext compressibility.

## Limitations

- Max 6 layers per vault
- Small files may end up larger post-encryption
- No streaming — full file loaded into memory
- Layers decompress to at most 256 MiB each by default (`max_decompressed`)
- Ed25519 is not post-quantum resistant

## Reference Implementation

github.com/whoami-harshal/biovault
