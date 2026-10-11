# Changelog

## 5.0.0

Format v5. Vaults written by 5.0 cannot be opened by 4.x; 5.0 still opens v4 vaults.

### Security
- **Encrypted layers now use AES-256-GCM** instead of Fernet (AES-128-CBC + HMAC-SHA256).
  Fernet tokens carried three leaks the threat model did not account for:
  - a cleartext 8-byte timestamp recording when each layer was encrypted, readable by anyone holding the vault;
  - base64 encoding, inflating every encrypted layer by roughly 40% (now a fixed 28 bytes: 12-byte nonce + 16-byte tag);
  - a constant `gAAAAA` prefix that identified the cipher.
- **Encrypted layers are bound to their own metadata.** Format version, reading mode, KDF, cipher and salt are authenticated as associated data. An encrypted layer moved to a different reading key fails to decrypt, even in an unsigned vault.
- **No downgrade by editing metadata.** The allowed cipher and KDFs are fixed by the format version: v5 layers must be AES-256-GCM with scrypt; Fernet and legacy PBKDF2 are accepted only in v4 vaults.
- Metadata `version` must match the header version byte.
- Wrong-password message now reads "Wrong password or modified layer", since authenticated encryption cannot tell the two apart.

### Packaging
- Python 3.10+ (3.9 reached end of life in October 2025).
- PyPI metadata, `pytest` test runner, GitHub Actions CI on Linux, Windows and macOS, and a trusted-publishing release workflow.

## 4.0.0
- Four symbols per byte (vaults halved in size), Ed25519 whole-vault signing, byte-level transform (~140x faster).

## 3.0.0
- Security review of v2: fixed arbitrary file write, plaintext-hash leak, write-on-integrity-failure, decompression bombs; PBKDF2 replaced by scrypt.
