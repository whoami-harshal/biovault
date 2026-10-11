# Security Policy

BioVault is an experimental, unaudited format. Please read the threat model in
[SPEC.md](SPEC.md) before relying on it.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/whoami-harshal/biovault/security/advisories/new)
rather than in a public issue. Include a proof-of-concept vault or script if you can.

Every confirmed issue gets a fix, a regression test that replays the exploit,
and a credit in the changelog unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---------|-----------|
| 5.x     | ✅ |
| 4.x     | Read-only: 5.x still opens v4 vaults |
| < 4     | ❌ |

## Out of scope

Behaviour the threat model already documents as not protected: hiding that
layers exist, tamper-proofing unsigned vaults, and ciphertext length leakage.
