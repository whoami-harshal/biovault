# biovault/cli.py
# V4 — encode/decode/info, plus keygen and signature verification

import argparse
import getpass
import os
import sys
from .encoder import BioVaultEncoder
from .decoder import BioVaultDecoder
from .compression import DEFAULT_MAX_DECOMPRESSED
from .signing import (
    generate_keypair, load_private_key, load_public_key, fingerprint,
)
from .output import safe_print

# Errors that mean "bad input file", not "bug in BioVault".
VAULT_ERRORS = (ValueError, KeyError, IndexError, OSError)


def _parse_size(text):
    """Accept plain bytes or a K/M/G suffix, e.g. 512M or 2G."""
    text = text.strip().upper()
    units = {'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3}
    if text and text[-1] in units:
        number, factor = text[:-1], units[text[-1]]
    else:
        number, factor = text, 1
    try:
        value = int(float(number) * factor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a size: {text}")
    if value <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return value


def _read_stdin_password():
    """Read one password from a line of stdin. Empty line = no password."""
    line = sys.stdin.readline() if sys.stdin is not None else ''
    return line.rstrip('\n').rstrip('\r')


def _ask_password(prompt_text):
    """
    Prompt for a password on the terminal.

    Scripts and CI should use --password-stdin instead of relying on this.
    getpass() reads the console directly on Windows, and isatty() cannot be
    trusted to detect that there is no terminal — under Git Bash / MinTTY it
    reports True even when stdin is /dev/null — so a prompt here would block
    forever rather than fail. An explicit flag is the only safe way to say
    "there is nobody here to type".
    """
    try:
        return getpass.getpass(prompt_text)
    except (EOFError, OSError):
        safe_print(
            "❌ Could not read a password from the terminal.\n"
            "    Use --password-stdin instead (echo PASSWORD | biovault ...)."
        )
        sys.exit(1)


def _warn_password_on_cli():
    safe_print(
        "⚠️  Passwords given with --password are visible to other users via the "
        "process list (ps / /proc) and are saved in your shell history.\n"
        "    Prefer --prompt-password (encode) or omitting --password (decode) "
        "to be prompted instead."
    )


def _load_signing_key(path):
    """Load a private key, prompting for its passphrase only if it needs one."""
    try:
        return load_private_key(path)
    except TypeError:
        pass                      # key is encrypted; a passphrase is required
    except (OSError, ValueError) as e:
        safe_print(f"❌ Cannot read signing key {path}: {e}")
        sys.exit(1)

    passphrase = _ask_password(f"Passphrase for {path}: ")
    try:
        return load_private_key(path, passphrase)
    except (OSError, ValueError) as e:
        safe_print(f"❌ Cannot unlock signing key {path}: {e}")
        sys.exit(1)


def cmd_keygen(args):
    out = args.output
    pub_path = out + '.pub'

    for path in (out, pub_path):
        if os.path.exists(path):
            safe_print(f"❌ {path} already exists — refusing to overwrite a key")
            sys.exit(1)

    if args.no_passphrase:
        passphrase = ''
    else:
        passphrase = _ask_password("Passphrase for the new key (blank = unencrypted): ")

    private_pem, public_pem = generate_keypair(passphrase or None)

    with open(out, 'wb') as f:
        f.write(private_pem)
    with open(pub_path, 'wb') as f:
        f.write(public_pem)

    try:
        os.chmod(out, 0o600)
    except OSError:
        pass                      # best effort; Windows ignores POSIX modes

    raw_pub = load_public_key(pub_path)
    safe_print("✅ Signing key created")
    safe_print(f"   Private key: {out}   (keep this secret)")
    safe_print(f"   Public key:  {pub_path}   (share this)")
    safe_print(f"   Fingerprint: {fingerprint(raw_pub)}")
    if not passphrase:
        safe_print("   ⚠️  Private key is NOT encrypted — protect the file itself")


def cmd_verify(args):
    try:
        decoder = BioVaultDecoder(args.input)
        expected = load_public_key(args.key)
        decoder.require_signature(expected)
        safe_print(f"\n✅ Signature valid — signed by {fingerprint(expected)}")
        safe_print("   This vault has not been modified since it was signed.")
    except VAULT_ERRORS as e:
        safe_print(f"❌ Verification failed: {e}")
        sys.exit(1)


def cmd_encode(args):
    encoder = BioVaultEncoder()
    passwords = args.password or []

    if passwords:
        _warn_password_on_cli()

    for i, item in enumerate(args.input):
        if ':' not in item:
            safe_print("❌ Error: Use format 'filename:mode' (e.g. secret.pdf:A0)")
            sys.exit(1)
        filepath, mode = item.rsplit(':', 1)

        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except OSError as e:
            safe_print(f"❌ Cannot read {filepath}: {e}")
            sys.exit(1)

        if args.password_stdin:
            pwd = _read_stdin_password() or None
        elif args.prompt_password:
            pwd = _ask_password(
                f"Password for {filepath} [{mode.upper()}] (blank = no encryption): "
            ) or None
        else:
            pwd = passwords[i] if i < len(passwords) else None

        filename = filepath.replace('\\', '/').split('/')[-1]

        try:
            encoder.add_layer(mode.upper(), filename, data, pwd)
        except ValueError as e:
            safe_print(f"❌ Error: {e}")
            sys.exit(1)

    sign_key = _load_signing_key(args.sign) if args.sign else None

    try:
        encoder.save(args.output, sign_key=sign_key)
    except (ValueError, OSError) as e:
        safe_print(f"❌ Error: {e}")
        sys.exit(1)


def cmd_decode(args):
    try:
        decoder = BioVaultDecoder(args.input, max_decompressed=args.max_decompressed)

        if args.verify:
            decoder.require_signature(load_public_key(args.verify))
            safe_print("   ✅ Signature verified")

        key = args.key.upper()

        password = args.password
        if password:
            _warn_password_on_cli()

        # Prompt only when this layer actually needs a password.
        meta = decoder.layer_meta(key)
        if meta is not None and meta.get('encrypted') and not password:
            if args.password_stdin:
                password = _read_stdin_password()
            else:
                password = _ask_password(f"Password for layer {key}: ")

        result = decoder.extract(key, args.output, password=password)
        if result is None:
            sys.exit(1)
    except VAULT_ERRORS as e:
        safe_print(f"❌ Error: {e}")
        sys.exit(1)


def cmd_info(args):
    try:
        decoder = BioVaultDecoder(args.input, max_decompressed=args.max_decompressed)
        if args.verify:
            decoder.require_signature(load_public_key(args.verify))
            safe_print("   ✅ Signature verified")
        decoder.info()
    except VAULT_ERRORS as e:
        safe_print(f"❌ Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog='biovault',
        description='🧬 BioVault v4 — DNA-inspired multi-layer file format'
    )
    subparsers = parser.add_subparsers(dest='command')

    enc = subparsers.add_parser('encode', help='Encode files into a vault')
    enc.add_argument('--input', nargs='+', required=True,
                     help='Files to encode: file.pdf:A0 secret.txt:A1')
    enc.add_argument('--password', nargs='+', default=None,
                     help='Passwords per file, same order as --input. '
                          'INSECURE: visible in ps and shell history — '
                          'prefer --prompt-password')
    enc.add_argument('--prompt-password', action='store_true',
                     help='Prompt securely for each file password (recommended)')
    enc.add_argument('--password-stdin', action='store_true',
                     help='Read one password per input file from stdin, in order '
                          '(blank line = no encryption). Use this in scripts and CI')
    enc.add_argument('--sign', metavar='KEYFILE', default=None,
                     help='Sign the vault with an Ed25519 private key (see keygen)')
    enc.add_argument('--output', required=True,
                     help='Output vault file (e.g. vault.bvault)')

    dec = subparsers.add_parser('decode', help='Extract a file from a vault')
    dec.add_argument('--input', required=True, help='Input .bvault file')
    dec.add_argument('--key', required=True,
                     help='Reading mode key: A0, A1, A2, B0, B1, B2')
    dec.add_argument('--password', default=None,
                     help='Password, if this layer was encrypted. INSECURE: '
                          'omit it and you will be prompted securely instead')
    dec.add_argument('--password-stdin', action='store_true',
                     help='Read the password from stdin instead of prompting. '
                          'Use this in scripts and CI')
    dec.add_argument('--verify', metavar='PUBKEY', default=None,
                     help='Require a valid signature from this public key')
    dec.add_argument('--max-decompressed', type=_parse_size,
                     default=DEFAULT_MAX_DECOMPRESSED, metavar='SIZE',
                     help='Maximum bytes a single layer may decompress to (default 256M). Accepts K/M/G suffixes')
    dec.add_argument('--output', required=True, help='Output file path')

    inf = subparsers.add_parser('info', help='Show vault information')
    inf.add_argument('--input', required=True, help='Input .bvault file')
    inf.add_argument('--verify', metavar='PUBKEY', default=None,
                     help='Require a valid signature from this public key')
    inf.add_argument('--max-decompressed', type=_parse_size,
                     default=DEFAULT_MAX_DECOMPRESSED, metavar='SIZE',
                     help='Maximum bytes a single layer may decompress to (default 256M). Accepts K/M/G suffixes')

    key = subparsers.add_parser('keygen', help='Create an Ed25519 signing keypair')
    key.add_argument('--output', required=True,
                     help='Private key path; public key gets a .pub suffix')
    key.add_argument('--no-passphrase', action='store_true',
                     help='Skip the passphrase prompt (key stored unencrypted)')

    ver = subparsers.add_parser('verify', help="Check a vault's signature")
    ver.add_argument('--input', required=True, help='Input .bvault file')
    ver.add_argument('--key', required=True, help='Public key file to check against')

    args = parser.parse_args()

    if args.command == 'encode':
        cmd_encode(args)
    elif args.command == 'decode':
        cmd_decode(args)
    elif args.command == 'info':
        cmd_info(args)
    elif args.command == 'keygen':
        cmd_keygen(args)
    elif args.command == 'verify':
        cmd_verify(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
