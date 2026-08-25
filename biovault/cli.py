# biovault/cli.py
# V3 — same commands, with secure password entry and version info

import argparse
import getpass
import sys
from .encoder import BioVaultEncoder
from .decoder import BioVaultDecoder
from .output import safe_print

# Errors that mean "bad input file", not "bug in BioVault".
VAULT_ERRORS = (ValueError, KeyError, IndexError, OSError)


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


def cmd_encode(args):
    encoder = BioVaultEncoder()
    passwords = args.password or []

    if passwords:
        _warn_password_on_cli()

    for i, item in enumerate(args.input):
        if ':' not in item:
            safe_print(f"❌ Error: Use format 'filename:mode' (e.g. secret.pdf:A0)")
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

    try:
        encoder.save(args.output)
    except (ValueError, OSError) as e:
        safe_print(f"❌ Error: {e}")
        sys.exit(1)


def cmd_decode(args):
    try:
        decoder = BioVaultDecoder(args.input)
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
        decoder = BioVaultDecoder(args.input)
        decoder.info()
    except VAULT_ERRORS as e:
        safe_print(f"❌ Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog='biovault',
        description='🧬 BioVault v3 — DNA-inspired multi-layer file format'
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
    dec.add_argument('--output', required=True, help='Output file path')

    inf = subparsers.add_parser('info', help='Show vault information')
    inf.add_argument('--input', required=True, help='Input .bvault file')

    args = parser.parse_args()

    if args.command == 'encode':
        cmd_encode(args)
    elif args.command == 'decode':
        cmd_decode(args)
    elif args.command == 'info':
        cmd_info(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
