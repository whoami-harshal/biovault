# biovault/cli.py
# V2.0 — same commands, now with --password support and version info

import argparse
import sys
from .encoder import BioVaultEncoder
from .decoder import BioVaultDecoder


def cmd_encode(args):
    encoder = BioVaultEncoder()
    passwords = args.password or []

    for i, item in enumerate(args.input):
        if ':' not in item:
            print(f"❌ Error: Use format 'filename:mode' (e.g. secret.pdf:A0)")
            sys.exit(1)
        filepath, mode = item.rsplit(':', 1)
        pwd = passwords[i] if i < len(passwords) else None

        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            print(f"❌ File not found: {filepath}")
            sys.exit(1)

        filename = filepath.split('/')[-1].split('\\')[-1]
        encoder.add_layer(mode.upper(), filename, data, pwd)

    encoder.save(args.output)


def cmd_decode(args):
    try:
        decoder = BioVaultDecoder(args.input)
        decoder.extract(args.key.upper(), args.output, password=args.password)
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def cmd_info(args):
    try:
        decoder = BioVaultDecoder(args.input)
        decoder.info()
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog='biovault',
        description='🧬 BioVault v2 — DNA-inspired multi-layer file format'
    )
    subparsers = parser.add_subparsers(dest='command')

    enc = subparsers.add_parser('encode', help='Encode files into a vault')
    enc.add_argument('--input', nargs='+', required=True,
                      help='Files to encode: file.pdf:A0 secret.txt:A1')
    enc.add_argument('--password', nargs='+', default=None,
                      help='Passwords per file, same order as --input (optional)')
    enc.add_argument('--output', required=True,
                      help='Output vault file (e.g. vault.bvault)')

    dec = subparsers.add_parser('decode', help='Extract a file from a vault')
    dec.add_argument('--input', required=True, help='Input .bvault file')
    dec.add_argument('--key', required=True,
                      help='Reading mode key: A0, A1, A2, B0, B1, B2')
    dec.add_argument('--password', default=None,
                      help='Password, if this layer was encrypted')
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
