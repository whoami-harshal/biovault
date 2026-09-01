# biovault/__init__.py

from .encoder import BioVaultEncoder
from .decoder import BioVaultDecoder
from .frames import (
    bytes_to_base4,
    base4_to_bytes,
    get_frame,
    get_antisense,
    apply_reading_mode,
    READING_MODES
)
from .crypto import encrypt_data, decrypt_data
from .compression import compress_data, decompress_data
from .packer import pack_sequence, unpack_sequence
from .signing import (
    generate_keypair, load_private_key, load_public_key, sign, verify, fingerprint
)

__version__ = '4.0.0'
__author__ = 'Harshal'
__description__ = 'DNA-inspired multi-layer file format'

__all__ = [
    'BioVaultEncoder',
    'BioVaultDecoder',
    'bytes_to_base4',
    'base4_to_bytes',
    'get_frame',
    'get_antisense',
    'apply_reading_mode',
    'READING_MODES',
    'encrypt_data',
    'decrypt_data',
    'compress_data',
    'decompress_data',
    'pack_sequence',
    'unpack_sequence',
    'generate_keypair',
    'load_private_key',
    'load_public_key',
    'sign',
    'verify',
    'fingerprint',
]
