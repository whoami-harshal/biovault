# biovault/packer.py
# V4 — Binary packing
# ASCII "ATGC" string = 1 byte per symbol (wasteful)
# Packed = 4 symbols per byte (2 bits each) — 4x smaller than ASCII
#
# v3 and earlier packed only 2 symbols per byte, leaving the top 4 bits of
# every byte zero and making each vault exactly twice the size it needed to be.

SYMBOLS = 'ATGC'
INDEX = {c: i for i, c in enumerate(SYMBOLS)}

SYMBOLS_PER_BYTE = 4


def pack_sequence(sequence: str) -> bytes:
    """
    Pack an ATGC string into binary.
    Four symbols -> one byte. Length is padded up to a multiple of 4 with 'A'.
    """
    symbols = [INDEX[c] for c in sequence]

    remainder = len(symbols) % SYMBOLS_PER_BYTE
    if remainder:
        symbols.extend([0] * (SYMBOLS_PER_BYTE - remainder))  # pad with 'A'

    packed = bytearray(len(symbols) // SYMBOLS_PER_BYTE)
    for i in range(0, len(symbols), SYMBOLS_PER_BYTE):
        packed[i // SYMBOLS_PER_BYTE] = (
            (symbols[i] << 6) | (symbols[i + 1] << 4) |
            (symbols[i + 2] << 2) | symbols[i + 3]
        )
    return bytes(packed)


def unpack_sequence(packed: bytes, symbol_count: int) -> str:
    """
    Unpack binary back into an ATGC string.
    symbol_count trims off any padding symbols added during packing.
    """
    result = []
    for byte in packed:
        result.append(SYMBOLS[(byte >> 6) & 0b11])
        result.append(SYMBOLS[(byte >> 4) & 0b11])
        result.append(SYMBOLS[(byte >> 2) & 0b11])
        result.append(SYMBOLS[byte & 0b11])
    return ''.join(result[:symbol_count])
