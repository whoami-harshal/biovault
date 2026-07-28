# biovault/packer.py
# V2.0 — Binary packing
# ASCII "ATGC" string = 1 byte per symbol (wasteful)
# Packed = 2 symbols per byte (2 bits each) — 4x smaller than ASCII

SYMBOLS = 'ATGC'
INDEX = {c: i for i, c in enumerate(SYMBOLS)}


def pack_sequence(sequence: str) -> bytes:
    """
    Pack an ATGC string into binary.
    Two symbols -> one byte. Odd length gets padded with 'A'.
    """
    symbols = [INDEX[c] for c in sequence]
    if len(symbols) % 2 != 0:
        symbols.append(0)  # pad with 'A' (index 0)

    packed = bytearray(len(symbols) // 2)
    for i in range(0, len(symbols), 2):
        packed[i // 2] = (symbols[i] << 2) | symbols[i + 1]
    return bytes(packed)


def unpack_sequence(packed: bytes, symbol_count: int) -> str:
    """
    Unpack binary back into an ATGC string.
    symbol_count trims off any padding symbol added during packing.
    """
    result = []
    for byte in packed:
        result.append(SYMBOLS[(byte >> 2) & 0b11])
        result.append(SYMBOLS[byte & 0b11])
    return ''.join(result[:symbol_count])
