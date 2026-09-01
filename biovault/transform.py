# biovault/transform.py
# V4 — the base-4 pipeline, done on bytes instead of characters.
#
# frames.py and packer.py are the readable reference implementation: they build
# an actual "ATGC" string so the DNA model is obvious. That costs a Python-level
# loop and a string four times the size of the payload, which put throughput
# around 3.5 seconds per megabyte — far too slow to sign and ship a real release
# artifact.
#
# This module produces byte-for-byte identical output using three observations:
#
#   1. Packing base-4 symbols back into bytes is the exact inverse of unpacking
#      them, so pack(bytes_to_base4(x)) == x. On mode A0 the entire ATGC round
#      trip is the identity function.
#   2. Complementing a symbol (A<->T, G<->C) flips the low bit of its 2-bit
#      index, so complementing a whole packed stream is XOR with 0x55.
#   3. Reversing the symbol order means reversing the bytes and reversing the
#      four symbols inside each byte — one 256-entry translation table.
#
# A frame offset prepends `frame` zero-symbols, which is a right shift of the
# whole bit stream by 2*frame bits.
#
# test_fast_path_matches_reference keeps the two implementations honest.

SYMBOLS_PER_BYTE = 4

# Reverse the four symbols within a byte AND complement each one.
_REVCOMP = bytes(
    ((((b >> 0) & 0b11) ^ 1) << 6) |
    ((((b >> 2) & 0b11) ^ 1) << 4) |
    ((((b >> 4) & 0b11) ^ 1) << 2) |
    ((((b >> 6) & 0b11) ^ 1) << 0)
    for b in range(256)
)


def _reverse_complement(data: bytes) -> bytes:
    """Reverse-complement a byte-aligned symbol stream."""
    return data.translate(_REVCOMP)[::-1]


def payload_to_packed(payload: bytes, mode: str) -> tuple[bytes, int]:
    """
    Run a payload through base-4 encoding, the reading frame, and packing.
    Returns (packed_bytes, sequence_length).
    """
    frame = int(mode[1])

    # Mode B reads the antisense strand. The payload is a whole number of
    # bytes, so its symbol stream is always a multiple of four and can be
    # reverse-complemented byte-wise.
    stream = payload if mode[0] == 'A' else _reverse_complement(payload)

    sequence_length = SYMBOLS_PER_BYTE * len(payload) + frame
    if frame == 0:
        return stream, sequence_length

    # Prepending `frame` zero-symbols shifts everything right by 2*frame bits.
    packed_length = (sequence_length + SYMBOLS_PER_BYTE - 1) // SYMBOLS_PER_BYTE
    pad_bits = 8 * packed_length - 2 * sequence_length

    value = int.from_bytes(stream, 'big') << pad_bits
    return value.to_bytes(packed_length, 'big'), sequence_length


def packed_to_payload(packed: bytes, sequence_length: int, mode: str,
                      payload_length: int) -> bytes:
    """Inverse of payload_to_packed, trimmed to payload_length."""
    frame = int(mode[1])

    if frame == 0:
        stream = packed
    else:
        # Undo the right shift, then drop the leading frame symbols.
        pad_bits = 8 * len(packed) - 2 * sequence_length
        value = int.from_bytes(packed, 'big') >> pad_bits

        body_symbols = sequence_length - frame
        body_bytes = (body_symbols + SYMBOLS_PER_BYTE - 1) // SYMBOLS_PER_BYTE
        # Re-align the remaining symbols to a byte boundary.
        value <<= 8 * body_bytes - 2 * body_symbols
        stream = value.to_bytes(body_bytes, 'big')

    if mode[0] != 'A':
        stream = _reverse_complement(stream)

    return stream[:payload_length]
