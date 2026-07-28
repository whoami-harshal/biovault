# biovault/frames.py
# Core DNA-inspired reading frame logic

SYMBOLS = 'ATGC'
COMPLEMENT = {'A': 'T', 'T': 'A', 'G': 'C', 'C': 'G'}

# ─────────────────────────────────────────
# BINARY ↔ BASE-4 CONVERSION
# ─────────────────────────────────────────

def bytes_to_base4(data: bytes) -> str:
    """Convert raw bytes to ATGC sequence"""
    result = []
    for byte in data:
        # Each byte = 4 base-4 symbols (2 bits each)
        for i in range(4):
            index = (byte >> (6 - 2 * i)) & 0b11
            result.append(SYMBOLS[index])
    return ''.join(result)


def base4_to_bytes(sequence: str) -> bytes:
    """Convert ATGC sequence back to raw bytes"""
    result = []
    # Clean sequence — only valid symbols
    sequence = ''.join(c for c in sequence if c in SYMBOLS)
    # Pad to multiple of 4
    while len(sequence) % 4 != 0:
        sequence += 'A'
    for i in range(0, len(sequence), 4):
        byte = 0
        for j in range(4):
            byte = (byte << 2) | SYMBOLS.index(sequence[i + j])
        result.append(byte)
    return bytes(result)



# READING FRAMES


def get_frame(sequence: str, frame: int) -> str:
    """
    Get forward reading frame (0, 1, or 2)
    Frame 0: ATGCATGC → [ATG][CAT][GC..]
    Frame 1: ATGCATGC → A[TGC][ATG][C..]
    Frame 2: ATGCATGC → AT[GCA][TGC][..]
    """
    if frame not in (0, 1, 2):
        raise ValueError("Frame must be 0, 1, or 2")
    return sequence[frame:]


def get_antisense(sequence: str) -> str:
    """
    Get reverse complement (antisense strand)
    Like DNA's double helix opposite strand
    ATGC → GCAT (reversed complement)
    """
    complemented = ''.join(COMPLEMENT.get(c, c) for c in sequence)
    return complemented[::-1]


def get_antisense_frame(sequence: str, frame: int) -> str:
    """Get reading frame from antisense strand"""
    antisense = get_antisense(sequence)
    return get_frame(antisense, frame)



# ALL 6 READING MODES


READING_MODES = {
    'A0': lambda seq: get_frame(seq, 0),
    'A1': lambda seq: get_frame(seq, 1),
    'A2': lambda seq: get_frame(seq, 2),
    'B0': lambda seq: get_antisense_frame(seq, 0),
    'B1': lambda seq: get_antisense_frame(seq, 1),
    'B2': lambda seq: get_antisense_frame(seq, 2),
}


def apply_reading_mode(sequence: str, mode: str) -> str:
    """Apply a reading mode key to a sequence"""
    if mode not in READING_MODES:
        raise ValueError(f"Invalid mode: {mode}. Use: {list(READING_MODES.keys())}")
    return READING_MODES[mode](sequence)