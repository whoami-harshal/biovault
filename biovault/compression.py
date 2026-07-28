# biovault/compression.py
# V2.0 — ZSTD compression before encoding
# Reduces payload size before base-4 conversion

import zstandard as zstd


def compress_data(data: bytes, level: int = 9) -> bytes:
    """Compress raw bytes using ZSTD. Level 9 = good ratio, still fast."""
    cctx = zstd.ZstdCompressor(level=level)
    return cctx.compress(data)


def decompress_data(data: bytes) -> bytes:
    """Decompress ZSTD-compressed bytes back to original."""
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(data)
