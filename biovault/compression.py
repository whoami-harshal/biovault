# biovault/compression.py
# V3 — ZSTD compression before encoding
# Reduces payload size before base-4 conversion

import io
import zstandard as zstd

# Ceiling on what a single layer may expand to. A vault is a container for
# ordinary files, so this is generous; the point is that it is finite.
DEFAULT_MAX_DECOMPRESSED = 256 * 1024 * 1024  # 256 MiB

_CHUNK = 64 * 1024


def compress_data(data: bytes, level: int = 9) -> bytes:
    """Compress raw bytes using ZSTD. Level 9 = good ratio, still fast."""
    cctx = zstd.ZstdCompressor(level=level)
    return cctx.compress(data)


def decompress_data(data: bytes,
                    max_output_size: int = DEFAULT_MAX_DECOMPRESSED) -> bytes:
    """
    Decompress, refusing to produce more than max_output_size bytes.

    Streams rather than calling dctx.decompress(): that call trusts the size
    declared in the frame header and allocates it up front, ignoring its own
    max_output_size argument, so a crafted frame forces a huge allocation.
    Streaming caps actual output, which also covers frames that omit the
    declared size to slip past a header check.
    """
    dctx = zstd.ZstdDecompressor()
    out = io.BytesIO()
    total = 0

    with dctx.stream_reader(io.BytesIO(data)) as reader:
        while True:
            chunk = reader.read(_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > max_output_size:
                raise ValueError(
                    f"Decompressed output exceeds the {max_output_size:,}-byte limit "
                    f"— refusing to continue (possible decompression bomb)"
                )
            out.write(chunk)

    return out.getvalue()
