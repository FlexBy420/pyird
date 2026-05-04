import zlib

def uncompress_gzip(data: bytes) -> bytes:
    if data[:2] == b"\x1f\x8b": # gzip magic number
        return zlib.decompress(data, zlib.MAX_WBITS | 16)
    return data