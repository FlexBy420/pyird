import struct

def read_uint32_le(data: bytes, offset: int) -> int:
    return struct.unpack('<I', data[offset:offset + 4])[0]

def unpack_le(fmt: str, data: bytes, offset: int = 0):
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, data[offset:offset + size])[0]