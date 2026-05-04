import struct
from binascii import crc32
from io import BytesIO
from utils.logger import log
from utils.gzip import uncompress_gzip
from core.iso import ISOHeader

class IrdFile:
    def __init__(self, offset: int, md5_checksum: bytes):
        self.offset:        int   = offset
        self.md5_checksum:  bytes = md5_checksum

class Ird:
    MAGIC = 0x44524933  # "3IRD" little-endian

    def __init__(self):
        self.version:              int         = 0
        self.product_code:         str         = ""
        self.title:                str         = ""
        self.title_length:         int         = 0
        self.update_version:       str         = ""
        self.game_version:         str         = ""
        self.app_version:          str         = ""
        self.id:                   int         = 0
        self.header_length:        int         = 0
        self.header:               bytes | None = None
        self.footer_length:        int         = 0
        self.footer:               bytes | None = None
        self.region_count:         int         = 0
        self.region_md5_checksums: list[bytes] = []
        self.file_count:           int         = 0
        self.files:                list[IrdFile] = []
        self.file_hashes:          dict        = {}
        self.unknown:              int         = 0
        self.pic:                  bytes | None = None
        self.data1:                bytes | None = None
        self.data2:                bytes | None = None
        self.uid:                  int         = 0
        self.crc32:                int         = 0
        self.disc_size:            int         = 0
        self.iso_files:            list[dict]  = []

def parse_ird_content(content: bytes) -> Ird:
    stream = BytesIO(content)
    result = Ird()

    stream.read(4) # skip magic
    result.version      = stream.read(1)[0]
    result.product_code = stream.read(9).decode("ascii")

    title_length = stream.read(1)[0]
    result.title = stream.read(title_length).decode("utf-8")

    result.update_version = stream.read(4).decode("ascii")
    result.game_version   = stream.read(5).decode("ascii")
    result.app_version    = stream.read(5).decode("ascii")

    if result.version == 7:
        result.id = struct.unpack("<I", stream.read(4))[0]

    result.header_length = struct.unpack("<I", stream.read(4))[0]
    result.header        = stream.read(result.header_length)

    result.footer_length = struct.unpack("<I", stream.read(4))[0]
    result.footer        = stream.read(result.footer_length)

    result.region_count = stream.read(1)[0]
    for _ in range(result.region_count):
        result.region_md5_checksums.append(stream.read(16))

    result.file_count = struct.unpack("<I", stream.read(4))[0]
    for _ in range(result.file_count):
        offset       = struct.unpack("<Q", stream.read(8))[0]
        md5_checksum = stream.read(16)
        result.files.append(IrdFile(offset, md5_checksum))

    result.unknown = struct.unpack("<I", stream.read(4))[0]

    if result.version == 9:
        result.pic = stream.read(115)
    result.data1 = stream.read(16)
    result.data2 = stream.read(16)
    if result.version < 9:
        result.pic = stream.read(115)

    result.uid      = struct.unpack("<I", stream.read(4))[0]
    data_length     = stream.tell()
    result.crc32    = struct.unpack("<I", stream.read(4))[0]

    calculated_crc = crc32(content[:data_length]) & 0xFFFFFFFF
    if result.crc32 != calculated_crc:
        log(f"[WARNING] CRC32 mismatch ({result.crc32:08x} != {calculated_crc:08x})")

    try:
        header_data     = uncompress_gzip(result.header)
        iso_header      = ISOHeader(header_data)
        result.disc_size  = iso_header.disc_size_bytes
        result.iso_files  = iso_header.files
    except Exception as e:
        log(f"[ERROR] ISO parse failed: {e}")

    return result