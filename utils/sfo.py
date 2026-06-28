import os
import struct
from utils.logger import log
from core.iso import ISOHeader

def parse_param_sfo(data: bytes | str) -> dict[str, str]:
    if not isinstance(data, (bytes, bytearray)):
        with open(data, "rb") as f:
            data = f.read()

    magic, _version, key_table_start, data_table_start, num_entries = (
        struct.unpack("<4sIIII", data[0:20])
    )
    if magic != b"\x00PSF":
        raise ValueError("Invalid PARAM.SFO magic")

    entries: dict[str, str] = {}
    for i in range(num_entries):
        base = 0x14 + i * 16
        key_offset, _fmt, data_len, _data_max_len, data_offset = struct.unpack(
            "<HHIII", data[base: base + 16]
        )

        key_abs = key_table_start + key_offset
        key = data[key_abs: data.index(b"\x00", key_abs)].decode("utf-8")

        val_abs = data_table_start + data_offset
        raw_val = data[val_abs: val_abs + data_len]
        try:
            value = raw_val.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            value = raw_val.hex()

        entries[key] = value

    return entries

_BLOCK = 2048
_PROBE_SECTORS = [512, 2048, 8192, 32768]

def _find_sfo_in_iso_data(data: bytes):
    preferred = None
    fallback  = None

    for entry in ISOHeader(data).files:
        upper = entry["name"].upper()
        if not upper.endswith("PARAM.SFO"):
            continue
        if "PS3_GAME" in upper:
            preferred = entry
            break
        if fallback is None:
            fallback = entry

    return preferred or fallback


def read_param_sfo_from_iso(iso_path: str) -> dict[str, str]:
    iso_size = os.path.getsize(iso_path)

    with open(iso_path, "rb") as fh:
        sfo_entry = None

        for sectors in _PROBE_SECTORS:
            read_bytes = min(sectors * _BLOCK, iso_size)
            fh.seek(0)
            data = fh.read(read_bytes)

            sfo_entry = _find_sfo_in_iso_data(data)
            if sfo_entry:
                log(f"[INFO] PARAM.SFO found after reading {read_bytes // _BLOCK} sectors")
                break

            if read_bytes >= iso_size:
                break

        if not sfo_entry:
            log("[WARNING] PARAM.SFO not found in ISO directory tree")
            return {}

        extent, size = sfo_entry["extents"][0]
        fh.seek(extent * _BLOCK)
        sfo_bytes = fh.read(size)

    return parse_param_sfo(sfo_bytes)