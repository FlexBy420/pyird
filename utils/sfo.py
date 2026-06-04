import os
import struct
import tempfile


def parse_param_sfo(path: str) -> dict[str, str]:
    with open(path, "rb") as f:
        data = f.read()

    magic, version, key_table_start, data_table_start, tables_entries = (
        struct.unpack("<4sIIII", data[0:20])
    )
    if magic != b"\0PSF":
        raise ValueError("Invalid PARAM.SFO file")

    entries: dict[str, str] = {}
    for i in range(tables_entries):
        entry_offset = 0x14 + i * 16
        key_offset, fmt, data_len, data_max_len, data_offset = struct.unpack(
            "<HHIII", data[entry_offset:entry_offset + 16]
        )
        key_off_abs = key_table_start + key_offset
        key = data[key_off_abs: data.find(b"\x00", key_off_abs)].decode("utf-8")

        val_off_abs = data_table_start + data_offset
        raw_val = data[val_off_abs: val_off_abs + data_len]
        try:
            value = raw_val.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            value = raw_val.hex()

        entries[key] = value

    return entries


def read_param_sfo_from_iso(iso_path: str) -> dict[str, str]:
    from core.iso import ISOHeader
    from utils.logger import log

    BLOCK = 2048

    with open(iso_path, "rb") as fh:
        fast_data = fh.read(512 * BLOCK)
        sfo_entry = next(
            (f for f in ISOHeader(fast_data).files
             if f["name"].upper().endswith("PARAM.SFO")),
            None,
        )

        if not sfo_entry:
            fh.seek(0)
            full_data = fh.read(4096 * BLOCK)
            sfo_entry = next(
                (f for f in ISOHeader(full_data).files
                 if f["name"].upper().endswith("PARAM.SFO")),
                None,
            )

        if not sfo_entry:
            log("[WARNING] PARAM.SFO not found in ISO directory tree")
            return {}

        extent, size = sfo_entry["extents"][0]
        fh.seek(extent * BLOCK)
        sfo_bytes = fh.read(size)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".sfo") as tmp:
        tmp.write(sfo_bytes)
        tmp_path = tmp.name
    try:
        return parse_param_sfo(tmp_path)
    finally:
        os.unlink(tmp_path)