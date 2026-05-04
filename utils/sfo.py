import struct


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