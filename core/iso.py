from utils.fs import read_uint32_le, unpack_le

class ISOHeader:

    def __init__(self, data: bytes):
        self.data = data
        self.block_size = 2048
        self.volume_space_size = 0
        self.files: list[dict] = []
        self._parse()

    def _read_sector(self, sector_index: int) -> bytes:
        off = sector_index * self.block_size
        return self.data[off: off + self.block_size]

    def _scan_volume_descriptors(self) -> tuple[bytes | None, str]:
        start = 16
        picked = None
        picked_enc = "ascii"
        i = start
        while True:
            if i * self.block_size >= len(self.data):
                break
            sec = self._read_sector(i)
            if len(sec) < 7:
                break
            vtype = sec[0]
            ident = sec[1:6]
            if ident != b"CD001":
                break
            if vtype == 2: # SVD (Joliet) - UCS-2 BE filenames
                picked = sec
                picked_enc = "utf-16-be"
                break
            if vtype == 1 and picked is None:
                picked = sec
                picked_enc = "ascii"
            if vtype == 255:
                break
            i += 1
        return picked, picked_enc

    def _extract_root_record(self, desc: bytes) -> bytes:
        root_record = desc[156:156 + 34]
        if root_record[0] == 0:
            root_record = desc[156:156 + 2048]
        return root_record

    def _parse(self):
        desc, encoding = self._scan_volume_descriptors()
        if not desc:
            return

        self.volume_space_size = read_uint32_le(desc, 80)
        root_record = self._extract_root_record(desc)
        if len(root_record) < 14:
            return

        extent_loc = unpack_le("<I", root_record, 2)
        data_len   = unpack_le("<I", root_record, 10)

        merged: dict[str, dict] = {}
        order:  list[str]       = []

        def read_dir(extent_loc_local: int, data_len_local: int, path: str):
            visited = getattr(read_dir, "_visited", set())
            if extent_loc_local in visited:
                return
            visited.add(extent_loc_local)
            setattr(read_dir, "_visited", visited)

            dir_offset = extent_loc_local * self.block_size
            dir_data   = self.data[dir_offset: dir_offset + data_len_local]
            pos = 0

            while pos < len(dir_data):
                length = dir_data[pos]
                if length == 0:
                    # Advance to the next sector boundary
                    pos = ((pos // self.block_size) + 1) * self.block_size
                    continue

                record = dir_data[pos: pos + length]
                if len(record) < 34:
                    break

                file_id_len = record[32]
                file_id_raw = record[33:33 + file_id_len]

                try:
                    if encoding == "utf-16-be":
                        fname = file_id_raw.decode("utf-16-be", errors="ignore")
                    else:
                        fname = file_id_raw.decode("ascii", errors="ignore")
                except Exception:
                    fname = file_id_raw.decode("latin-1", errors="ignore")

                # Strip version suffix (;1, ;2 …) and trailing nulls
                fname = fname.split(";")[0].rstrip("\x00")

                extent = read_uint32_le(record, 2)
                size   = read_uint32_le(record, 10)
                flags  = record[25]

                # Skip "." and ".." directory entries
                if fname in (".", "..", "") and (flags & 0x02):
                    pos += length
                    continue

                full_path = f"{path}/{fname}" if path else fname

                if flags & 0x02:
                    read_dir(extent, size, full_path)
                else:
                    if full_path in merged:
                        # Multi-extent file - append and accumulate size
                        merged[full_path]["extents"].append((extent, size))
                        merged[full_path]["size"] += size
                    else:
                        merged[full_path] = {
                            "name":         full_path,
                            "first_extent": extent,
                            "extents":      [(extent, size)],
                            "size":         size,
                        }
                        order.append(full_path)

                pos += length

        read_dir(extent_loc, data_len, path="")
        self.files = [merged[name] for name in order]

    @property
    def disc_size_bytes(self) -> int:
        return self.volume_space_size * self.block_size