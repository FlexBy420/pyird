import struct
import zlib
from binascii import crc32
from io import BytesIO
import os
import threading
import queue
import math
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox

def uncompress_gzip(data: bytes) -> bytes:
    if data[:2] == b'\x1f\x8b':  # gzip magic
        return zlib.decompress(data, zlib.MAX_WBITS | 16)
    return data

def read_uint32_le(data: bytes, offset: int) -> int:
    return struct.unpack('<I', data[offset:offset+4])[0]

def unpack_le(fmt: str, data: bytes, offset: int = 0):
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, data[offset:offset+size])[0]

class ISOHeader:
    def __init__(self, data: bytes):
        self.data = data
        self.block_size = 2048
        self.volume_space_size = 0
        self.files = []  # list of dicts
        self._parse()

    def _read_sector(self, sector_index: int) -> bytes:
        off = sector_index * self.block_size
        return self.data[off: off + self.block_size]

    def _scan_volume_descriptors(self):
        start = 16
        picked = None
        picked_enc = 'ascii'  # default
        i = start
        while True:
            if i * self.block_size >= len(self.data):
                break
            sec = self._read_sector(i)
            if len(sec) < 7:
                break
            vtype = sec[0]
            ident = sec[1:6]
            if ident != b'CD001':
                break
            if vtype == 2:
                # SVD (Joliet) - check escape sequences (0x25 0x2F 0x45) etc.
                # Joliet uses UCS-2 BE filenames in the SVD
                picked = sec
                picked_enc = 'utf-16-be'
                break
            if vtype == 1 and picked is None:
                picked = sec
                picked_enc = 'ascii'
            if vtype == 255:
                break
            i += 1
        return picked, picked_enc

    def _extract_root_record(self, desc: bytes) -> bytes:
        root_record = desc[156:156 + 34]
        length = root_record[0]
        if length == 0:
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
        extent_loc = unpack_le('<I', root_record, 2)
        data_len = unpack_le('<I', root_record, 10)
        merged = {}
        order = []

        def read_dir(extent_loc_local, data_len_local, path):
            # Prevent infinite recursion by remembering visited extents
            visited = getattr(read_dir, "_visited", set())
            if extent_loc_local in visited:
                return
            visited.add(extent_loc_local)
            setattr(read_dir, "_visited", visited)

            dir_offset = extent_loc_local * self.block_size
            dir_data = self.data[dir_offset: dir_offset + data_len_local]
            pos = 0
            while pos < len(dir_data):
                if pos >= len(dir_data):
                    break
                length = dir_data[pos]
                if length == 0:
                    # advance to next sector boundary
                    pos = ((pos // self.block_size) + 1) * self.block_size
                    continue
                record = dir_data[pos: pos + length]
                if len(record) < 34:
                    break
                file_id_len = record[32]
                file_id_raw = record[33:33 + file_id_len]
                # Joliet uses UCS-2 BE (utf-16-be), PVD uses ASCII with ;1 suffix
                try:
                    if encoding == 'utf-16-be':
                        # file_id_raw length is in bytes and may be odd; decode as utf-16-be
                        fname = file_id_raw.decode('utf-16-be', errors='ignore')
                    else:
                        fname = file_id_raw.decode('ascii', errors='ignore')
                except Exception:
                    fname = file_id_raw.decode('latin-1', errors='ignore')

                # Remove version number suffixes like ;1 ;2 and trailing nulls
                fname = fname.split(';')[0].rstrip('\x00')

                extent = read_uint32_le(record, 2)
                size = read_uint32_le(record, 10)
                flags = record[25]

                # skip '.' and '..' which sometimes are represented as 0-length or special names
                if fname in ('.', '..', '') and (flags & 0x02):
                    pos += length
                    continue

                full_path = f"{path}/{fname}" if path else fname

                if flags & 0x02:
                    # directory: recurse
                    read_dir(extent, size, full_path)
                else:
                    # file: merge if already present (multi-extent). We'll key by full_path case-sensitively.
                    if full_path in merged:
                        # append extent piece and add size
                        merged[full_path]['extents'].append((extent, size))
                        merged[full_path]['size'] += size
                    else:
                        merged[full_path] = {
                            'name': full_path,
                            'first_extent': extent,
                            'extents': [(extent, size)],
                            'size': size
                        }
                        order.append(full_path)

                pos += length

        read_dir(extent_loc, data_len, path="")
        # Build files list preserving order
        self.files = [merged[name] for name in order]

    @property
    def disc_size_bytes(self) -> int:
        return self.volume_space_size * self.block_size

class IrdFile:
    def __init__(self, offset: int, md5_checksum: bytes):
        self.offset = offset
        self.md5_checksum = md5_checksum

class Ird:
    MAGIC = 0x44524933  # "3IRD" in little-endian

    def __init__(self):
        self.version = 0
        self.product_code = ""
        self.title = ""
        self.title_length = 0
        self.update_version = ""
        self.game_version = ""
        self.app_version = ""
        self.id = 0
        self.header_length = 0
        self.header = None
        self.footer_length = 0
        self.footer = None
        self.region_count = 0
        self.region_md5_checksums = []
        self.file_count = 0
        self.files = []
        self.file_hashes = {}
        self.unknown = 0
        self.pic = None
        self.data1 = None
        self.data2 = None
        self.uid = 0
        self.crc32 = 0
        self.disc_size = 0
        self.iso_files = []

def parse_ird_content(content: bytes) -> Ird:
    stream = BytesIO(content)
    result = Ird()

    # Magic
    stream.read(4)  # skip magic
    result.version = stream.read(1)[0]
    result.product_code = stream.read(9).decode('ascii')

    # Title
    title_length = stream.read(1)[0]
    result.title = stream.read(title_length).decode('utf-8')

    # Versions
    result.update_version = stream.read(4).decode('ascii')
    result.game_version = stream.read(5).decode('ascii')
    result.app_version = stream.read(5).decode('ascii')

    if result.version == 7:
        result.id = struct.unpack('<I', stream.read(4))[0]

    # Header/Footer
    result.header_length = struct.unpack('<I', stream.read(4))[0]
    result.header = stream.read(result.header_length)

    result.footer_length = struct.unpack('<I', stream.read(4))[0]
    result.footer = stream.read(result.footer_length)

    # Regions
    result.region_count = stream.read(1)[0]
    for _ in range(result.region_count):
        result.region_md5_checksums.append(stream.read(16))

    # Files
    result.file_count = struct.unpack('<I', stream.read(4))[0]
    for _ in range(result.file_count):
        offset = struct.unpack('<Q', stream.read(8))[0]
        md5_checksum = stream.read(16)
        result.files.append(IrdFile(offset, md5_checksum))

    result.unknown = struct.unpack('<I', stream.read(4))[0]

    # Version-specific fields
    if result.version == 9:
        result.pic = stream.read(115)
    result.data1 = stream.read(16)
    result.data2 = stream.read(16)
    if result.version < 9:
        result.pic = stream.read(115)

    # UID & CRC32
    result.uid = struct.unpack('<I', stream.read(4))[0]
    data_length = stream.tell()
    result.crc32 = struct.unpack('<I', stream.read(4))[0]

    calculated_crc = crc32(content[:data_length]) & 0xffffffff
    if result.crc32 != calculated_crc:
        print(f"Warning: CRC32 mismatch ({result.crc32:08x} != {calculated_crc:08x})")

    # Parse ISO
    try:
        header_data = uncompress_gzip(result.header)
        iso_header = ISOHeader(header_data)
        result.disc_size = iso_header.disc_size_bytes
        result.iso_files = iso_header.files
    except Exception as e:
        print("ISO parse failed:", e)

    return result

def human_size(n: int) -> str:
    if n is None or n == "":
        return ""
    if n == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(n, 1024)))
    i = min(i, len(units) - 1)
    p = math.pow(1024, i)
    s = round(n / p, 2)
    return f"{s} {units[i]}"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        self.title("PYIRD v2.1")
        self.geometry("1200x700")
        self.minsize(1000, 650)

        self.main = ctk.CTkFrame(self, corner_radius=8)
        self.main.pack(fill="both", expand=True, padx=12, pady=12)

        self.main.grid_columnconfigure(0, weight=1)
        # rows: 0 header row, 1 filename, 2 divider, 3 progress, 4 info, 5 divider, 6 table
        for r in range(7):
            self.main.grid_rowconfigure(r, weight=0)
        self.main.grid_rowconfigure(6, weight=1)  # table expands

        # Top bar: Select button + status text
        self.topbar = ctk.CTkFrame(self.main, fg_color="transparent")
        self.topbar.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 6))
        self.topbar.grid_columnconfigure(0, weight=0)
        self.topbar.grid_columnconfigure(1, weight=1)

        self.pick_btn = ctk.CTkButton(self.topbar, text="Select IRD file", command=self.pick_file)
        self.pick_btn.grid(row=0, column=0, sticky="w")

        self.status_var = ctk.StringVar(value="")
        self.status_lbl = ctk.CTkLabel(self.topbar, textvariable=self.status_var)
        self.status_lbl.grid(row=0, column=1, sticky="e")

        # Loaded file label
        self.loaded_var = ctk.StringVar(value="")
        self.loaded_lbl = ctk.CTkLabel(self.main, textvariable=self.loaded_var, font=("", 14, "bold"))
        self.loaded_lbl.grid(row=1, column=0, sticky="w", pady=(0, 6))

        self._divider(self.main, 2)

        #Progress row
        self.progress_row = ctk.CTkFrame(self.main, fg_color="transparent")
        self.progress_row.grid(row=3, column=0, sticky="ew", pady=6)
        self.progress_row.grid_columnconfigure(0, weight=0)
        self.progress_row.grid_columnconfigure(1, weight=1)

        self.progress = ctk.CTkProgressBar(self.progress_row, mode="indeterminate")
        self.progress.grid(row=0, column=0, padx=(0, 12))
        self.progress_lbl = ctk.CTkLabel(self.progress_row, text="Parsing IRD...")
        self.progress_lbl.grid(row=0, column=1, sticky="w")
        self._set_busy(False)

        # Info table
        self.info_frame = ctk.CTkFrame(self.main)
        self.info_frame.grid(row=4, column=0, sticky="ew", pady=(6, 6))
        for c in range(7):
            self.info_frame.grid_columnconfigure(c, weight=1)

        headers = ["Product Code", "Title", "App Version", "Game Version", "Update Version", "Files", "Total Size"]
        self.info_vars = [ctk.StringVar(value="") for _ in headers]

        # header labels
        for i, h in enumerate(headers):
            lbl = ctk.CTkLabel(self.info_frame, text=h, font=("", 12, "bold"))
            lbl.grid(row=0, column=i, sticky="ew", padx=4, pady=(4, 2))

        # value labels
        for i, var in enumerate(self.info_vars):
            val = ctk.CTkLabel(self.info_frame, textvariable=var)
            val.grid(row=1, column=i, sticky="ew", padx=4, pady=(0, 6))

        self._divider(self.main, 5)

        # Files table
        self.table_frame = ctk.CTkFrame(self.main)
        self.table_frame.grid(row=6, column=0, sticky="nsew", pady=(6, 0))
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        columns = ("name", "offset", "size", "md5")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings", selectmode="browse", height=20)
        self.tree.heading("name", text="Filename")
        self.tree.heading("offset", text="Start Sector")
        self.tree.heading("size", text="Size (bytes)")
        self.tree.heading("md5", text="MD5 Hash")

        self.tree.column("name", anchor="w", stretch=True, width=500)
        self.tree.column("offset", anchor="w", stretch=True, width=150)
        self.tree.column("size", anchor="w", stretch=True, width=150)
        self.tree.column("md5", anchor="w", stretch=True, width=320)

        self.tree.grid(row=0, column=0, sticky="nsew")

        style = ttk.Style(self)
        style.configure("Treeview", rowheight=20)

        # internal state
        self._rows_queue: "queue.Queue[list[tuple]]" = queue.Queue()
        self._inserting = False

    def _divider(self, parent, row_index):
        sep = ttk.Separator(parent, orient="horizontal")
        sep.grid(row=row_index, column=0, sticky="ew", pady=(6, 6))

    def _set_busy(self, busy: bool, msg: str | None = None):
        if busy:
            self.progress_row.grid()
            self.progress.start()
        else:
            self.progress.stop()
            self.progress_row.grid_remove()
        if msg is not None:
            self.status_var.set(msg)

    def pick_file(self):
        path = filedialog.askopenfilename(
            title="Select IRD file",
            filetypes=[("IRD files", "*.ird")]
        )
        if not path:
            return
        self.loaded_var.set(f"Loaded IRD: {os.path.basename(path)}")
        self.status_var.set("")
        self.clear_table()
        self._load_ird(path)

    def clear_table(self):
        self.tree.delete(*self.tree.get_children())

    def _load_ird(self, path: str):
        self._set_busy(True, "Reading file...")
        t = threading.Thread(target=self._parse_and_fill, args=(path,), daemon=True)
        t.start()

    def _parse_and_fill(self, path: str):
        try:
            with open(path, "rb") as f:
                content = f.read()
            content = uncompress_gzip(content)

            magic = struct.unpack("<I", content[:4])[0]
            if magic != Ird.MAGIC:
                raise ValueError("Not a valid IRD file")

            self._set_status_threadsafe("Parsing IRD header...")
            ird = parse_ird_content(content)

            # Build rows
            rows = []
            self._set_status_threadsafe("Preparing rows...")
            for i, ird_file in enumerate(ird.files):
                if i < len(ird.iso_files):
                    fdata = ird.iso_files[i]
                    name = fdata["name"]
                    size = fdata["size"]
                else:
                    name = f"File {i}"
                    size = ""
                rows.append((
                    name,
                    str(ird_file.offset),
                    str(size),
                    ird_file.md5_checksum.hex()
                ))

            # update info section
            self._update_info_threadsafe(
                product_code=ird.product_code,
                title=ird.title,
                app_version=ird.app_version,
                game_version=ird.game_version,
                update_version=ird.update_version,
                file_count=str(ird.file_count),
                total_size=f"{ird.disc_size} ({human_size(ird.disc_size)})" if ird.disc_size else ""
            )

            BATCH = 500
            for i in range(0, len(rows), BATCH):
                self._rows_queue.put(rows[i:i+BATCH])

            self._schedule_insert_batches()
        except Exception as ex:
            self._show_error_threadsafe(f"Failed to load IRD.\n\n{ex}")

    def _set_status_threadsafe(self, msg: str):
        self.after(0, lambda: self.status_var.set(msg))

    def _update_info_threadsafe(
        self,
        product_code: str,
        title: str,
        app_version: str,
        game_version: str,
        update_version: str,
        file_count: str,
        total_size: str
    ):
        def apply():
            vals = [product_code, title, app_version, game_version, update_version, file_count, total_size]
            for var, v in zip(self.info_vars, vals):
                var.set(v)
        self.after(0, apply)

    def _show_error_threadsafe(self, msg: str):
        def apply():
            self._set_busy(False, "")
            messagebox.showerror("Error", msg)
        self.after(0, apply)

    def _schedule_insert_batches(self):
        if self._inserting:
            return
        self._inserting = True
        self._set_busy(True, "Rendering table...")
        self.after(0, self._insert_next_batch)

    def _insert_next_batch(self):
        try:
            batch = self._rows_queue.get_nowait()
        except queue.Empty:
            self._inserting = False
            self._set_busy(False, "Done.")
            return

        for row in batch:
            self.tree.insert("", "end", values=row)

        self.after(1, self._insert_next_batch)

if __name__ == "__main__":
    App().mainloop()