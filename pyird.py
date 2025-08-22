import struct
import zlib
from binascii import crc32
from io import BytesIO
import os
import threading
import queue
import math
import hashlib
import mmap
import requests
import json
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
IRD_DIR = os.path.join(APP_ROOT, "ird")

BASE_IRD_URL = "https://github.com/FlexBy420/playstation_3_ird_database/raw/main/"
JSON_URL = "https://flexby420.github.io/playstation_3_ird_database/all.json"

def load_local_ird(title_id, app_ver, game_ver, fw_ver, update_ver=None):
    if not title_id:
        return None
    title_id = title_id.upper()
    if not os.path.exists(IRD_DIR):
        return None

    for f in os.listdir(IRD_DIR):
        if f.upper().startswith(title_id) and f.lower().endswith(".ird"):
            path = os.path.join(IRD_DIR, f)
            try:
                with open(path, "rb") as fp:
                    content = fp.read()
                content = uncompress_gzip(content)

                magic = struct.unpack("<I", content[:4])[0]
                if magic != Ird.MAGIC:
                    continue  # skip invalid

                ird = parse_ird_content(content)

                # strict check
                if (ird.product_code.upper() == title_id and
                    ird.app_version.strip() == (app_ver or "").strip() and
                    ird.game_version.strip() == (game_ver or "").strip() and
                    ird.update_version.strip() == (update_ver or "").strip()):
                    return path
            except Exception as e:
                print(f"Failed to check local IRD {path}: {e}")
                continue
    return None

def _norm(s):
    return (s or "").strip()

def _fw_tuple(s):
    s = _norm(s)
    parts = []
    for p in s.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)

def fetch_remote_ird(title_id, app_ver, game_ver, fw_ver):
    title_id = (title_id or "").upper()
    app_ver  = (app_ver or "").strip()
    game_ver = (game_ver or "").strip()
    fw_ver   = (fw_ver or "").strip()

    resp = requests.get(JSON_URL, timeout=20)
    resp.raise_for_status()
    ird_data = resp.json()

    if title_id not in ird_data:
        return None

    for entry in ird_data[title_id]:
        if ((entry.get("app-ver") or "").strip() == app_ver and
            (entry.get("game-ver") or "").strip() == game_ver and
            (entry.get("fw-ver") or "").strip() == fw_ver):

            # build local file path
            fname = os.path.basename(entry["link"])
            if not fname.lower().endswith(".ird"):
                fname += ".ird"
            local_path = os.path.join(IRD_DIR, fname)

            # download file
            os.makedirs(IRD_DIR, exist_ok=True)
            url = BASE_IRD_URL + entry["link"]
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            with open(local_path, "wb") as f:
                f.write(r.content)
            return local_path

    # no exact match
    return None

def auto_get_ird(param_sfo):
    title_id = (param_sfo or {}).get("TITLE_ID")
    app_ver  = (param_sfo or {}).get("APP_VER")
    game_ver = (param_sfo or {}).get("VERSION")
    update_ver = (param_sfo or {}).get("UPDATE_VER")

    # normalize FW_VER from PS3_SYSTEM_VER
    fw_ver = (param_sfo or {}).get("PS3_SYSTEM_VER")
    if fw_ver:
        # "043.3100" -> "4.31"
        fw_ver = fw_ver.lstrip("0")
        if fw_ver.endswith("00"):
            fw_ver = fw_ver[:-2]
        if fw_ver.startswith("0"):
            fw_ver = fw_ver[1:]

    if not title_id:
        messagebox.showwarning("IRD Auto", "Missing TITLE_ID in PARAM.SFO")
        return None

    # local check
    local = load_local_ird(title_id, app_ver, game_ver, fw_ver, update_ver)
    if local:
        return local

    # remote fetch
    try:
        remote = fetch_remote_ird(title_id, app_ver, game_ver, fw_ver)
        if remote:
            return remote
        else:
            messagebox.showwarning(
                "IRD Auto",
                f"No matching IRD found online for {title_id}\n"
                f"(APP_VER={app_ver}, GAME_VER={game_ver}, UPDATE_VER={update_ver}, FW_VER={fw_ver})"
            )
    except Exception as e:
        messagebox.showwarning("IRD Auto", f"Failed to fetch IRD: {e}")
    return None

def uncompress_gzip(data: bytes) -> bytes:
    if data[:2] == b"\x1f\x8b":  # gzip magic
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

    calculated_crc = crc32(content[:data_length]) & 0xFFFFFFFF
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

        self.title("PYIRD v2.4 (Experimental)")
        self.geometry("1300x740")
        self.minsize(1100, 680)

        self.main = ctk.CTkFrame(self, corner_radius=8)
        self.main.pack(fill="both", expand=True, padx=12, pady=12)

        self.main.grid_columnconfigure(0, weight=1)
        for r in range(8):
            self.main.grid_rowconfigure(r, weight=0)
        self.main.grid_rowconfigure(7, weight=1)

        # Top bar
        self.topbar = ctk.CTkFrame(self.main, fg_color="transparent")
        self.topbar.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 6))
        self.topbar.grid_columnconfigure(0, weight=0)
        self.topbar.grid_columnconfigure(1, weight=0)
        self.topbar.grid_columnconfigure(2, weight=1)

        self.pick_btn = ctk.CTkButton(self.topbar, text="Select IRD File", command=self.pick_file, state="disabled")
        self.pick_btn.grid(row=0, column=0, sticky="w")
        self.pick_folder_btn = ctk.CTkButton(self.topbar, text="Select Game Folder", command=self.pick_folder)
        self.pick_folder_btn.grid(row=0, column=1, padx=(8, 0), sticky="w")

        self.status_var = ctk.StringVar(value="")
        self.status_lbl = ctk.CTkLabel(self.topbar, textvariable=self.status_var)
        self.status_lbl.grid(row=0, column=2, sticky="e")

        # IRD & JB labels
        self.loaded_ird_var = ctk.StringVar(value="")
        self.loaded_ird_lbl = ctk.CTkLabel(self.main, textvariable=self.loaded_ird_var, font=("", 14, "bold"))
        self.loaded_ird_lbl.grid(row=1, column=0, sticky="w")

        self.loaded_jb_var = ctk.StringVar(value="")
        self.loaded_jb_lbl = ctk.CTkLabel(self.main, textvariable=self.loaded_jb_var, font=("", 14, "bold"))
        self.loaded_jb_lbl.grid(row=2, column=0, sticky="w", pady=(0, 6))

        self._divider(self.main, 3)

        # Progress
        self.progress_row = ctk.CTkFrame(self.main, fg_color="transparent")
        self.progress_row.grid(row=4, column=0, sticky="ew", pady=6)
        self.progress_row.grid_columnconfigure(0, weight=0)
        self.progress_row.grid_columnconfigure(1, weight=1)

        self.progress = ctk.CTkProgressBar(self.progress_row, mode="indeterminate")
        self.progress.grid(row=0, column=0, padx=(0, 12))
        self.progress_lbl = ctk.CTkLabel(self.progress_row, text="Working...")
        self.progress_lbl.grid(row=0, column=1, sticky="w")
        self._set_busy(False)

        # Info frame
        self.info_frame = ctk.CTkFrame(self.main)
        self.info_frame.grid(row=5, column=0, sticky="ew", pady=(6, 6))
        for c in range(7):
            self.info_frame.grid_columnconfigure(c, weight=1)

        headers = ["Product Code", "Title", "App Version", "Game Version", "Update Version", "Files", "Total Size"]
        self.info_vars = [ctk.StringVar(value="") for _ in headers]
        self.info_labels = []

        for i, h in enumerate(headers):
            lbl = ctk.CTkLabel(self.info_frame, text=h, font=("", 12, "bold"))
            lbl.grid(row=0, column=i, sticky="ew", padx=4, pady=(4, 2))
        for i, var in enumerate(self.info_vars):
            val = ctk.CTkLabel(self.info_frame, textvariable=var)
            val.grid(row=1, column=i, sticky="ew", padx=4, pady=(0, 6))
            self.info_labels.append(val)

        self._divider(self.main, 6)

        # Treeview Table
        self.table_container = ctk.CTkFrame(self.main)
        self.table_container.grid(row=7, column=0, sticky="nsew", pady=(6, 0))
        self.table_container.grid_columnconfigure(0, weight=1)
        self.table_container.grid_rowconfigure(0, weight=1)

        self.table_headers = ("Filename", "Size (bytes)", "MD5 (IRD)", "Size (JB)", "MD5 (JB)", "Result")

        self.tree = ttk.Treeview(self.table_container, columns=self.table_headers, show="headings")
        self.tree.grid(row=0, column=0, sticky="nsew")

        for col in self.table_headers:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="w", width=150, stretch=True)

        self._rows = []  # store tree item IDs

        self.current_ird = None
        self.current_jb = None
        self.param_sfo = None

        self._result_q = queue.Queue()
        self._summary_counts = {"ok":0, "missing":0, "mismatch":0}
        self.after(50, self._drain_results)

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

    def _show_error_threadsafe(self, msg: str):
        def apply():
            self._set_busy(False, "")
            messagebox.showerror("Error", msg)
        self.after(0, apply)

    def _set_status_threadsafe(self, msg: str):
        self.after(0, lambda: self.status_var.set(msg))

    def _clear_table(self):
        for iid in self._rows:
            self.tree.delete(iid)
        self._rows.clear()

    def reset_app_state(self):
        # Clear IRD and JB data
        self.current_ird = None
        self.current_jb = None
        self.param_sfo = None

        # Clear labels
        self.loaded_ird_var.set("")
        self.loaded_jb_var.set("")
        for var in self.info_vars:
            var.set("")

        # Clear the treeview table
        self._clear_table()

        # Reset status and progress
        self.status_var.set("")
        self._set_busy(False)
        self.progress_lbl.configure(text="Working...")

        # Reset summary counts
        self._summary_counts = {"ok": 0, "missing": 0, "mismatch": 0}

        # Disable IRD button until a new folder is loaded
        self.pick_btn.configure(state="disabled")

        # Clear the result queue
        while not self._result_q.empty():
            try:
                self._result_q.get_nowait()
            except queue.Empty:
                break

    def _add_table_row(self, values: list[str], tag: str = ""):
        if tag in ("missing", "mismatch"):
            iid = self.tree.insert("", 0, values=values, tags=(tag,))
            self._rows.insert(0, iid)
        else:
            iid = self.tree.insert("", "end", values=values, tags=(tag,))
            self._rows.append(iid)

    def _drain_results(self, max_per_tick: int = 1200):
        if self._result_q.qsize() > 5000:
            max_per_tick = 3000
        processed = 0
        while processed < max_per_tick and not self._result_q.empty():
            idx, jb_size, jb_md5, result, tag = self._result_q.get()
            if 0 <= idx < len(self._rows):
                vals = list(self.tree.item(self._rows[idx], "values"))
                vals[3] = jb_size or ""
                vals[4] = jb_md5 or ""
                vals[5] = result or ""
                self.tree.item(self._rows[idx], values=vals)
                self.tree.tag_configure("ok", background="#eaffea")
                self.tree.tag_configure("missing", background="#ffecec")
                self.tree.tag_configure("mismatch", background="#fff5d6")
                self.tree.item(self._rows[idx], tags=(tag,))

                if tag in ("missing", "mismatch"):
                    self.tree.move(self._rows[idx], "", 0)

            if tag in self._summary_counts:
                self._summary_counts[tag] += 1
            processed += 1
        self.after(25, self._drain_results)

    def _parse_param_sfo(self, path):
        with open(path, "rb") as f:
            data = f.read()
        magic, version, key_table_start, data_table_start, tables_entries = struct.unpack("<4sIIII", data[0:20])
        if magic != b"\0PSF":
            raise ValueError("Invalid PARAM.SFO file")
        entries = {}
        for i in range(tables_entries):
            entry_offset = 0x14 + i * 16
            key_offset, fmt, data_len, data_max_len, data_offset = struct.unpack("<HHIII", data[entry_offset:entry_offset+16])
            key_off_abs = key_table_start + key_offset
            key = data[key_off_abs:data.find(b"\x00", key_off_abs)].decode("utf-8")
            val_off_abs = data_table_start + data_offset
            raw_val = data[val_off_abs: val_off_abs + data_len]
            try:
                value = raw_val.decode("utf-8").rstrip("\x00")
            except UnicodeDecodeError:
                value = raw_val.hex()
            entries[key] = value
        return entries

    def _compare_param_with_ird(self):
        if not self.current_ird or not self.param_sfo:
            return True  # nothing to compare yet

        mismatches = []
        ird_fields = {
            "TITLE_ID": (self.info_vars[0], self.info_labels[0], "Product Code"),
            "APP_VER": (self.info_vars[2], self.info_labels[2], "App Version"),
            "VERSION": (self.info_vars[3], self.info_labels[3], "Game Version"),
            "UPDATE_VER": (self.info_vars[4], self.info_labels[4], "Update Version"),
        }

        # check mismatches and mark labels
        for key, (var, label, display_name) in ird_fields.items():
            ird_val = var.get()
            sfo_val = self.param_sfo.get(key)
            if sfo_val and sfo_val != ird_val:
                mismatches.append(f"{display_name} in IRD: {ird_val}\n{display_name} in Game Files: {sfo_val}")
                label.configure(text_color="red")
            else:
                label.configure(text_color="white")

        # show all mismatches in a single messagebox
        if mismatches:
            messagebox.showerror(
                "IRD mismatch",
                "The provided IRD does not appear to be for this game.\nPlease choose the correct IRD.\n\n" +
                "\n".join(mismatches)
            )
            # unload wrong ird
            self.current_ird = None
            self.loaded_ird_var.set("")
            self.clear_table()
            for var in self.info_vars:
                var.set("")
            return False  # stop validation
        return True

    def pick_file(self):
        path = filedialog.askopenfilename(
            title="Select IRD file",
            filetypes=[("IRD files", "*.ird")]
        )
        if not path:
            return
        self.loaded_ird_var.set(f"Loaded IRD: {os.path.basename(path)}")
        self.status_var.set("")
        self._load_ird(path, source="user")
        if not self._compare_param_with_ird():
            return

    def pick_folder(self):
        root = filedialog.askdirectory(title="Select Game Folder (contains PS3_GAME, etc.)")
        if not root:
            return
        
        self.reset_app_state()

        if not os.path.isdir(os.path.join(root, "PS3_GAME")):
            messagebox.showerror("Invalid Folder", "Selected folder does not contain PS3_GAME.")
            return

        self.current_jb = root
        self.loaded_jb_var.set(f"Loaded Game Folder: {root}")
        self.pick_btn.configure(state="normal")

        sfo_path = os.path.join(root, "PS3_GAME", "PARAM.SFO")
        if os.path.exists(sfo_path):
            try:
                self.param_sfo = self._parse_param_sfo(sfo_path)
                if not self._compare_param_with_ird():
                    return
            except Exception as e:
                messagebox.showwarning("PARAM.SFO", f"Failed to parse PARAM.SFO: {e}")

        # auto ird fetch
        ird_path = auto_get_ird(self.param_sfo)
        if ird_path:
            self._load_ird(ird_path, source="auto")
        else:
            self.status_var.set("IRD not found for this game.")

    def clear_table(self):
        self._clear_table()

    def _load_ird(self, path: str, source: str = "user"):
        if source == "user":
            self.loaded_ird_var.set(f"Loaded IRD: {os.path.basename(path)}")
        elif source == "auto":
            self.loaded_ird_var.set(f"Auto-Fetched IRD: {os.path.basename(path)}")

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
            self.current_ird = ird

            # Build rows
            self._set_status_threadsafe("Preparing rows...")
            offset_to_file = {f['first_extent']: f for f in ird.iso_files}

            def apply_rows():
                self._clear_table()
                for ird_file in ird.files:
                    fdata = offset_to_file.get(ird_file.offset)
                    if fdata:
                        name = fdata['name']
                        size = fdata['size']
                    else:
                        name = f"File {ird_file.offset}"
                        size = ""
                    self._add_table_row([
                        name,
                        str(size),
                        ird_file.md5_checksum.hex(),
                        "",  # jb_size
                        "",  # jb_md5
                        ""   # result
                    ])

                # extra file
                if self.current_jb:
                    file_map = self._build_case_insensitive_file_map(self.current_jb)
                    ird_set = set(self._normalize_path_for_match(f['name']) for f in ird.iso_files)
                    extra_files = [full_path for rel_path, full_path in file_map.items()
                                   if self._normalize_path_for_match(rel_path) not in ird_set]

                    for full_path in extra_files:
                        rel_path = os.path.relpath(full_path, self.current_jb).replace("\\", "/")
                        self.tree.insert("", 0, values=[
                            rel_path,
                            "",  # size
                            "",  # md5 IRD
                            "",  # size JB
                            "",  # md5 JB
                            "Extra File"
                        ], tags=("extra",))
                    self.tree.tag_configure("extra", background="#d0f0ff")

                # update info section
                vals = [
                    ird.product_code,
                    ird.title,
                    ird.app_version,
                    ird.game_version,
                    ird.update_version,
                    str(ird.file_count),
                    f"{ird.disc_size} ({human_size(ird.disc_size)})" if ird.disc_size else ""
                ]
                for var, v in zip(self.info_vars, vals):
                    var.set(v)

            self.after(0, apply_rows)

            def finish_and_maybe_validate():
                self._set_busy(False, "Done.")
                # Auto-validate
                if self.current_jb:
                    if self._compare_param_with_ird():
                        self._validate_jb_folder(self.current_jb)
            self.after(0, finish_and_maybe_validate)

        except Exception as ex:
            self._show_error_threadsafe(f"Failed to load IRD.{ex}")

    def _validate_jb_folder(self, root: str):
        self._set_busy(True, "Scanning JB folder...")
        t = threading.Thread(target=self._validate_worker, args=(root,), daemon=True)
        t.start()

    @staticmethod
    def _normalize_path_for_match(rel_path: str) -> str:
        return rel_path.replace("\\", "/").strip("/").rstrip(".").lower()

    @staticmethod
    def _build_case_insensitive_file_map(root: str) -> dict[str, str]:
        mapping: dict[str, str] = {}
        root = os.path.abspath(root)
        for base, _, files in os.walk(root):
            for fn in files:
                full = os.path.join(base, fn)
                rel = os.path.relpath(full, root)
                mapping[App._normalize_path_for_match(rel)] = full
        return mapping

    @staticmethod
    def _md5_of_file(path: str, chunk_size: int = 4 * 1024 * 1024, mmap_threshold: int = 2048 * 1024 * 1024) -> tuple[str, int]:
        h = hashlib.md5()
        size = os.path.getsize(path)
        # special case: empty file
        if size == 0:
            return h.hexdigest(), 0
        with open(path, "rb") as f:
            if size <= mmap_threshold:
                # mmap the whole file (2 GB)
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    h.update(mm)
            else:
                # stream in chunks (4 MB)
                while chunk := f.read(chunk_size):
                    h.update(chunk)
        return h.hexdigest(), size

    def _validate_worker(self, root: str):
        try:
            ird = self.current_ird
            if not ird:
                self._set_status_threadsafe("Load an IRD first")
                self._set_busy(False)
                return

            while not self._result_q.empty():
                try: self._result_q.get_nowait()
                except queue.Empty: break
            self._summary_counts = {"ok": 0, "missing": 0, "mismatch": 0}

            total_files = len(ird.files)
            self._files_done = 0  # counter for progress

            file_map = self._build_case_insensitive_file_map(root)
            self._set_status_threadsafe("Validating files...")
            self.progress_lbl.configure(text=f"0 / {total_files} files")

            file_queue = queue.Queue(maxsize=20)  # buffer between producer and workers
            cpu_total = os.cpu_count() or 4
            num_workers = max(1, cpu_total // 2)

            # sequential file listing
            def producer():
                for idx, f in enumerate(ird.files):
                    iso_entry = next((e for e in ird.iso_files if e['first_extent'] == f.offset), None)
                    rel = iso_entry['name'] if iso_entry else f"File {f.offset}"
                    key = self._normalize_path_for_match(rel)
                    real_path = file_map.get(key)
                    if real_path:
                        file_queue.put((idx, f, rel, real_path))
                    else:
                        file_queue.put((idx, f, rel, None))  # missing file

                # signal workers to stop
                for _ in range(num_workers):
                    file_queue.put(None)

            # CPU-bound validation
            def worker():
                while True:
                    item = file_queue.get()
                    if item is None:
                        break
                    idx, f, rel, real_path = item

                    if real_path is None:
                        result = (idx, None, None, "Missing", "missing")
                    else:
                        try:
                            md5_hex, size = self._md5_of_file(real_path)
                            md5_ok = (md5_hex.lower() == f.md5_checksum.hex().lower())
                            status = "OK" if md5_ok else "Mismatch (md5)"
                            status_class = "ok" if md5_ok else "mismatch"
                            result = (idx, str(size), md5_hex, status, status_class)
                        except Exception as e:
                            result = (idx, "", f"<error: {e}>", "Read error", "mismatch")

                    self._result_q.put(result)

                    # increment progress
                    self._files_done += 1
                    done = self._files_done
                    self.after(0, lambda d=done: self.progress_lbl.configure(
                        text=f"{d} / {total_files} files"))

            threading.Thread(target=producer, daemon=True).start()
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                for _ in range(num_workers):
                    executor.submit(worker)

            # finish callback
            def finish_when_quiet():
                if not self._result_q.empty():
                    self.after(150, finish_when_quiet)
                    return
                ok = self._summary_counts["ok"]
                missing = self._summary_counts["missing"]
                mismatch = self._summary_counts["mismatch"]
                summary = f"Validation finished.\nOK: {ok}\nMissing: {missing}\nMismatch: {mismatch}\n"
                self._set_busy(False, "Validation complete.")
                messagebox.showinfo("Game Validation", summary)
                self._summary_counts = {"ok": 0, "missing": 0, "mismatch": 0}

            self.after(150, finish_when_quiet)

        except Exception as ex:
            self._show_error_threadsafe(f"Validation failed. {ex}")

if __name__ == "__main__":
    App().mainloop()