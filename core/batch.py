import os
import queue
import struct
from utils.logger import log, log_exception
from utils.gzip import uncompress_gzip
from utils.sfo import parse_param_sfo, read_param_sfo_from_iso
from utils.ird_fetch import auto_get_ird
from core.ird import Ird, parse_ird_content
from core.validator import (
    normalize_path_for_match,
    build_case_insensitive_file_map,
    run_validation,
    run_iso_validation,
)

class BatchGameEntry:
    def __init__(self, kind: str, path: str, display_name: str):
        self.kind:          str = kind          # "jb" or "iso"
        self.path:          str = path
        self.display_name:  str = display_name
        self.status:        str = "pending"     # pending / ok / invalid / error
        self.error:         str = ""
        self.ok:            int = 0
        self.invalid:       int = 0
        self.missing:       int = 0
        self.rows:          list[dict] = []      # {"name","size","md5","result","tag"}
        self.extra_files:   list[str] = []
        self.product_code:  str = ""
        self.title:          str = ""

def scan_batch_games(root: str) -> list[BatchGameEntry]:
    entries: list[BatchGameEntry] = []
    for dirpath, dirnames, filenames in os.walk(root):
        if "PS3_GAME" in dirnames:
            entries.append(
                BatchGameEntry("jb", dirpath, os.path.basename(dirpath) or dirpath)
            )
            dirnames[:] = []  # don't descend further into a found JB game
            continue
        for fn in filenames:
            if fn.lower().endswith(".iso"):
                entries.append(BatchGameEntry("iso", os.path.join(dirpath, fn), fn))
    return entries

def validate_single_game(
    entry: BatchGameEntry,
    hdd_mode: bool,
    file_progress_cb,   # callable(done: int, total: int)
    file_status_cb,     # callable(msg: str)
) -> None:
    param_sfo: dict = {}
    try:
        if entry.kind == "jb":
            sfo_path = os.path.join(entry.path, "PS3_GAME", "PARAM.SFO")
            if os.path.exists(sfo_path):
                param_sfo = parse_param_sfo(sfo_path)
        else:
            param_sfo = read_param_sfo_from_iso(entry.path)
    except Exception as e:
        entry.status = "error"
        entry.error  = f"Failed to read PARAM.SFO: {e}"
        return

    entry.title = (param_sfo or {}).get("TITLE", "")
    try:
        ird_path = auto_get_ird(param_sfo, pick_fn=None)
    except Exception as e:
        entry.status = "error"
        entry.error  = f"IRD lookup failed: {e}"
        return

    if not ird_path:
        entry.status = "error"
        entry.error  = "No matching IRD found"
        return

    try:
        with open(ird_path, "rb") as f:
            content = f.read()
        content = uncompress_gzip(content)
        magic = struct.unpack("<I", content[:4])[0]
        if magic != Ird.MAGIC:
            raise ValueError("Not a valid IRD file")
        ird = parse_ird_content(content)
    except Exception as e:
        entry.status = "error"
        entry.error  = f"Failed to parse IRD: {e}"
        return

    entry.product_code = ird.product_code.strip()
    mismatches = []
    checks = {
        "TITLE_ID":       ird.product_code,
        "APP_VER":        ird.app_version,
        "VERSION":        ird.game_version,
        "PS3_SYSTEM_VER": ird.update_version,
    }
    for key, ird_val in checks.items():
        sfo_val = (param_sfo or {}).get(key)
        left = (ird_val or "").strip()
        right = (sfo_val or "").strip()
        if key == "PS3_SYSTEM_VER":
            from utils.ird_fetch import _normalize_fw_ver
            left = _normalize_fw_ver(left)
            right = _normalize_fw_ver(right)
        if sfo_val and right != left:
            mismatches.append(f"{key}: IRD={ird_val!r} SFO={sfo_val!r}")
    if mismatches:
        entry.status = "error"
        entry.error  = "IRD mismatch: " + "; ".join(mismatches)
        return

    result_q: queue.Queue = queue.Queue()
    offset_to_iso = {f["first_extent"]: f for f in ird.iso_files}

    if entry.kind == "jb":
        run_validation(
            ird=ird,
            root=entry.path,
            result_q=result_q,
            hdd_mode=hdd_mode,
            progress_callback=file_progress_cb,
            status_callback=file_status_cb,
        )
    else:
        run_iso_validation(
            ird=ird,
            iso_path=entry.path,
            result_q=result_q,
            progress_callback=file_progress_cb,
            status_callback=file_status_cb,
        )

    idx_to_name:    dict[int, str] = {}
    idx_to_size:    dict[int, int] = {}
    idx_to_ird_md5: dict[int, str] = {}
    for idx, ird_file in enumerate(ird.files):
        iso_entry = offset_to_iso.get(ird_file.offset)
        idx_to_name[idx]    = iso_entry["name"] if iso_entry else f"File {ird_file.offset}"
        idx_to_size[idx]    = iso_entry["size"] if iso_entry else 0
        idx_to_ird_md5[idx] = ird_file.md5_checksum.hex()

    rows_by_idx: dict[int, dict] = {}
    while not result_q.empty():
        idx, size, md5_hex, result_txt, tag = result_q.get()
        rows_by_idx[idx] = {
            "name":   idx_to_name.get(idx, f"File {idx}"),
            "size":   idx_to_size.get(idx, 0),
            "md5":    idx_to_ird_md5.get(idx, ""),
            "result": result_txt or "",
            "tag":    tag,
        }
        if tag == "ok":
            entry.ok += 1
        elif tag == "invalid":
            entry.invalid += 1
        elif tag == "missing":
            entry.missing += 1

    entry.rows = [rows_by_idx[i] for i in sorted(rows_by_idx.keys())]
    if entry.kind == "jb":
        try:
            file_map = build_case_insensitive_file_map(entry.path)
            ird_set  = {normalize_path_for_match(f["name"]) for f in ird.iso_files}
            entry.extra_files = [
                os.path.relpath(full_path, entry.path).replace("\\", "/")
                for rel_path, full_path in file_map.items()
                if normalize_path_for_match(rel_path) not in ird_set
            ]
        except Exception as e:
            log_exception(f"Failed to compute extra files for {entry.path}", e)

    entry.status = "invalid" if (entry.invalid > 0 or entry.missing > 0) else "ok"
