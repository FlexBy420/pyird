import hashlib
import mmap
import os
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from utils.logger import log

def normalize_path_for_match(rel_path: str) -> str:
    return rel_path.replace("\\", "/").strip("/").rstrip(".").lower()

def build_case_insensitive_file_map(root: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    root = os.path.abspath(root)
    for base, _, files in os.walk(root):
        for fn in files:
            full = os.path.join(base, fn)
            rel  = os.path.relpath(full, root)
            mapping[normalize_path_for_match(rel)] = full
    return mapping

def md5_of_file(
    path: str,
    chunk_size: int = 16 * 1024 * 1024,
    mmap_threshold: int = 2048 * 1024 * 1024,
) -> tuple[str, int]:
    h    = hashlib.md5(usedforsecurity=False)
    size = os.path.getsize(path)
    if size == 0:
        return h.hexdigest(), 0
    with open(path, "rb") as f:
        if size <= mmap_threshold:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                h.update(mm)
        else:
            while chunk := f.read(chunk_size):
                h.update(chunk)
    return h.hexdigest(), size

def _resolve_num_workers(hdd_mode: bool) -> int:
    if hdd_mode:
        return 1
    try:
        import settings as _settings
        cfg = int(_settings.get("max_workers", 0))
        if cfg > 0:
            return cfg
    except Exception:
        pass
    return max(1, (os.cpu_count() or 4) // 2)

def run_validation(
    ird,
    root: str,
    result_q: queue.Queue,
    hdd_mode: bool,
    progress_callback,      # callable(done: int, total: int)
    status_callback,        # callable(msg: str)
) -> None:
    total_files = len(ird.files)
    files_done  = 0
    done_lock   = threading.Lock()

    file_map    = build_case_insensitive_file_map(root)
    num_workers = _resolve_num_workers(hdd_mode)

    offset_to_iso = {e["first_extent"]: e for e in ird.iso_files}
    expected_md5 = {f.offset: f.md5_checksum.hex() for f in ird.files}

    log(
        f"[VALIDATION] Starting validation of {total_files} files in {root} "
        f"({'HDD/sequential' if hdd_mode else f'{num_workers} workers'})"
    )

    status_callback("Validating files…")
    progress_callback(0, total_files)

    file_queue: queue.Queue = queue.Queue(maxsize=20)

    def producer():
        for idx, f in enumerate(ird.files):
            iso_entry = offset_to_iso.get(f.offset)
            rel       = iso_entry["name"] if iso_entry else f"File {f.offset}"
            key       = normalize_path_for_match(rel)
            real_path = file_map.get(key)
            file_queue.put((idx, f.offset, rel, real_path))

        for _ in range(num_workers):
            file_queue.put(None)   # sentinels

    def worker():
        nonlocal files_done
        while True:
            item = file_queue.get()
            if item is None:
                break
            idx, offset, rel, real_path = item

            if real_path is None:
                result = (idx, None, None, "Missing", "missing")
            else:
                try:
                    md5_hex, size = md5_of_file(real_path)
                    ok     = md5_hex == expected_md5[offset]
                    result = (
                        idx,
                        str(size),
                        md5_hex,
                        "OK" if ok else "Invalid",
                        "ok" if ok else "invalid",
                    )
                    log(f"[JB-VALIDATION] {rel}: {'OK' if ok else 'INVALID'}")
                except Exception as e:
                    log(f"[ERROR] Read error: {e}")
                    result = (idx, "", f"<error: {e}>", "Read error", "invalid")

            result_q.put(result)
            with done_lock:
                files_done += 1
                current = files_done
            progress_callback(current, total_files)

    threading.Thread(target=producer, daemon=True).start()
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        for _ in range(num_workers):
            executor.submit(worker)

def run_iso_validation(
    ird,
    iso_path: str,
    result_q: queue.Queue,
    progress_callback,      # callable(done: int, total: int)
    status_callback,        # callable(msg: str)
) -> None:
    BLOCK = 2048
    CHUNK = 16 * 1024 * 1024

    total_files   = len(ird.files)
    offset_to_iso = {f["first_extent"]: f for f in ird.iso_files}

    expected_md5 = {f.offset: f.md5_checksum.hex() for f in ird.files}

    status_callback("Validating ISO files…")
    progress_callback(0, total_files)

    with open(iso_path, "rb") as fh:
        try:
            os.posix_fadvise(fh.fileno(), 0, 0, os.POSIX_FADV_SEQUENTIAL)
        except (AttributeError, OSError):
            pass

        for idx, ird_file in enumerate(ird.files):
            iso_entry = offset_to_iso.get(ird_file.offset)
            rel       = iso_entry["name"] if iso_entry else f"File @sector {ird_file.offset}"
            try:
                h           = hashlib.md5(usedforsecurity=False)
                actual_size = 0

                for extent_sector, extent_size in (
                    iso_entry["extents"] if iso_entry else [(ird_file.offset, 0)]
                ):
                    fh.seek(extent_sector * BLOCK)
                    remaining = extent_size
                    while remaining > 0:
                        to_read = min(CHUNK, remaining)
                        data    = fh.read(to_read)
                        if not data:
                            break
                        h.update(data)
                        actual_size += len(data)
                        remaining   -= len(data)

                md5_hex = h.hexdigest()
                ok      = md5_hex == expected_md5[ird_file.offset]
                result  = (
                    idx,
                    str(actual_size),
                    md5_hex,
                    "OK" if ok else "Invalid",
                    "ok" if ok else "invalid",
                )
                log(f"[ISO-VALID] {rel}: {'OK' if ok else 'INVALID'}")
            except Exception as e:
                log(f"[ERROR] ISO read error for {rel}: {e}")
                result = (idx, "", f"<error: {e}>", "Read error", "invalid")

            result_q.put(result)
            progress_callback(idx + 1, total_files)