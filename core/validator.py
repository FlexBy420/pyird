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
    chunk_size: int = 4 * 1024 * 1024,
    mmap_threshold: int = 2048 * 1024 * 1024,
) -> tuple[str, int]:
    h    = hashlib.md5()
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

    file_map    = build_case_insensitive_file_map(root)
    num_workers = _resolve_num_workers(hdd_mode)

    log(
        f"[VALIDATION] Starting validation of {total_files} files in {root} "
        f"({'HDD/sequential' if hdd_mode else f'{num_workers} workers'})"
    )

    status_callback("Validating files…")
    progress_callback(0, total_files)

    file_queue: queue.Queue = queue.Queue(maxsize=20)

    def producer():
        for idx, f in enumerate(ird.files):
            iso_entry = next(
                (e for e in ird.iso_files if e["first_extent"] == f.offset), None
            )
            rel       = iso_entry["name"] if iso_entry else f"File {f.offset}"
            key       = normalize_path_for_match(rel)
            real_path = file_map.get(key)
            file_queue.put((idx, f, rel, real_path))

        for _ in range(num_workers):
            file_queue.put(None)   # sentinels

    def worker():
        nonlocal files_done
        while True:
            item = file_queue.get()
            if item is None:
                break
            idx, f, rel, real_path = item

            if real_path is None:
                result = (idx, None, None, "Missing", "missing")
            else:
                try:
                    md5_hex, size = md5_of_file(real_path)
                    ok     = md5_hex.lower() == f.md5_checksum.hex().lower()
                    result = (
                        idx,
                        str(size),
                        md5_hex,
                        "OK" if ok else "Invalid (MD5)",
                        "ok" if ok else "invalid",
                    )
                    log(
                        f"[JB-VALIDATION] {rel}: {'OK' if ok else 'INVALID'} "
                    )
                except Exception as e:
                    log(f"[ERROR] Read error: {e}")
                    result = (idx, "", f"<error: {e}>", "Read error", "invalid")

            result_q.put(result)
            files_done += 1
            progress_callback(files_done, total_files)

    threading.Thread(target=producer, daemon=True).start()
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        for _ in range(num_workers):
            executor.submit(worker)