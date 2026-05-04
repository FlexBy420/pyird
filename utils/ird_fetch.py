import os
import struct
import requests
from tkinter import messagebox
from config import IRD_DIR, BASE_IRD_URL, JSON_URL
from utils.logger import log
from utils.gzip import uncompress_gzip

def _norm(s: str) -> str:
    return (s or "").strip()

def _is_redump(link: str) -> bool:
    return "redump" in (link or "").lower()

def _entry_label(entry: dict) -> str:
    link   = entry.get("link", "")
    source = "Redump" if _is_redump(link) else "Other"
    name   = os.path.basename(link) or link
    return f"[{source}] {name}"

def _redump_key(item) -> int:
    link = item.get("link", "") if isinstance(item, dict) else item
    return 0 if _is_redump(link) else 1

def load_local_ird(
    title_id: str,
    app_ver: str,
    game_ver: str,
    fw_ver: str,
    update_ver: str | None = None,
) -> list[str]:

    from core.ird import Ird, parse_ird_content

    if not title_id or not os.path.exists(IRD_DIR):
        return []

    normalized_id = title_id.replace("-", "").upper()
    matches: list[str] = []

    for fname in os.listdir(IRD_DIR):
        if not fname.lower().endswith(".ird"):
            continue

        stem = os.path.splitext(fname)[0].replace("-", "").replace(" ", "").upper()
        if not stem.startswith(normalized_id):
            continue

        path = os.path.join(IRD_DIR, fname)
        try:
            with open(path, "rb") as fp:
                content = fp.read()
            content = uncompress_gzip(content)

            magic = struct.unpack("<I", content[:4])[0]
            if magic != Ird.MAGIC:
                continue

            ird = parse_ird_content(content)
            if (
                ird.product_code.upper() == title_id
                and (not app_ver    or ird.app_version.strip()    == app_ver.strip())
                and (not game_ver   or ird.game_version.strip()   == game_ver.strip())
                and (not update_ver or ird.update_version.strip() == update_ver.strip())
            ):
                matches.append(path)

        except Exception as e:
            log(f"[ERROR] Failed to check local IRD {path}: {e}")

    # Prefer Redump named files
    matches.sort(key=_redump_key)
    return matches

def _fetch_ird_index() -> dict | None:
    try:
        resp = requests.get(JSON_URL, timeout=20)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        log(f"[ERROR] Failed to fetch IRD index JSON: {e}")
        return None


def fetch_remote_ird_candidates(
    title_id: str,
    app_ver: str,
    game_ver: str,
    fw_ver: str,
) -> list[dict]:

    title_id = (title_id or "").upper()
    app_ver  = _norm(app_ver)
    game_ver = _norm(game_ver)
    fw_ver   = _norm(fw_ver)

    ird_data = _fetch_ird_index()
    if not ird_data:
        return []

    if title_id not in ird_data:
        log(f"[WARNING] No IRD entries found for title {title_id}")
        return []

    matches = [
        e for e in ird_data[title_id]
        if (
            _norm(e.get("app-ver"))  == app_ver
            and _norm(e.get("game-ver")) == game_ver
            and _norm(e.get("fw-ver"))   == fw_ver
        )
    ]
    matches.sort(key=_redump_key)
    return matches

def download_ird_entry(entry: dict) -> str | None:
    link  = entry.get("link", "")
    fname = os.path.basename(link)
    if not fname.lower().endswith(".ird"):
        fname += ".ird"
    local_path = os.path.join(IRD_DIR, fname)

    os.makedirs(IRD_DIR, exist_ok=True)
    url = BASE_IRD_URL + link
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        with open(local_path, "wb") as f:
            f.write(r.content)
        log(f"[INFO] IRD downloaded successfully: {local_path}")
        return local_path
    except requests.RequestException as e:
        log(f"[ERROR] Failed to download IRD from {url}: {e}")
        messagebox.showwarning(
            "IRD Download Failed",
            f"Failed to download IRD for {link}.\nError: {e}",
        )
        return None
    except Exception as e:
        log(f"[ERROR] Unexpected error while saving IRD: {e}")
        return None

def auto_get_ird(
    param_sfo: dict | None,
    pick_fn=None,
) -> str | None:
    sfo        = param_sfo or {}
    title_id   = sfo.get("TITLE_ID")
    app_ver    = sfo.get("APP_VER")
    game_ver   = sfo.get("VERSION")
    update_ver = sfo.get("UPDATE_VER")

    # Normalise PS3_SYSTEM_VER  e.g. "043.3100" into "4.31"
    fw_ver = sfo.get("PS3_SYSTEM_VER")
    if fw_ver:
        fw_ver = fw_ver.lstrip("0")
        if fw_ver.endswith("00"):
            fw_ver = fw_ver[:-2]
        if fw_ver.startswith("0"):
            fw_ver = fw_ver[1:]

    if not title_id:
        messagebox.showwarning(
            "IRD Auto",
            "Online Fetch failed!\nPlease try selecting IRD manually.\n"
            "Missing TITLE_ID in PARAM.SFO",
        )
        return None

    # Local cache
    local_matches = load_local_ird(title_id, app_ver, game_ver, fw_ver, update_ver)
    if local_matches:
        if len(local_matches) == 1 or pick_fn is None:
            chosen = local_matches[0]
        else:
            options = [(os.path.basename(p), p) for p in local_matches]
            chosen  = pick_fn(options)
        if chosen:
            log(f"[INFO] Using local IRD: {chosen}")
            return chosen

    # Remote download
    try:
        candidates = fetch_remote_ird_candidates(title_id, app_ver, game_ver, fw_ver)
        if not candidates:
            messagebox.showwarning(
                "IRD Auto",
                f"No matching IRD found online for {title_id}\n"
                f"App Version={app_ver}\nGame Version={game_ver}\n"
                f"FW Version={fw_ver}",
            )
            return None

        if len(candidates) == 1 or pick_fn is None:
            chosen_entry = candidates[0]
        else:
            options      = [(_entry_label(e), e) for e in candidates]
            chosen_entry = pick_fn(options)

        if chosen_entry is None:
            return None
        return download_ird_entry(chosen_entry)

    except Exception as e:
        log(f"[ERROR] Failed to fetch IRD: {e}")
        messagebox.showwarning("IRD Auto", f"Failed to fetch IRD: {e}")
        return None