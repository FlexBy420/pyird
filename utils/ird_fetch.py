import os
import struct
import requests
import settings
from config import BASE_IRD_URL, JSON_URL
from utils.logger import log, log_exception
from utils.gzip import uncompress_gzip


def _norm(s: str) -> str:
    return (s or "").strip()


def _normalize_fw_ver(value: str | None) -> str:
    value = _norm(value)
    if not value:
        return ""
    value = value.lstrip("0")
    if value.endswith("00"):
        value = value[:-2]
    if value.startswith("0"):
        value = value[1:]
    return value


def _ird_dir() -> str:
    path = os.path.abspath(settings.get("ird_dir"))
    os.makedirs(path, exist_ok=True)
    return path


def _is_redump(link: str) -> bool:
    return "redump" in (link or "").lower()


def _entry_label(entry: dict) -> str:
    link = entry.get("link", "")
    source = "Redump" if _is_redump(link) else "Other"
    name = os.path.basename(link) or link
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

    ird_dir = _ird_dir()
    if not title_id:
        return []

    normalized_id = title_id.replace("-", "").upper()
    matches: list[str] = []

    for fname in os.listdir(ird_dir):
        if not fname.lower().endswith(".ird"):
            continue

        stem = os.path.splitext(fname)[0].replace("-", "").replace(" ", "").upper()
        if not stem.startswith(normalized_id):
            continue

        path = os.path.join(ird_dir, fname)
        try:
            with open(path, "rb") as fp:
                content = uncompress_gzip(fp.read())

            if len(content) < 4 or struct.unpack("<I", content[:4])[0] != Ird.MAGIC:
                continue

            ird = parse_ird_content(content)
            if (
                _norm(ird.product_code).upper() == _norm(title_id).upper()
                and (not app_ver or _norm(ird.app_version) == _norm(app_ver))
                and (not game_ver or _norm(ird.game_version) == _norm(game_ver))
                and (not fw_ver or _normalize_fw_ver(ird.update_version) == _normalize_fw_ver(fw_ver))
            ):
                matches.append(path)
        except Exception as exc:
            log_exception(f"Failed to check local IRD: {path}", exc)

    matches.sort(key=_redump_key)
    return matches


def _fetch_ird_index() -> dict | None:
    try:
        resp = requests.get(JSON_URL, timeout=20)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        log_exception("Failed to fetch or parse IRD index JSON", exc)
        return None


def fetch_remote_ird_candidates(
    title_id: str,
    app_ver: str,
    game_ver: str,
    fw_ver: str,
) -> list[dict]:
    title_id = _norm(title_id).upper()
    app_ver = _norm(app_ver)
    game_ver = _norm(game_ver)
    fw_ver = _normalize_fw_ver(fw_ver)

    ird_data = _fetch_ird_index()
    if not ird_data:
        return []

    if title_id not in ird_data:
        log(f"[WARNING] No IRD entries found for title {title_id}")
        return []

    matches = [
        e for e in ird_data[title_id]
        if (
            _norm(e.get("app-ver")) == app_ver
            and _norm(e.get("game-ver")) == game_ver
            and _normalize_fw_ver(e.get("fw-ver")) == fw_ver
        )
    ]
    matches.sort(key=_redump_key)
    return matches


def download_ird_entry(entry: dict) -> str | None:
    link = entry.get("link", "")
    fname = os.path.basename(link)
    if not fname.lower().endswith(".ird"):
        fname += ".ird"
    local_path = os.path.join(_ird_dir(), fname)
    url = BASE_IRD_URL + link

    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        with open(local_path, "wb") as f:
            f.write(r.content)
        log(f"[INFO] IRD downloaded successfully: {local_path}")
        return local_path
    except Exception as exc:
        log_exception(f"Failed to download/save IRD from {url}", exc)
        return None


def auto_get_ird(param_sfo: dict | None, pick_fn=None) -> str | None:
    sfo = param_sfo or {}
    title_id = sfo.get("TITLE_ID")
    app_ver = sfo.get("APP_VER")
    game_ver = sfo.get("VERSION")
    fw_ver = _normalize_fw_ver(sfo.get("PS3_SYSTEM_VER"))

    if not title_id:
        log("[WARNING] IRD auto lookup skipped: PARAM.SFO has no TITLE_ID")
        return None

    local_matches = load_local_ird(title_id, app_ver, game_ver, fw_ver)
    if local_matches:
        if len(local_matches) == 1 or pick_fn is None:
            chosen = local_matches[0]
        else:
            options = [(os.path.basename(p), p) for p in local_matches]
            chosen = pick_fn(options)
        if chosen:
            log(f"[INFO] Using local IRD: {chosen}")
            return chosen

    try:
        candidates = fetch_remote_ird_candidates(title_id, app_ver, game_ver, fw_ver)
        if not candidates:
            log(
                f"[INFO] No matching IRD found online for {title_id} "
                f"(App={app_ver}, Game={game_ver}, FW={fw_ver})"
            )
            return None

        if len(candidates) == 1 or pick_fn is None:
            chosen_entry = candidates[0]
        else:
            options = [(_entry_label(e), e) for e in candidates]
            chosen_entry = pick_fn(options)

        if chosen_entry is None:
            return None
        return download_ird_entry(chosen_entry)
    except Exception as exc:
        log_exception("Failed to fetch IRD", exc)
        return None
