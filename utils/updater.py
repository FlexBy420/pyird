import threading
import requests
from utils.logger import log

RELEASES_URL    = "https://api.github.com/repos/FlexBy420/pyird/releases/latest"
RELEASES_PAGE   = "https://github.com/FlexBy420/pyird/releases/latest"

def _parse_version(tag: str) -> int:
    try:
        return int(tag.lstrip("v"))
    except ValueError:
        return -1

def check_for_update(
    current_version: str,
    on_update_available,   # callable(latest_tag: str, url: str)
    on_up_to_date=None,    # callable() | None
    on_error=None,         # callable(err: str) | None
) -> None:

    def _worker():
        try:
            resp = requests.get(RELEASES_URL, timeout=10)
            resp.raise_for_status()
            latest_tag = resp.json().get("tag_name", "")
            log(f"[UPDATER] Current: {current_version}  Latest: {latest_tag}")

            if _parse_version(latest_tag) > _parse_version(current_version):
                if on_update_available:
                    on_update_available(latest_tag, RELEASES_PAGE)
            else:
                if on_up_to_date:
                    on_up_to_date()

        except requests.RequestException as e:
            log(f"[UPDATER] Could not check for updates: {e}")
            if on_error:
                on_error(str(e))
        except Exception as e:
            log(f"[UPDATER] Unexpected error during update check: {e}")
            if on_error:
                on_error(str(e))

    threading.Thread(target=_worker, daemon=True).start()