import os
import sys
import datetime
import settings as _settings

if getattr(sys, "frozen", False):
    APP_ROOT = os.path.dirname(os.path.abspath(sys.argv[0]))
else:
    APP_ROOT = os.path.dirname(os.path.abspath(__file__))

IRD_DIR  = _settings.get("ird_dir")
LOG_DIR  = _settings.get("log_dir")
LOG_FILE = os.path.join(LOG_DIR, f"{datetime.date.today():%Y-%m-%d}.log")

os.makedirs(IRD_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

BASE_IRD_URL = "https://github.com/FlexBy420/playstation_3_ird_database/raw/main/"
JSON_URL     = "https://flexby420.github.io/playstation_3_ird_database/all.json"
APP_VERSION = "v0"

if not getattr(sys, "frozen", False) and APP_VERSION == "v0":
    try:
        import subprocess as _sp
        _count = _sp.check_output(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=APP_ROOT,
            stderr=_sp.DEVNULL,
        ).decode().strip()
        APP_VERSION = f"v{_count}"
    except Exception:
        pass