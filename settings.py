import json
import os
import sys

if getattr(sys, "frozen", False):
    _APP_ROOT = os.path.dirname(os.path.abspath(sys.argv[0]))
else:
    _APP_ROOT = os.path.dirname(os.path.abspath(__file__))

SETTINGS_FILE = os.path.join(_APP_ROOT, "settings.json")

DEFAULTS: dict = {
    "ird_dir":     os.path.join(_APP_ROOT, "ird"),
    "log_dir":     os.path.join(_APP_ROOT, "logs"),
    "max_workers": 0, # 0 = auto (half of CPU cores)
}

_data: dict = {}

def _load() -> None:
    global _data
    _data = dict(DEFAULTS)
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                _data.update(json.load(f))
        except Exception:
            pass

def save() -> None:
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        import sys as _sys
        _sys.__stderr__.write(f"[SETTINGS] save() failed: {e}\n")

def get(key: str, default=None):
    return _data.get(key, DEFAULTS.get(key, default))

def set_value(key: str, value) -> None:
    _data[key] = value
    save()

_load()