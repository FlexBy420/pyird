import json
import logging
import os
import sys

if getattr(sys, "frozen", False):
    _APP_ROOT = os.path.dirname(os.path.abspath(sys.argv[0]))
else:
    _APP_ROOT = os.path.dirname(os.path.abspath(__file__))

SETTINGS_FILE = os.path.join(_APP_ROOT, "settings.json")

DEFAULTS: dict = {
    "ird_dir": os.path.join(_APP_ROOT, "ird"),
    "log_dir": os.path.join(_APP_ROOT, "logs"),
    "max_workers": 0,  # 0 = auto (half of CPU cores)
}

_data: dict = {}


def _report_settings_error(message: str, exc: BaseException) -> None:
    logger = logging.getLogger("pyird")
    if logger.handlers:
        logger.exception(message, exc_info=(type(exc), exc, exc.__traceback__))
    else:
        try:
            sys.__stderr__.write(f"[SETTINGS] {message}: {exc}\n")
        except Exception:
            pass


def _load() -> None:
    global _data
    _data = dict(DEFAULTS)
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                _data.update(loaded)
            else:
                raise ValueError("settings.json root must be a JSON object")
        except Exception as exc:
            _report_settings_error("Failed to load settings; defaults will be used", exc)


def save() -> None:
    directory = os.path.dirname(SETTINGS_FILE)
    os.makedirs(directory, exist_ok=True)
    tmp_path = SETTINGS_FILE + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(_data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, SETTINGS_FILE)
    except Exception as exc:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        _report_settings_error("Failed to save settings", exc)
        raise


def get(key: str, default=None):
    return _data.get(key, DEFAULTS.get(key, default))


def set_value(key: str, value) -> None:
    _data[key] = value
    save()


def update_values(values: dict) -> None:
    _data.update(values)
    save()


_load()
