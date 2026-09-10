from __future__ import annotations

import datetime
import logging
import os
import sys
import threading
import traceback
from typing import TextIO

import settings

_LOGGER_NAME = "pyird"
_logger = logging.getLogger(_LOGGER_NAME)
_logger.setLevel(logging.DEBUG)
_logger.propagate = False
_lock = threading.RLock()
_file_handler: logging.FileHandler | None = None
_original_stdout: TextIO | None = sys.__stdout__
_original_stderr: TextIO | None = sys.__stderr__

class _ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {record.getMessage()}"

class _LineStream:
    def __init__(self, level: int, fallback: TextIO | None):
        self.level = level
        self.fallback = fallback
        self._buffer = ""
        self._lock = threading.Lock()

    def write(self, message: str) -> int:
        if not message:
            return 0
        with self._lock:
            self._buffer += message.replace("\r\n", "\n").replace("\r", "\n")
            while "\n" in self._buffer:
                line, self._buffer = self._buffer.split("\n", 1)
                if line:
                    _logger.log(self.level, line)
        return len(message)

    def flush(self) -> None:
        with self._lock:
            if self._buffer:
                _logger.log(self.level, self._buffer)
                self._buffer = ""
        try:
            self.fallback.flush()
        except Exception:
            pass

    def isatty(self) -> bool:
        try:
            return self.fallback.isatty()
        except Exception:
            return False

    @property
    def encoding(self):
        return getattr(self.fallback, "encoding", "utf-8")

def _daily_log_path(log_dir: str | None = None) -> str:
    directory = os.path.abspath(log_dir or settings.get("log_dir"))
    return os.path.join(directory, f"{datetime.date.today():%Y-%m-%d}.log")

def configure(log_dir: str | None = None) -> str | None:
    """Configure console/file logging. Safe to call again after settings change."""
    global _file_handler
    with _lock:
        if (
            _original_stdout is not None
            and not any(getattr(h, "_pyird_console", False) for h in _logger.handlers)
        ):
            console = logging.StreamHandler(_original_stdout)
            console._pyird_console = True  # type: ignore[attr-defined]
            console.setLevel(logging.DEBUG)
            console.setFormatter(_ConsoleFormatter())
            _logger.addHandler(console)

        if _file_handler is not None:
            _logger.removeHandler(_file_handler)
            try:
                _file_handler.close()
            except Exception:
                pass
            _file_handler = None

        path = _daily_log_path(log_dir)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            handler = logging.FileHandler(path, mode="a", encoding="utf-8")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(threadName)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            _logger.addHandler(handler)
            _file_handler = handler
            return path
        except Exception:
            try:
                if _original_stderr is not None:
                    _original_stderr.write(
                        f"[PYIRD LOGGER] Could not open log file {path!r}:\n"
                        f"{traceback.format_exc()}\n"
                    )
                    _original_stderr.flush()
            except Exception:
                pass
            return None

def set_log_dir(log_dir: str) -> str | None:
    return configure(log_dir)

def log(msg: str, level: int = logging.INFO) -> None:
    _logger.log(level, str(msg))

def log_exception(msg: str, exc: BaseException | None = None) -> None:
    if exc is None:
        _logger.exception(msg)
        return
    _logger.error(
        "%s\n%s",
        msg,
        "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).rstrip(),
    )

def _install_exception_hooks() -> None:
    def sys_hook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        _logger.critical(
            "Uncaught Python exception\n%s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_tb)).rstrip(),
        )

    def thread_hook(args: threading.ExceptHookArgs):
        _logger.critical(
            "Uncaught exception in thread %s\n%s",
            getattr(args.thread, "name", "<unknown>"),
            "".join(traceback.format_exception(
                args.exc_type, args.exc_value, args.exc_traceback
            )).rstrip(),
        )

    sys.excepthook = sys_hook
    threading.excepthook = thread_hook

configure()
_install_exception_hooks()
sys.stdout = _LineStream(logging.INFO, _original_stdout)
sys.stderr = _LineStream(logging.ERROR, _original_stderr)
