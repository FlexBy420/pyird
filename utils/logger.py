import sys
import datetime
from config import LOG_FILE

class Logger:

    def __init__(self, logfile_path: str):
        self.terminal = sys.stdout
        try:
            self.log = open(logfile_path, "a", encoding="utf-8")
        except Exception as e:
            self.log = None
            self.terminal.write(f"[LOGGER INIT ERROR] Could not open log file: {e}\n")

    def write(self, message: str):
        message = message.rstrip("\n")
        if not message:
            return
        timestamped = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {message}\n"

        try:
            self.terminal.write(timestamped)
        except Exception:
            pass

        if self.log:
            try:
                self.log.write(timestamped)
                self.log.flush()
            except Exception as e:
                self.terminal.write(f"[LOGGER ERROR] Failed to write log: {e}\n")
                self.log = None

    def flush(self):
        try:
            self.terminal.flush()
        except Exception:
            pass
        if self.log:
            try:
                self.log.flush()
            except Exception:
                self.log = None

_logger = Logger(LOG_FILE)
sys.stdout = _logger
sys.stderr = _logger

def log(msg: str) -> None:
    print(msg)