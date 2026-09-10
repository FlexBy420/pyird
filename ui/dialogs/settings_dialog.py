import customtkinter as ctk
from tkinter import filedialog, messagebox
from utils.logger import log, set_log_dir

class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        import settings as _settings
        self._settings = _settings

        self.title("Settings")
        self.geometry("560x260")
        self.resizable(False, False)
        self.transient(parent)
        self.after(50, self._do_grab)

        pad = {"padx": 12, "pady": 6}

        # IRD folder
        ctk.CTkLabel(self, text="IRD Folder:", anchor="w").grid(
            row=0, column=0, sticky="w", **pad
        )
        self._ird_var = ctk.StringVar(value=_settings.get("ird_dir"))
        ctk.CTkEntry(self, textvariable=self._ird_var, width=340).grid(
            row=0, column=1, sticky="ew", padx=(0, 4), pady=6
        )
        ctk.CTkButton(self, text="Browse...", width=80,
                      command=self._browse_ird).grid(row=0, column=2, padx=(0, 12), pady=6)

        # Log folder
        ctk.CTkLabel(self, text="Log Folder:", anchor="w").grid(
            row=1, column=0, sticky="w", **pad
        )
        self._log_var = ctk.StringVar(value=_settings.get("log_dir"))
        ctk.CTkEntry(self, textvariable=self._log_var, width=340).grid(
            row=1, column=1, sticky="ew", padx=(0, 4), pady=6
        )
        ctk.CTkButton(self, text="Browse...", width=80,
                      command=self._browse_log).grid(row=1, column=2, padx=(0, 12), pady=6)

        # Max workers
        ctk.CTkLabel(self, text="CPU Workers:", anchor="w").grid(
            row=2, column=0, sticky="w", **pad
        )
        self._workers_var = ctk.StringVar(value=str(_settings.get("max_workers", 0)))
        ctk.CTkEntry(self, textvariable=self._workers_var, width=80).grid(
            row=2, column=1, sticky="w", padx=(0, 4), pady=6
        )
        ctk.CTkLabel(
            self,
            text="0 = auto (half of CPU cores)",
            text_color="gray",
            font=("", 11),
        ).grid(row=2, column=2, sticky="e", padx=(0, 4))

        # Note
        ctk.CTkLabel(
            self,
            text="Changes are applied immediately.",
            text_color="gray",
            font=("", 11),
        ).grid(row=3, column=0, columnspan=3, sticky="w", padx=12, pady=(4, 0))

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=4, column=0, columnspan=3, pady=16)
        ctk.CTkButton(btn_frame, text="Save", width=100,
                      command=self._save).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Cancel", width=100, fg_color="gray40",
                      command=self._cancel).pack(side="left", padx=8)

        self.grid_columnconfigure(1, weight=1)

    def _browse_ird(self):
        d = filedialog.askdirectory(title="Select IRD folder", parent=self)
        if d:
            self._ird_var.set(d)

    def _browse_log(self):
        d = filedialog.askdirectory(title="Select Log folder", parent=self)
        if d:
            self._log_var.set(d)

    def _do_grab(self):
        try:
            self.grab_set()
            self.focus_set()
        except Exception:
            pass

    def _cancel(self):
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def _save(self):
        try:
            workers = int(self._workers_var.get())
            if workers < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid value", "CPU Workers must be a non-negative integer.", parent=self)
            return

        ird_dir = self._ird_var.get()
        log_dir = self._log_var.get()

        try:
            self._settings.update_values({
                "ird_dir": ird_dir,
                "log_dir": log_dir,
                "max_workers": workers,
            })
            # Re-open the file logger immediately in the newly selected directory.
            set_log_dir(log_dir)
        except Exception as exc:
            messagebox.showerror(
                "Settings",
                f"Failed to save settings:\n{exc}",
                parent=self,
            )
            return

        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()
        log(f"[SETTINGS] Saved: ird={ird_dir}, log={log_dir}, workers={workers}")
