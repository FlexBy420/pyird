import os
import queue
import struct
import threading
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox, Listbox, SINGLE, END
import webbrowser
from config import APP_VERSION
from utils.logger import log
from utils.updater import check_for_update, RELEASES_PAGE
from utils.gzip import uncompress_gzip
from utils.sfo import parse_param_sfo, read_param_sfo_from_iso
from utils.ird_fetch import auto_get_ird
from utils.size_units import human_size
from core.ird import Ird, parse_ird_content
from core.validator import (
    normalize_path_for_match,
    build_case_insensitive_file_map,
    run_validation,
    run_iso_validation,
)

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
            text="Folder changes take effect after restarting the application.",
            text_color="#c8a800",
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
            if workers < 0: raise ValueError
        except ValueError:
            messagebox.showerror("Invalid value", "CPU Workers must be a non-negative integer.", parent=self)
            return

        ird_dir = self._ird_var.get()
        log_dir = self._log_var.get()

        self._settings._data["ird_dir"] = ird_dir
        self._settings._data["log_dir"] = log_dir
        self._settings._data["max_workers"] = workers
        self._settings.save()

        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()
        log(f"[SETTINGS] Saved: ird={ird_dir}, log={log_dir}, workers={workers}")

class IrdPickerDialog(ctk.CTkToplevel):
    def __init__(self, parent, options: list[tuple[str, object]]):
        super().__init__(parent)
        self.title("Select IRD")
        self.geometry("620x480")
        self.resizable(True, False)
        self.lift()
        self.after(100, self._do_grab)

        self.chosen = None
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        ctk.CTkLabel(
            self,
            text="Multiple matching IRDs were found - please choose one:",
            font=("", 13, "bold"),
        ).pack(padx=14, pady=(14, 6), anchor="w")

        ctk.CTkLabel(
            self,
            text="Redump entries are verified disc images and are preferred.",
            text_color="gray",
            font=("", 11),
        ).pack(padx=14, pady=(0, 8), anchor="w")

        list_frame = ctk.CTkFrame(self)
        list_frame.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        sb = ctk.CTkScrollbar(list_frame, orientation="vertical")
        sb.pack(side="right", fill="y")

        self._lb = Listbox(
            list_frame,
            selectmode=SINGLE,
            bg="#1e1e1e", fg="white",
            selectbackground="#1f6aa5",
            font=("Consolas", 11),
            bd=0, highlightthickness=0,
            yscrollcommand=sb.set,
        )
        self._lb.pack(fill="both", expand=True)
        sb.configure(command=self._lb.yview)

        self._values = []
        for label, value in options:
            self._lb.insert(END, f"  {label}")
            self._values.append(value)

        self._lb.selection_set(0)
        self._lb.bind("<Double-Button-1>", lambda _e: self._select())

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(side="bottom", pady=(0, 16))
        ctk.CTkButton(btn_frame, text="Select", width=110,
                      command=self._select).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Cancel", width=110, fg_color="gray40",
                      command=self._on_close).pack(side="left", padx=8)

    def _do_grab(self):
        try:
            self.grab_set()
            self.focus_set()
        except Exception:
            pass

    def _on_close(self):
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def _select(self):
        sel = self._lb.curselection()
        if sel:
            self.chosen = self._values[sel[0]]
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("PYIRD")
        self.geometry("1300x740")
        self.minsize(1100, 680)

        self.main = ctk.CTkFrame(self, corner_radius=8)
        self.main.pack(fill="both", expand=True, padx=12, pady=12)

        self.main.grid_columnconfigure(0, weight=1)
        for r in range(8):
            self.main.grid_rowconfigure(r, weight=0)
        self.main.grid_rowconfigure(7, weight=1)

        # Top bar
        self.topbar = ctk.CTkFrame(self.main, fg_color="transparent")
        self.topbar.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 6))
        self.topbar.grid_columnconfigure(5, weight=1)

        self.pick_btn = ctk.CTkButton(
            self.topbar, text="Select IRD File", command=self.pick_file
        )
        self.pick_btn.grid(row=0, column=0, sticky="w")

        self.pick_folder_btn = ctk.CTkButton(
            self.topbar, text="Select Game Folder", command=self.pick_folder
        )
        self.pick_folder_btn.grid(row=0, column=1, padx=(8, 0), sticky="w")

        self.pick_iso_btn = ctk.CTkButton(
            self.topbar, text="Select Decrypted ISO", command=self.pick_iso
        )
        self.pick_iso_btn.grid(row=0, column=2, padx=(8, 0), sticky="w")

        self.hdd_mode_var = ctk.BooleanVar(value=False)
        self.hdd_mode_chk = ctk.CTkCheckBox(
            self.topbar, text="HDD Mode (Slow)", variable=self.hdd_mode_var
        )
        self.hdd_mode_chk.grid(row=0, column=3, padx=(12, 0), sticky="w")

        self.settings_btn = ctk.CTkButton(
            self.topbar, text="Settings", width=100,
            fg_color="gray30", hover_color="gray40",
            command=self.open_settings,
        )
        self.settings_btn.grid(row=0, column=4, padx=(12, 0), sticky="w")

        self.status_var = ctk.StringVar(value="")
        self.status_lbl = ctk.CTkLabel(self.topbar, textvariable=self.status_var)
        self.status_lbl.grid(row=0, column=5, sticky="e", padx=(0, 20))

        self._update_btn = ctk.CTkButton(
            self.topbar, text="", width=0,
            fg_color="#1a6b2e", hover_color="#22883a", text_color="white",
            command=self._open_release_page,
        )
        # Hidden until an update is found
        self._update_tag  = ""
        self._update_url  = RELEASES_PAGE

        # Path labels
        self.loaded_ird_var   = ctk.StringVar(value="")
        self._loaded_ird_full = ""
        self._loaded_ird_lbl  = ctk.CTkLabel(
            self.main, textvariable=self.loaded_ird_var, font=("", 14, "bold")
        )
        self._loaded_ird_lbl.grid(row=1, column=0, sticky="w")

        self.loaded_jb_var   = ctk.StringVar(value="")
        self._loaded_jb_full = ""
        self._loaded_jb_lbl  = ctk.CTkLabel(
            self.main, textvariable=self.loaded_jb_var, font=("", 14, "bold")
        )
        self._loaded_jb_lbl.grid(row=2, column=0, sticky="w", pady=(0, 6))

        self._bind_tooltip(self._loaded_ird_lbl, lambda: self._loaded_ird_full)
        self._bind_tooltip(self._loaded_jb_lbl,  lambda: self._loaded_jb_full)

        self.validation_result_var = ctk.StringVar(value="")
        ctk.CTkLabel(
            self.main, textvariable=self.validation_result_var, font=("", 14, "bold")
        ).grid(row=2, column=0, sticky="e", padx=(0, 20))

        self._divider(self.main, 3)

        # Progress row
        self.progress_row = ctk.CTkFrame(self.main, fg_color="transparent")
        self.progress_row.grid(row=4, column=0, sticky="ew", pady=6)
        self.progress_row.grid_columnconfigure(0, weight=0)
        self.progress_row.grid_columnconfigure(1, weight=1)

        self.progress = ctk.CTkProgressBar(self.progress_row, mode="indeterminate")
        self.progress.grid(row=0, column=0, padx=(0, 12))
        self.progress_lbl = ctk.CTkLabel(self.progress_row, text="Working...")
        self.progress_lbl.grid(row=0, column=1, sticky="w")
        self._set_busy(False)

        # Info panel
        self.info_frame = ctk.CTkFrame(self.main)
        self.info_frame.grid(row=5, column=0, sticky="ew", pady=(6, 6))
        for c in range(7):
            self.info_frame.grid_columnconfigure(c, weight=1)

        self._info_meta = [
            ("Product Code", "TITLE_ID",         "Product code printed on the disc."),
            ("Title",        "TITLE",            "Game title."),
            ("App Version",  "APP_VER",          "Game version as seen in XMB (APP_VER)."),
            ("Game Version", "VERSION",          "Disc print version (VERSION) of this specific\ngame version (APP_VER)."),
            ("Update Ver.",  "PS3_SYSTEM_VER",   "Minimum firmware version required (PS3_SYSTEM_VER), and provided on the disc for offline update."),
            ("Files",        None,               "Number of files on the disc (from IRD)."),
            ("Total Size",   None,               "Game size on disc (from IRD)."),
        ]
        headers      = [m[0] for m in self._info_meta]
        self.info_vars   = [ctk.StringVar(value="") for _ in headers]
        self.info_labels = []

        for i, h in enumerate(headers):
            ctk.CTkLabel(self.info_frame, text=h, font=("", 12, "bold")).grid(
                row=0, column=i, sticky="ew", padx=4, pady=(4, 2)
            )
        for i, var in enumerate(self.info_vars):
            lbl = ctk.CTkLabel(self.info_frame, textvariable=var)
            lbl.grid(row=1, column=i, sticky="ew", padx=4, pady=(0, 6))
            self.info_labels.append(lbl)
            self._bind_info_tooltip(lbl, i)

        self._divider(self.main, 6)

        # Treeview table
        self.table_container = ctk.CTkFrame(self.main)
        self.table_container.grid(row=7, column=0, sticky="nsew", pady=(6, 0))
        self.table_container.grid_columnconfigure(0, weight=1)
        self.table_container.grid_rowconfigure(0, weight=1)

        self.table_headers = ("Filename", "Size", "MD5", "Result")
        self._row_details:   dict[str, str] = {}
        self._row_raw_size: dict[str, int] = {}
        self.tree = ttk.Treeview(
            self.table_container, columns=self.table_headers, show="headings"
        )
        self.tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ctk.CTkScrollbar(
            self.table_container, orientation="vertical", command=self.tree.yview
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        col_cfg = {
            "Filename": dict(anchor="w", width=380, stretch=True,  minwidth=120),
            "Size":     dict(anchor="e", width=110, stretch=False, minwidth=80),
            "MD5":      dict(anchor="w", width=260, stretch=False, minwidth=220),
            "Result":   dict(anchor="w", width=120, stretch=False, minwidth=80),
        }
        for col in self.table_headers:
            self.tree.heading(col, text=col)
            self.tree.column(col, **col_cfg.get(col, dict(anchor="w", width=150, stretch=False)))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#1e1e1e", foreground="white",
            fieldbackground="#1e1e1e", rowheight=22,
            bordercolor="#3a3a3a", borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background="#2b2b2b", foreground="white", relief="flat",
        )
        style.map("Treeview.Heading", background=[("active", "#444444")])

        self._rows:       list[str] = []
        self._extra_rows: list[str] = []

        # Tooltip for invalid/missing rows
        self._tree_tip: object = None
        self.tree.bind("<Motion>",   self._on_tree_motion)
        self.tree.bind("<Leave>",    self._on_tree_leave)

        self.current_ird  = None
        self.current_jb:  str | None = None
        self.current_iso: str | None = None
        self.param_sfo:   dict | None = None
        self._ird_info:   dict       = {}

        self._result_q       = queue.Queue()
        self._summary_counts = {"ok": 0, "missing": 0, "invalid": 0}
        self._files_done     = 0

        # Queue for tasks that need to run on the UI thread from background threads
        self._ui_request_q: queue.Queue = queue.Queue()

        self.after(50, self._drain_results)
        self.after(50, self._drain_ui_requests)
        self.after(1000, self._start_update_check)

    @staticmethod
    def _truncate_path(label: str, path: str, max_chars: int = 80) -> str:
        full = f"{label}: {path}"
        if len(full) <= max_chars:
            return full
        parts = path.replace("\\", "/").split("/")
        tail  = parts[-1]
        for part in reversed(parts[:-1]):
            candidate = f"{part}/{tail}"
            if len(f"{label}: …/{candidate}") <= max_chars:
                tail = candidate
            else:
                break
        return f"{label}: …/{tail}"

    def _set_ird_label(self, label: str, path: str) -> None:
        self._loaded_ird_full = f"{label}: {path}"
        self.loaded_ird_var.set(self._truncate_path(label, path))

    def _set_jb_label(self, label: str, path: str) -> None:
        self._loaded_jb_full = f"{label}: {path}"
        self.loaded_jb_var.set(self._truncate_path(label, path))

    @staticmethod
    def _bind_tooltip(widget, text_fn):
        tip: list = [None]

        def enter(_e):
            msg = text_fn()
            if not msg:
                return
            x = widget.winfo_rootx() + 4
            y = widget.winfo_rooty() + widget.winfo_height() + 2
            tw = ctk.CTkToplevel(widget)
            tw.wm_overrideredirect(True)
            tw.wm_geometry(f"+{x}+{y}")
            ctk.CTkLabel(
                tw, text=msg, font=("", 11),
                fg_color="#2b2b2b", corner_radius=4,
                padx=8, pady=4,
            ).pack()
            tip[0] = tw

        def leave(_e):
            if tip[0]:
                try:
                    tip[0].destroy()
                except Exception:
                    pass
                tip[0] = None

        widget.bind("<Enter>", enter, add="+")
        widget.bind("<Leave>", leave, add="+")

    def _on_tree_motion(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            self._hide_tree_tip()
            return

        col     = self.tree.identify_column(event.x)
        headers = self.tree["columns"]
        col_idx = int(col.lstrip("#")) - 1 if col.startswith("#") else -1
        col_name = headers[col_idx] if 0 <= col_idx < len(headers) else ""

        if col_name == "Size":
            raw = self._row_raw_size.get(iid, 0)
            tip_text = f"{raw:,} bytes" if raw else ""
        else:
            tip_text = self._row_details.get(iid, "")

        if not tip_text:
            self._hide_tree_tip()
            return

        tip_key = (iid, col_name)
        if self._tree_tip and getattr(self._tree_tip, "_for_key", None) == tip_key:
            return
        self._hide_tree_tip()
        x = self.tree.winfo_rootx() + event.x + 16
        y = self.tree.winfo_rooty() + event.y + 4
        tw = ctk.CTkToplevel(self)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tw._for_key = tip_key
        ctk.CTkLabel(
            tw, text=tip_text, font=("Consolas", 11),
            fg_color="#2b2b2b", corner_radius=4,
            justify="left", padx=10, pady=6,
        ).pack()
        self._tree_tip = tw

    def _on_tree_leave(self, _event):
        self._hide_tree_tip()

    def _hide_tree_tip(self):
        if self._tree_tip:
            try:
                self._tree_tip.destroy()
            except Exception:
                pass
            self._tree_tip = None

    def _bind_info_tooltip(self, widget, col_idx: int):
        tip: list = [None]

        def enter(_e):
            _header, sfo_key, description = self._info_meta[col_idx]
            ird_info = self._ird_info

            lines = [description, ""]

            if col_idx == 5: # Files
                ird_count = ird_info.get("file_count")
                sfo_count = None
                if ird_count is not None:
                    lines.append(f"IRD: {ird_count} files")
                actual = None
                if self.current_jb:
                    try:
                        actual = sum(len(fs) for _, _, fs in os.walk(self.current_jb))
                        lines.append(f"Disk : {actual} files")
                    except Exception:
                        pass
                elif self.current_iso and ird_info:
                    lines.append("Disk: (from ISO - not separately counted)")

            elif col_idx == 6: # Total Size
                raw = ird_info.get("disc_size", 0)
                if raw:
                    lines.append(f"IRD: {human_size(raw)}  ({raw:,} B)")
                else:
                    lines.append("IRD: -")

            elif sfo_key:
                ird_val = list(ird_info.values())[col_idx] if ird_info else None
                sfo_val = (self.param_sfo or {}).get(sfo_key, "").strip() or "-"
                ird_str = (str(ird_val).strip() if ird_val else None) or "-"
                lines.append(f"IRD: {ird_str}")
                lines.append(f"SFO: {sfo_val}")

            tip_text = "\n".join(lines).strip()
            if not tip_text:
                return

            x = widget.winfo_rootx()
            y = widget.winfo_rooty() + widget.winfo_height() + 2
            tw = ctk.CTkToplevel(widget)
            tw.wm_overrideredirect(True)
            tw.wm_geometry(f"+{x}+{y}")
            ctk.CTkLabel(
                tw, text=tip_text, font=("Consolas", 11),
                fg_color="#2b2b2b", corner_radius=4,
                justify="left", padx=10, pady=6,
            ).pack()
            tip[0] = tw

        def leave(_e):
            if tip[0]:
                try:
                    tip[0].destroy()
                except Exception:
                    pass
                tip[0] = None

        widget.bind("<Enter>", enter, add="+")
        widget.bind("<Leave>", leave, add="+")

    def _start_update_check(self):
        check_for_update(
            current_version=APP_VERSION,
            on_update_available=lambda tag, url: self.after(
                0, lambda: self._show_update_badge(tag, url)
            ),
        )

    def _show_update_badge(self, tag: str, url: str):
        self._update_tag = tag
        self._update_url = url
        self._update_btn.configure(
            text=f"Update available: {tag}  ↓",
        )
        self._update_btn.grid(row=0, column=6, padx=(12, 0), sticky="w")
        log(f"[UPDATER] New version available: {tag}")

    def _open_release_page(self):
        webbrowser.open(self._update_url)

    def open_settings(self):
        SettingsDialog(self)

    def _pick_ird_ui(self, options: list[tuple[str, object]]) -> object:
        dlg = IrdPickerDialog(self, options)
        self.wait_window(dlg)
        return dlg.chosen

    def _drain_ui_requests(self):
        try:
            while True:
                fn = self._ui_request_q.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.after(30, self._drain_ui_requests)

    def _run_on_ui(self, fn):
        self.after(0, fn)

    _FIXED_WIDTH_COLS = {"Size", "MD5", "Result"}

    def autosize_tree_columns(self):
        self.update_idletasks()
        for col in self.tree["columns"]:
            if col in self._FIXED_WIDTH_COLS:
                continue
            char_widths = (
                [len(self.tree.heading(col, option="text"))]
                + [len(str(self.tree.set(iid, col))) for iid in self.tree.get_children()]
            )
            self.tree.column(col, width=max(char_widths) * 7 + 20)

    def _set_controls_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.pick_btn.configure(state=state)
        self.pick_folder_btn.configure(state=state)
        self.pick_iso_btn.configure(state=state)
        self.hdd_mode_chk.configure(state=state)
        self.settings_btn.configure(state=state)

    @staticmethod
    def _divider(parent, row_index: int):
        ttk.Separator(parent, orient="horizontal").grid(
            row=row_index, column=0, sticky="ew", pady=(6, 6)
        )

    def _set_busy(self, busy: bool, msg: str | None = None):
        if busy:
            self.progress_row.grid()
            self.progress.start()
        else:
            self.progress.stop()
            self.progress_row.grid_remove()
        if msg is not None:
            self.status_var.set(msg)

    def _show_error_threadsafe(self, msg: str):
        self.after(0, lambda: (self._set_busy(False, ""), messagebox.showerror("Error", msg)))

    def _set_status_threadsafe(self, msg: str):
        self.after(0, lambda: self.status_var.set(msg))

    def _clear_table(self):
        for iid in self._rows + self._extra_rows:
            self.tree.delete(iid)
        self._rows.clear()
        self._extra_rows.clear()
        self._row_details.clear()
        self._row_raw_size.clear()

    def _add_table_row(self, values: list[str], tag: str = "", raw_size: int = 0):
        if tag in ("missing", "invalid"):
            iid = self.tree.insert("", 0, values=values, tags=(tag,))
            self._rows.insert(0, iid)
        else:
            iid = self.tree.insert("", "end", values=values, tags=(tag,))
            self._rows.append(iid)
        self._row_details[iid]  = ""
        self._row_raw_size[iid] = raw_size
        return iid

    def _drain_results(self, max_per_tick: int = 1200):
        if self._result_q.qsize() > 5000:
            max_per_tick = 3000
        processed = 0
        while processed < max_per_tick and not self._result_q.empty():
            idx, jb_size, jb_md5, result, tag = self._result_q.get()
            if 0 <= idx < len(self._rows):
                iid  = self._rows[idx]
                vals = list(self.tree.item(iid, "values"))
                vals[3] = result or ""
                if tag == "invalid":
                    ird_md5  = vals[2]
                    raw_ird  = self._row_raw_size.get(iid, 0)
                    raw_jb   = int(jb_size) if jb_size and jb_size.isdigit() else None
                    def _fmt(raw):
                        if raw is None: return chr(8212)
                        return f"{human_size(raw)}  ({raw:,} B)"
                    detail = (
                        f"{'Size':8}  IRD  {_fmt(raw_ird)}\n"
                        f"{'':8}  File {_fmt(raw_jb)}\n"
                        f"\n"
                        f"{'MD5':8}  IRD  {ird_md5}\n"
                        f"{'':8}  File {jb_md5 or chr(8212)}"
                    )
                    self._row_details[iid] = detail
                elif tag == "missing":
                    self._row_details[iid] = "File not found on disk"
                else:
                    raw_jb = int(jb_size) if jb_size and jb_size.isdigit() else None
                    if raw_jb is not None:
                        self._row_raw_size[iid] = raw_jb
                    self._row_details[iid] = ""
                self.tree.item(iid, values=vals)
                self.tree.tag_configure("ok",      background="#2E8B57")
                self.tree.tag_configure("missing", background="#9B1313")
                self.tree.tag_configure("invalid", background="#C76E00")
                self.tree.tag_configure("extra",   background="#6B6248")
                self.tree.item(iid, tags=(tag,))
                if tag in ("missing", "invalid"):
                    self.tree.move(iid, "", 0)
            if tag in self._summary_counts:
                self._summary_counts[tag] += 1
            processed += 1
        self.after(25, self._drain_results)

    def reset_app_state(self):
        self.current_ird = None
        self.current_jb  = None
        self.current_iso = None
        self.param_sfo   = None

        self._set_ird_label("", "")
        self._set_jb_label("", "")
        self.validation_result_var.set("")
        for var in self.info_vars:
            var.set("")

        self._clear_table()
        self.status_var.set("")
        self._set_busy(False)
        self.progress_lbl.configure(text="Working...")
        self._summary_counts = {"ok": 0, "missing": 0, "invalid": 0}
        self.pick_btn.configure(state="disabled")

        while not self._result_q.empty():
            try:
                self._result_q.get_nowait()
            except queue.Empty:
                break

    def clear_table(self):
        self._clear_table()

    def _compare_param_with_ird(self) -> bool:
        if not self.current_ird or not self.param_sfo:
            return True

        ird_fields = {
            "TITLE_ID":   (self.info_vars[0], self.info_labels[0], "Product Code"),
            "APP_VER":    (self.info_vars[2], self.info_labels[2], "App Version"),
            "VERSION":    (self.info_vars[3], self.info_labels[3], "Game Version"),
            "UPDATE_VER": (self.info_vars[4], self.info_labels[4], "Update Version"),
        }

        mismatches = []
        for key, (var, label, display_name) in ird_fields.items():
            ird_val = var.get()
            sfo_val = self.param_sfo.get(key)
            if sfo_val and sfo_val != ird_val:
                mismatches.append(
                    f"{display_name} in IRD: {ird_val}\n"
                    f"{display_name} in Game Files: {sfo_val}"
                )
                label.configure(text_color="red")
            else:
                label.configure(text_color="white")

        if mismatches:
            messagebox.showerror(
                "IRD mismatch",
                "The provided IRD does not appear to be for this game.\n"
                "Please choose the correct IRD.\n\n" + "\n".join(mismatches),
            )
            self.current_ird = None
            self._set_ird_label("", "")
            self.clear_table()
            for var in self.info_vars:
                var.set("")
            return False
        return True

    def pick_file(self):
        path = filedialog.askopenfilename(
            title="Select IRD file", filetypes=[("IRD files", "*.ird")], parent=self
        )
        if not path:
            return
        self._set_ird_label("Loaded IRD", os.path.basename(path))
        self.status_var.set("")
        self._load_ird(path, source="user")
        if not self._compare_param_with_ird():
            return
        log(f"[USER] Selected IRD file: {path}")

    def pick_folder(self):
        root = filedialog.askdirectory(
            title="Select Game Folder (contains PS3_GAME, etc.)", parent=self
        )
        if not root:
            log("[USER] Cancelled game folder selection")
            return
        log(f"[USER] Selected game folder: {root}")

        self.reset_app_state()

        if not os.path.isdir(os.path.join(root, "PS3_GAME")):
            messagebox.showerror(
                "Invalid Folder", "Selected folder does not contain PS3_GAME."
            )
            return

        self.current_jb = root
        self._set_jb_label("Loaded Game Folder", root)
        self.pick_btn.configure(state="normal")

        sfo_path = os.path.join(root, "PS3_GAME", "PARAM.SFO")
        if os.path.exists(sfo_path):
            try:
                self.param_sfo = parse_param_sfo(sfo_path)
                if not self._compare_param_with_ird():
                    return
            except Exception as e:
                log(f"[ERROR] Failed to parse PARAM.SFO: {e}")
                messagebox.showwarning("PARAM.SFO", f"Failed to parse PARAM.SFO: {e}")

        # Disable controls while fetching IRD in background
        self._set_controls_enabled(False)
        self._set_busy(True, "Looking for IRD...")

        param_sfo_snapshot = dict(self.param_sfo) if self.param_sfo else {}

        threading.Thread(
            target=self._fetch_ird_worker,
            args=(root, param_sfo_snapshot),
            daemon=True,
        ).start()

    def pick_iso(self):
        path = filedialog.askopenfilename(
            title="Select Decrypted PS3 ISO",
            filetypes=[("ISO files", "*.iso"), ("All files", "*.*")],
            parent=self,
        )
        if not path:
            log("[USER] Cancelled ISO selection")
            return
        log(f"[USER] Selected decrypted ISO: {path}")

        self.reset_app_state()
        self.current_iso = path
        self._set_jb_label("Loaded ISO", path)
        self.pick_btn.configure(state="normal")

        # Try to read PARAM.SFO from inside the ISO
        self._set_controls_enabled(False)
        self._set_busy(True, "Reading ISO...")
        threading.Thread(
            target=self._iso_preflight_worker,
            args=(path,),
            daemon=True,
        ).start()

    def _iso_preflight_worker(self, iso_path: str):
        try:
            self.param_sfo = read_param_sfo_from_iso(iso_path)

            def on_ui():
                self._compare_param_with_ird()
                self._set_busy(True, "Looking for IRD...")
                param_sfo_snapshot = dict(self.param_sfo) if self.param_sfo else {}
                threading.Thread(
                    target=self._fetch_ird_worker,
                    args=(iso_path, param_sfo_snapshot),
                    daemon=True,
                ).start()

            self.after(0, on_ui)

        except Exception as ex:
            log(f"[ERROR] ISO preflight failed: {ex}")
            self.after(0, lambda: (
                self._set_busy(False, ""),
                self._set_controls_enabled(True),
                messagebox.showwarning("ISO", f"Failed to read ISO: {ex}"),
            ))

    def _fetch_ird_worker(self, root: str, param_sfo: dict):
        try:
            ird_path = auto_get_ird(param_sfo, pick_fn=self._pick_ird_blocking)
        except Exception as e:
            log(f"[ERROR] Failed to fetch IRD: {e}")
            err_msg = str(e)
            self.after(0, lambda: (
                self._set_busy(False, ""),
                self._set_controls_enabled(True),
                messagebox.showwarning("IRD Auto", f"Failed to fetch IRD: {err_msg}"),
            ))
            return

        if ird_path:
            self.after(0, lambda p=ird_path: self._on_ird_fetched(p))
        else:
            self.after(0, lambda: (
                self._set_busy(False, "IRD not found for this game."),
                self._set_controls_enabled(True),
                self.status_var.set("IRD not found for this game."),
            ))
            log(f"[INFO] No IRD found for {param_sfo.get('TITLE_ID', 'unknown')}")
            log(f"[SFO] SFO contents: {param_sfo}")

    def _on_ird_fetched(self, ird_path: str):
        self._set_busy(False, "")
        self._set_controls_enabled(True)
        self._load_ird(ird_path, source="auto")
        log(f"[INFO] Auto-fetched IRD at {ird_path}")

    def _pick_ird_blocking(self, options: list[tuple[str, object]]) -> object:
        result_holder = [None]
        done_event    = threading.Event()

        def show_on_ui():
            dlg = IrdPickerDialog(self, options)
            self.wait_window(dlg)
            result_holder[0] = dlg.chosen
            done_event.set()

        self.after(0, show_on_ui)
        done_event.wait()
        return result_holder[0]

    def _load_ird(self, path: str, source: str = "user"):
        label = "Auto-Fetched IRD" if source == "auto" else "Loaded IRD"
        self._set_ird_label(label, os.path.basename(path))
        self._set_busy(True, "Reading file...")
        threading.Thread(target=self._parse_and_fill, args=(path,), daemon=True).start()

    def _parse_and_fill(self, path: str):
        try:
            with open(path, "rb") as f:
                content = f.read()
            content = uncompress_gzip(content)

            magic = struct.unpack("<I", content[:4])[0]
            if magic != Ird.MAGIC:
                raise ValueError("Not a valid IRD file")

            self._set_status_threadsafe("Parsing IRD header...")
            log(f"[INFO] Parsing IRD file {path} ({len(content)} bytes)")
            ird = parse_ird_content(content)
            self.current_ird = ird
            log(
                f"[INFO] Parsed IRD: Product={ird.product_code}, Title='{ird.title}', "
                f"AppVer={ird.app_version}, GameVer={ird.game_version}, "
                f"UpdateVer={ird.update_version}"
            )

            self._set_status_threadsafe("Preparing rows...")
            offset_to_file = {f["first_extent"]: f for f in ird.iso_files}

            def apply_rows():
                self._clear_table()
                for ird_file in ird.files:
                    fdata = offset_to_file.get(ird_file.offset)
                    if fdata:
                        name = fdata["name"]
                        size = fdata["size"]
                    else:
                        name = f"File {ird_file.offset}"
                        size = ""
                    self._add_table_row(
                        [name, human_size(size) if size else "", ird_file.md5_checksum.hex(), ""],
                        raw_size=int(size) if size else 0,
                    )

                # Extra files not mentioned in the IRD
                if self.current_jb:
                    file_map = build_case_insensitive_file_map(self.current_jb)
                    ird_set  = {
                        normalize_path_for_match(f["name"]) for f in ird.iso_files
                    }
                    extra_files = [
                        full_path
                        for rel_path, full_path in file_map.items()
                        if normalize_path_for_match(rel_path) not in ird_set
                    ]
                    for full_path in extra_files:
                        log(f"[INFO] Extra file detected: {full_path}")
                        rel_path = os.path.relpath(
                            full_path, self.current_jb
                        ).replace("\\", "/")
                        iid = self.tree.insert(
                            "", 0,
                            values=[rel_path, "", "", "Extra File"],
                            tags=("extra",),
                        )
                        self._extra_rows.append(iid)

                # Update info panel
                def _clean(s: str) -> str:
                    v = (s or "").strip()
                    return v if v else "-"

                vals = [
                    _clean(ird.product_code),
                    _clean(ird.title),
                    _clean(ird.app_version),
                    _clean(ird.game_version),
                    _clean(ird.update_version),
                    str(ird.file_count),
                    human_size(ird.disc_size) if ird.disc_size else "-",
                ]
                for var, v in zip(self.info_vars, vals):
                    var.set(v)
                self._ird_info = {
                    "product_code":  _clean(ird.product_code),
                    "title":         _clean(ird.title),
                    "app_version":   _clean(ird.app_version),
                    "game_version":  _clean(ird.game_version),
                    "update_version":_clean(ird.update_version),
                    "file_count":    ird.file_count,
                    "disc_size":     ird.disc_size,
                }

            self.after(0, apply_rows)
            self.after(50, self.autosize_tree_columns)

            def finish_and_maybe_validate():
                self._set_busy(False, "Done.")
                if self.current_jb:
                    if self._compare_param_with_ird():
                        self._validate_jb_folder(self.current_jb)
                elif self.current_iso:
                    if self._compare_param_with_ird():
                        self._validate_iso(self.current_iso)

            self.after(0, finish_and_maybe_validate)

        except Exception as ex:
            log(f"[ERROR] Failed to load IRD: {ex}")
            self._show_error_threadsafe(f"Failed to load IRD. {ex}")

    def _validate_jb_folder(self, root: str):
        self._set_busy(True, "Scanning JB folder...")
        self._set_controls_enabled(False)
        threading.Thread(
            target=self._validate_worker, args=(root,), daemon=True
        ).start()

    def _validate_worker(self, root: str):
        try:
            ird = self.current_ird
            if not ird:
                self._set_status_threadsafe("Load an IRD first")
                self._set_busy(False)
                return

            while not self._result_q.empty():
                try:
                    self._result_q.get_nowait()
                except queue.Empty:
                    break

            self._summary_counts = {"ok": 0, "missing": 0, "invalid": 0}
            self._files_done     = 0

            def progress_cb(done: int, total: int):
                self.after(0, lambda: self.progress_lbl.configure(
                    text=f"{done} / {total} files"
                ))

            def status_cb(msg: str):
                self._set_status_threadsafe(msg)

            run_validation(
                ird=ird,
                root=root,
                result_q=self._result_q,
                hdd_mode=self.hdd_mode_var.get(),
                progress_callback=progress_cb,
                status_callback=status_cb,
            )

            def finish_when_quiet():
                if not self._result_q.empty():
                    self.after(150, finish_when_quiet)
                    return
                ok      = self._summary_counts["ok"]
                missing = self._summary_counts["missing"]
                invalid = self._summary_counts["invalid"]
                summary = (
                    f"Validation finished.\n"
                    f"OK: {ok}\nInvalid: {invalid}\nMissing: {missing}"
                )
                self.validation_result_var.set(
                    f"OK: {ok} | Invalid: {invalid} | Missing: {missing}"
                )
                self._set_busy(False, "Validation complete.")
                self._set_controls_enabled(True)
                messagebox.showinfo("Game Validation", summary)
                log(f"[VALIDATION] {summary}")
                self._summary_counts = {"ok": 0, "missing": 0, "invalid": 0}

            self.after(150, finish_when_quiet)

        except Exception as ex:
            log(f"[ERROR] Validation failed: {ex}")
            self._show_error_threadsafe(f"Validation failed. {ex}")
            self._set_controls_enabled(True)

    def _validate_iso(self, iso_path: str):
        self._set_busy(True, "Scanning ISO...")
        self._set_controls_enabled(False)
        threading.Thread(
            target=self._validate_iso_worker, args=(iso_path,), daemon=True
        ).start()

    def _validate_iso_worker(self, iso_path: str):
        try:
            ird = self.current_ird
            if not ird:
                self._set_status_threadsafe("Load an IRD first")
                self._set_busy(False)
                return

            while not self._result_q.empty():
                try:
                    self._result_q.get_nowait()
                except queue.Empty:
                    break

            self._summary_counts = {"ok": 0, "missing": 0, "invalid": 0}
            self._files_done = 0

            total_files = len(ird.files)
            self.after(0, lambda: self.progress_lbl.configure(
                text=f"0 / {total_files} files"
            ))

            def progress_cb(done: int, total: int):
                self.after(0, lambda: self.progress_lbl.configure(
                    text=f"{done} / {total} files"
                ))

            def status_cb(msg: str):
                self._set_status_threadsafe(msg)

            run_iso_validation(
                ird=ird,
                iso_path=iso_path,
                result_q=self._result_q,
                progress_callback=progress_cb,
                status_callback=status_cb,
            )

            def finish_when_quiet():
                if not self._result_q.empty():
                    self.after(150, finish_when_quiet)
                    return
                ok      = self._summary_counts["ok"]
                missing = self._summary_counts["missing"]
                invalid = self._summary_counts["invalid"]
                summary = (
                    f"ISO Validation finished.\n"
                    f"OK: {ok}\nInvalid: {invalid}\nMissing: {missing}"
                )
                self.validation_result_var.set(
                    f"OK: {ok} | Invalid: {invalid} | Missing: {missing}"
                )
                self._set_busy(False, "ISO Validation complete.")
                self._set_controls_enabled(True)
                messagebox.showinfo("ISO Validation", summary)
                log(f"[ISO-VALID] {summary}")
                self._summary_counts = {"ok": 0, "missing": 0, "invalid": 0}

            self.after(150, finish_when_quiet)

        except Exception as ex:
            log(f"[ERROR] ISO validation failed: {ex}")
            self._show_error_threadsafe(f"ISO Validation failed. {ex}")
            self._set_controls_enabled(True)