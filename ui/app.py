import os
import queue
import struct
import threading
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox, Listbox, SINGLE, END
from utils.logger import log
from utils.gzip import uncompress_gzip
from utils.sfo import parse_param_sfo
from utils.ird_fetch import auto_get_ird
from utils.size_units import human_size
from core.ird import Ird, parse_ird_content
from core.validator import (
    normalize_path_for_match,
    build_case_insensitive_file_map,
    run_validation,
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
        self.grab_set()
        self.focus_set()
        self.lift()

        self.chosen = None

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
                      command=self.destroy).pack(side="left", padx=8)

    def _select(self):
        sel = self._lb.curselection()
        if sel:
            self.chosen = self._values[sel[0]]
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

        # Path labels
        self.loaded_ird_var = ctk.StringVar(value="")
        ctk.CTkLabel(
            self.main, textvariable=self.loaded_ird_var, font=("", 14, "bold")
        ).grid(row=1, column=0, sticky="w")

        self.loaded_jb_var = ctk.StringVar(value="")
        ctk.CTkLabel(
            self.main, textvariable=self.loaded_jb_var, font=("", 14, "bold")
        ).grid(row=2, column=0, sticky="w", pady=(0, 6))

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

        headers = [
            "Product Code", "Title", "App Version",
            "Game Version", "Update Version", "Files", "Total Size",
        ]
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

        self._divider(self.main, 6)

        # Treeview table
        self.table_container = ctk.CTkFrame(self.main)
        self.table_container.grid(row=7, column=0, sticky="nsew", pady=(6, 0))
        self.table_container.grid_columnconfigure(0, weight=1)
        self.table_container.grid_rowconfigure(0, weight=1)

        self.table_headers = (
            "Filename", "Size (bytes)", "MD5 (IRD)", "Size (JB)", "MD5 (JB)", "Result"
        )
        self.tree = ttk.Treeview(
            self.table_container, columns=self.table_headers, show="headings"
        )
        self.tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ctk.CTkScrollbar(
            self.table_container, orientation="vertical", command=self.tree.yview
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        for col in self.table_headers:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="w", width=150, stretch=True)

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

        self.current_ird  = None
        self.current_jb:  str | None = None
        self.current_iso: str | None = None
        self.param_sfo:   dict | None = None

        self._result_q       = queue.Queue()
        self._summary_counts = {"ok": 0, "missing": 0, "invalid": 0}
        self._files_done     = 0

        # Queue for tasks that need to run on the UI thread from background threads
        self._ui_request_q: queue.Queue = queue.Queue()

        self.after(50, self._drain_results)
        self.after(50, self._drain_ui_requests)

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

    def autosize_tree_columns(self):
        self.update_idletasks()
        for col in self.tree["columns"]:
            max_width = max(
                [len(self.tree.heading(col, option="text"))]
                + [len(str(self.tree.set(iid, col))) for iid in self.tree.get_children()]
            )
            self.tree.column(col, width=max_width * 7 + 20)

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

    def _add_table_row(self, values: list[str], tag: str = ""):
        if tag in ("missing", "invalid"):
            iid = self.tree.insert("", 0, values=values, tags=(tag,))
            self._rows.insert(0, iid)
        else:
            iid = self.tree.insert("", "end", values=values, tags=(tag,))
            self._rows.append(iid)

    def _drain_results(self, max_per_tick: int = 1200):
        if self._result_q.qsize() > 5000:
            max_per_tick = 3000
        processed = 0
        while processed < max_per_tick and not self._result_q.empty():
            idx, jb_size, jb_md5, result, tag = self._result_q.get()
            if 0 <= idx < len(self._rows):
                vals     = list(self.tree.item(self._rows[idx], "values"))
                vals[3]  = jb_size or ""
                vals[4]  = jb_md5  or ""
                vals[5]  = result  or ""
                self.tree.item(self._rows[idx], values=vals)
                self.tree.tag_configure("ok",      background="#2E8B57")
                self.tree.tag_configure("missing", background="#9B1313")
                self.tree.tag_configure("invalid", background="#C76E00")
                self.tree.tag_configure("extra",   background="#6B6248")
                self.tree.item(self._rows[idx], tags=(tag,))
                if tag in ("missing", "invalid"):
                    self.tree.move(self._rows[idx], "", 0)
            if tag in self._summary_counts:
                self._summary_counts[tag] += 1
            processed += 1
        self.after(25, self._drain_results)

    def reset_app_state(self):
        self.current_ird = None
        self.current_jb  = None
        self.current_iso = None
        self.param_sfo   = None

        self.loaded_ird_var.set("")
        self.loaded_jb_var.set("")
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
            self.loaded_ird_var.set("")
            self.clear_table()
            for var in self.info_vars:
                var.set("")
            return False
        return True

    def pick_file(self):
        path = filedialog.askopenfilename(
            title="Select IRD file", filetypes=[("IRD files", "*.ird")]
        )
        if not path:
            return
        self.loaded_ird_var.set(f"Loaded IRD: {os.path.basename(path)}")
        self.status_var.set("")
        self._load_ird(path, source="user")
        if not self._compare_param_with_ird():
            return
        log(f"[USER] Selected IRD file: {path}")

    def pick_folder(self):
        root = filedialog.askdirectory(
            title="Select Game Folder (contains PS3_GAME, etc.)"
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
        self.loaded_jb_var.set(f"Loaded Game Folder: {root}")
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
        )
        if not path:
            log("[USER] Cancelled ISO selection")
            return
        log(f"[USER] Selected decrypted ISO: {path}")

        self.reset_app_state()
        self.current_iso = path
        self.loaded_jb_var.set(f"Loaded ISO: {path}")
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
            from core.iso import ISOHeader
            param_sfo: dict = {}

            BLOCK = 2048

            with open(iso_path, "rb") as fh:
                vd_data = fh.read(18 * BLOCK)  # sectors 0-17, VD is at 16+
                iso_vd = ISOHeader(vd_data)

                sfo_entry = None

                fh.seek(0)
                fast_data = fh.read(512 * BLOCK)
                iso_fast = ISOHeader(fast_data)
                sfo_entry = next(
                    (f for f in iso_fast.files
                     if f["name"].upper().endswith("PARAM.SFO")),
                    None,
                )

                if not sfo_entry:
                    fh.seek(0)
                    full_data = fh.read(2048 * BLOCK)
                    iso_full = ISOHeader(full_data)
                    sfo_entry = next(
                        (f for f in iso_full.files
                         if f["name"].upper().endswith("PARAM.SFO")),
                        None,
                    )

                if sfo_entry:
                    extent, size = sfo_entry["extents"][0]
                    fh.seek(extent * BLOCK)
                    sfo_bytes = fh.read(size)
                    import tempfile, os as _os
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".sfo") as tmp:
                        tmp.write(sfo_bytes)
                        tmp_path = tmp.name
                    try:
                        param_sfo = parse_param_sfo(tmp_path)
                    finally:
                        _os.unlink(tmp_path)
                else:
                    log("[WARNING] PARAM.SFO not found in ISO directory tree")

            self.param_sfo = param_sfo

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
            self.after(0, lambda: (
                self._set_busy(False, ""),
                self._set_controls_enabled(True),
                messagebox.showwarning("IRD Auto", f"Failed to fetch IRD: {e}"),
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

    def _on_ird_fetched(self, ird_path: str):
        self._set_busy(False, "")
        self._set_controls_enabled(True)
        self._load_ird(ird_path, source="auto")
        log(f"[INFO] Auto-fetched IRD at {ird_path}")

    def _pick_ird_blocking(self, options: list[tuple[str, object]]) -> object:
        result_holder = [None]
        done_event    = threading.Event()

        def show_on_ui():
            result_holder[0] = self._pick_ird_ui(options)
            done_event.set()

        self.after(0, show_on_ui)
        done_event.wait()
        return result_holder[0]

    def _load_ird(self, path: str, source: str = "user"):
        label = "Auto-Fetched IRD" if source == "auto" else "Loaded IRD"
        self.loaded_ird_var.set(f"{label}: {os.path.basename(path)}")
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
                        [name, str(size), ird_file.md5_checksum.hex(), "", "", ""]
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
                            values=[rel_path, "", "", "", "", "Extra File"],
                            tags=("extra",),
                        )
                        self._extra_rows.append(iid)

                # Update info panel
                vals = [
                    ird.product_code,
                    ird.title,
                    ird.app_version,
                    ird.game_version,
                    ird.update_version,
                    str(ird.file_count),
                    f"{ird.disc_size} ({human_size(ird.disc_size)})"
                    if ird.disc_size else "",
                ]
                for var, v in zip(self.info_vars, vals):
                    var.set(v)

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
        import hashlib

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
            self._set_status_threadsafe("Validating ISO files…")

            BLOCK = 2048
            CHUNK = 4 * 1024 * 1024  # 4 MB read chunks

            offset_to_iso = {f["first_extent"]: f for f in ird.iso_files}

            with open(iso_path, "rb") as fh:
                for idx, ird_file in enumerate(ird.files):
                    iso_entry = offset_to_iso.get(ird_file.offset)
                    if iso_entry:
                        rel = iso_entry["name"]
                        expected_size = iso_entry["size"]
                    else:
                        rel = f"File @sector {ird_file.offset}"
                        expected_size = 0

                    try:
                        h = hashlib.md5()
                        actual_size = 0

                        for extent_sector, extent_size in (
                            iso_entry["extents"] if iso_entry else [(ird_file.offset, 0)]
                        ):
                            fh.seek(extent_sector * BLOCK)
                            remaining = extent_size
                            while remaining > 0:
                                to_read = min(CHUNK, remaining)
                                data = fh.read(to_read)
                                if not data:
                                    break
                                h.update(data)
                                actual_size += len(data)
                                remaining  -= len(data)

                        md5_hex = h.hexdigest()
                        ok = md5_hex.lower() == ird_file.md5_checksum.hex().lower()
                        result = (
                            idx,
                            str(actual_size),
                            md5_hex,
                            "OK" if ok else "Invalid (MD5)",
                            "ok" if ok else "invalid",
                        )
                        log(
                            f"[ISO-VALID] {rel}: {'OK' if ok else 'INVALID'} "
                        )
                    except Exception as e:
                        log(f"[ERROR] ISO read error for {rel}: {e}")
                        result = (idx, "", f"<error: {e}>", "Read error", "invalid")

                    self._result_q.put(result)
                    self._files_done += 1
                    done = self._files_done
                    self.after(0, lambda d=done: self.progress_lbl.configure(
                        text=f"{d} / {total_files} files"
                    ))

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