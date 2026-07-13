import os
import queue
import struct
import threading
import tkinter as tk
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
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
from core.batch import scan_batch_games, validate_single_game
from ui.tooltip import bind_tooltip
from ui.results_table import ResultsTable
from ui.info_panel import InfoPanel
from ui.dialogs import (
    SettingsDialog,
    IrdPickerDialog,
    IrdInfoDialog,
    BatchProgressDialog,
    BatchResultsDialog,
)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(f"PYIRD {APP_VERSION}")
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
        self.topbar.grid_columnconfigure(6, weight=1)

        self.pick_btn = ctk.CTkButton(
            self.topbar, text="Select IRD File", command=self.pick_file
        )
        self.pick_btn.grid(row=0, column=0, sticky="w")

        self.pick_game_btn = ctk.CTkButton(
            self.topbar, text="Select Game (Folder / ISO)", command=self._show_pick_game_menu
        )
        self.pick_game_btn.grid(row=0, column=1, padx=(8, 0), sticky="w")

        self.batch_validate_btn = ctk.CTkButton(
            self.topbar, text="Batch Validate", command=self.batch_validate
        )
        self.batch_validate_btn.grid(row=0, column=2, padx=(8, 0), sticky="w")

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

        self.ird_info_btn = ctk.CTkButton(
            self.topbar, text="IRD Info", width=110,
            fg_color="gray30", hover_color="gray40",
            state="disabled",
            command=self.open_ird_info,
        )
        self.ird_info_btn.grid(row=0, column=5, padx=(8, 0), sticky="w")

        self.status_var = ctk.StringVar(value="")
        self.status_lbl = ctk.CTkLabel(self.topbar, textvariable=self.status_var)
        self.status_lbl.grid(row=0, column=6, sticky="e", padx=(0, 20))

        self._update_btn = ctk.CTkButton(
            self.topbar, text="", width=0,
            fg_color="#1a6b2e", hover_color="#22883a", text_color="white",
            command=self._open_release_page,
        )
        # Hidden until an update is found
        self._update_tag = ""
        self._update_url = RELEASES_PAGE

        # Path labels
        self.loaded_ird_var = ctk.StringVar(value="")
        self._loaded_ird_full = ""
        self._loaded_ird_lbl = ctk.CTkLabel(
            self.main, textvariable=self.loaded_ird_var, font=("", 14, "bold")
        )
        self._loaded_ird_lbl.grid(row=1, column=0, sticky="w")

        self.loaded_jb_var = ctk.StringVar(value="")
        self._loaded_jb_full = ""
        self._loaded_jb_lbl = ctk.CTkLabel(
            self.main, textvariable=self.loaded_jb_var, font=("", 14, "bold")
        )
        self._loaded_jb_lbl.grid(row=2, column=0, sticky="w", pady=(0, 6))

        bind_tooltip(self._loaded_ird_lbl, lambda: self._loaded_ird_full)
        bind_tooltip(self._loaded_jb_lbl,  lambda: self._loaded_jb_full)

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
        self.info_panel = InfoPanel(self.main, self._info_tooltip_text)
        self.info_panel.grid(row=5, column=0, sticky="ew", pady=(6, 6))

        self._divider(self.main, 6)

        # Results table
        self.results = ResultsTable(self.main)
        self.results.grid(row=7, column=0, sticky="nsew", pady=(6, 0))

        self.current_ird = None
        self.current_jb: str | None = None
        self.current_iso: str | None = None
        self.param_sfo: dict | None = None
        self._ird_info: dict = {}

        self._result_q = queue.Queue()
        self._summary_counts = {"ok": 0, "missing": 0, "invalid": 0}
        self._files_done = 0

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
        tail = parts[-1]
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

    def _info_tooltip_text(self, col_idx: int) -> str:
        _header, sfo_key, description = self.info_panel.meta[col_idx]
        ird_info = self._ird_info
        lines = [description, ""]

        if col_idx == 5:  # Files
            ird_count = ird_info.get("file_count")
            if ird_count is not None:
                lines.append(f"IRD: {ird_count} files")
            if self.current_jb:
                try:
                    actual = sum(len(fs) for _, _, fs in os.walk(self.current_jb))
                    lines.append(f"Disk : {actual} files")
                except Exception:
                    pass
            elif self.current_iso and ird_info:
                lines.append("Disk: (from ISO - not separately counted)")
        elif col_idx == 6:  # Total Size
            raw = ird_info.get("disc_size", 0)
            lines.append(f"IRD: {human_size(raw)}  ({raw:,} B)" if raw else "IRD: -")
        elif sfo_key:
            ird_val = list(ird_info.values())[col_idx] if ird_info else None
            sfo_val = (self.param_sfo or {}).get(sfo_key, "").strip() or "-"
            ird_str = (str(ird_val).strip() if ird_val else None) or "-"
            lines.append(f"IRD: {ird_str}")
            lines.append(f"SFO: {sfo_val}")

        return "\n".join(lines).strip()

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
            text=f"Update available: {tag}",
        )
        self._update_btn.grid(row=0, column=7, padx=(12, 0), sticky="w")
        log(f"[UPDATER] New version available: {tag}")

    def _open_release_page(self):
        url = self._update_url
        opened = False

        try:
            opened = webbrowser.open(url)
        except Exception:
            pass

        if not opened:
            try:
                import subprocess
                subprocess.Popen(["xdg-open", url],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
                opened = True
            except Exception:
                pass
        try:
            self.clipboard_clear()
            self.clipboard_append(url)
            self.update()
        except Exception:
            pass

        if not opened:
            messagebox.showinfo(
                "Update available",
                f"Could not open browser automatically.\n\nURL copied to clipboard:\n{url}",
            )

    def open_settings(self):
        SettingsDialog(self)

    def open_ird_info(self):
        if not self.current_ird:
            return
        IrdInfoDialog(self, self.current_ird)

    def _show_pick_game_menu(self):
        menu = tk.Menu(
            self, tearoff=0, bg="#2b2b2b", fg="white",
            activebackground="#1f6aa5", activeforeground="white", bd=0,
        )
        menu.add_command(label="Game Folder (JB)...", command=self.pick_folder)
        menu.add_command(label="Decrypted ISO...",     command=self.pick_iso)
        try:
            x = self.pick_game_btn.winfo_rootx()
            y = self.pick_game_btn.winfo_rooty() + self.pick_game_btn.winfo_height()
            menu.tk_popup(x, y)
        finally:
            try:
                menu.grab_release()
            except Exception:
                pass

    def batch_validate(self):
        root = filedialog.askdirectory(
            title="Select folder containing your games (JB folders and/or ISO files)",
            parent=self,
        )
        if not root:
            log("[USER] Cancelled batch validate folder selection")
            return
        log(f"[USER] Batch validate root: {root}")

        self._set_controls_enabled(False)
        self._set_busy(True, "Scanning for games...")

        threading.Thread(
            target=self._batch_validate_worker, args=(root,), daemon=True
        ).start()

    def _batch_validate_worker(self, root: str):
        try:
            entries = scan_batch_games(root)
        except Exception as ex:
            log(f"[ERROR] Batch scan failed: {ex}")
            self.after(0, lambda ex=ex: (
                self._set_busy(False, ""),
                self._set_controls_enabled(True),
                messagebox.showerror("Batch Validate", f"Failed to scan folder: {ex}", parent=self),
            ))
            return

        if not entries:
            self.after(0, lambda: (
                self._set_busy(False, ""),
                self._set_controls_enabled(True),
                messagebox.showinfo(
                    "Batch Validate",
                    "No games found.\nExpected either folders containing PS3_GAME "
                    "or .iso files somewhere inside the selected folder.",
                    parent=self,
                ),
            ))
            return

        total = len(entries)
        dlg_holder: list = [None]
        dlg_ready = threading.Event()

        def make_dialog():
            dlg_holder[0] = BatchProgressDialog(self, total)
            dlg_ready.set()

        self.after(0, make_dialog)
        dlg_ready.wait()
        dlg = dlg_holder[0]

        for i, entry in enumerate(entries, start=1):
            self.after(0, lambda i=i, name=entry.display_name: dlg.update_game(i - 1, total, name))
            self.after(0, lambda: dlg.update_file_progress(""))
            try:
                self._batch_validate_single(entry, dlg)
            except Exception as ex:
                entry.status = "error"
                entry.error = str(ex)
                log(f"[ERROR] Batch validate failed for {entry.path}: {ex}")

        self.after(0, lambda: dlg.update_game(total, total, "Done"))

        def finish():
            dlg.close()
            self._set_busy(False, "Batch validation complete.")
            self._set_controls_enabled(True)
            ok = sum(1 for e in entries if e.status == "ok")
            invalid = sum(1 for e in entries if e.status == "invalid")
            errors = sum(1 for e in entries if e.status == "error")
            log(f"[BATCH] Finished. Games: {total}  OK: {ok}  Invalid: {invalid}  Errors: {errors}")
            BatchResultsDialog(self, entries)

        self.after(150, finish)

    def _batch_validate_single(self, entry, dlg: "BatchProgressDialog"):
        def file_progress_cb(done: int, total: int):
            self.after(0, lambda: dlg.update_file_progress(f"{done} / {total} files"))

        def file_status_cb(msg: str):
            self.after(0, lambda: dlg.update_file_progress(msg))

        validate_single_game(
            entry,
            hdd_mode=self.hdd_mode_var.get(),
            file_progress_cb=file_progress_cb,
            file_status_cb=file_status_cb,
        )

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

    def _set_controls_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.pick_btn.configure(state=state)
        self.pick_game_btn.configure(state=state)
        self.batch_validate_btn.configure(state=state)
        self.hdd_mode_chk.configure(state=state)
        self.settings_btn.configure(state=state)
        self.ird_info_btn.configure(
            state=state if (enabled and self.current_ird) else "disabled"
        )

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

    def _drain_results(self, max_per_tick: int = 1200):
        if self._result_q.qsize() > 5000:
            max_per_tick = 3000
        processed = 0
        while processed < max_per_tick and not self._result_q.empty():
            idx, jb_size, jb_md5, result, tag = self._result_q.get()
            self.results.update_row(idx, jb_size, jb_md5, result, tag)
            if tag in self._summary_counts:
                self._summary_counts[tag] += 1
            processed += 1
        self.after(25, self._drain_results)

    def reset_app_state(self):
        self.current_ird = None
        self.current_jb = None
        self.current_iso = None
        self.param_sfo = None

        self._set_ird_label("", "")
        self._set_jb_label("", "")
        self.validation_result_var.set("")
        self.info_panel.clear()

        self.results.clear()
        self.status_var.set("")
        self._set_busy(False)
        self.progress_lbl.configure(text="Working...")
        self._summary_counts = {"ok": 0, "missing": 0, "invalid": 0}
        self.pick_btn.configure(state="disabled")
        self.ird_info_btn.configure(state="disabled")

        while not self._result_q.empty():
            try:
                self._result_q.get_nowait()
            except queue.Empty:
                break

    def clear_table(self):
        self.results.clear()

    def _compare_param_with_ird(self) -> bool:
        if not self.current_ird or not self.param_sfo:
            return True

        ird_fields = {
            "TITLE_ID":   (self.info_panel.vars[0], self.info_panel.labels[0], "Product Code"),
            "APP_VER":    (self.info_panel.vars[2], self.info_panel.labels[2], "App Version"),
            "VERSION":    (self.info_panel.vars[3], self.info_panel.labels[3], "Game Version"),
            "UPDATE_VER": (self.info_panel.vars[4], self.info_panel.labels[4], "Update Version"),
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
            self.info_panel.clear()
            self.ird_info_btn.configure(state="disabled")
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
            self.after(0, lambda ex=ex: (
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
        done_event = threading.Event()

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
                self.results.clear()
                for ird_file in ird.files:
                    fdata = offset_to_file.get(ird_file.offset)
                    if fdata:
                        name = fdata["name"]
                        size = fdata["size"]
                    else:
                        name = f"File {ird_file.offset}"
                        size = ""
                    self.results.add_row(
                        [name, human_size(size) if size else "", ird_file.md5_checksum.hex(), ""],
                        raw_size=int(size) if size else 0,
                    )

                # Extra files not mentioned in the IRD
                if self.current_jb:
                    file_map = build_case_insensitive_file_map(self.current_jb)
                    ird_set = {
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
                        self.results.add_extra_row([rel_path, "", "", "Extra File"])

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
                self.info_panel.set_values(vals)
                self._ird_info = {
                    "product_code":   _clean(ird.product_code),
                    "title":          _clean(ird.title),
                    "app_version":    _clean(ird.app_version),
                    "game_version":   _clean(ird.game_version),
                    "update_version": _clean(ird.update_version),
                    "file_count":     ird.file_count,
                    "disc_size":      ird.disc_size,
                }

            self.after(0, apply_rows)
            self.after(0, lambda: self.ird_info_btn.configure(state="normal"))
            self.after(50, self.results.autosize_columns)

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
            self._files_done = 0

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
                ok = self._summary_counts["ok"]
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
                ok = self._summary_counts["ok"]
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
