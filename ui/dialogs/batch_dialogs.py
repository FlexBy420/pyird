import customtkinter as ctk
from tkinter import ttk, messagebox
from utils.size_units import human_size
from core.batch import BatchGameEntry

class BatchProgressDialog(ctk.CTkToplevel):
    def __init__(self, parent, total: int):
        super().__init__(parent)
        self.title("Batch Validation")
        self.geometry("540x200")
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", lambda: None)  # not user-closable
        self.after(50, self._do_grab)

        self._total = max(total, 1)

        self.game_lbl = ctk.CTkLabel(self, text="Preparing...", font=("", 13, "bold"))
        self.game_lbl.pack(padx=16, pady=(16, 6), anchor="w")

        self.count_lbl = ctk.CTkLabel(self, text=f"0 / {total} games")
        self.count_lbl.pack(padx=16, anchor="w")

        self.bar = ctk.CTkProgressBar(self, width=500)
        self.bar.pack(padx=16, pady=(10, 6))
        self.bar.set(0)

        self.file_lbl = ctk.CTkLabel(self, text="", text_color="gray")
        self.file_lbl.pack(padx=16, pady=(4, 16), anchor="w")

    def _do_grab(self):
        try:
            self.grab_set()
            self.focus_set()
        except Exception:
            pass

    def update_game(self, done: int, total: int, name: str):
        self.count_lbl.configure(text=f"{done} / {total} games")
        self.game_lbl.configure(text=f"Validating: {name}")
        self.bar.set(done / self._total)

    def update_file_progress(self, msg: str):
        self.file_lbl.configure(text=msg)

    def close(self):
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

class GameReportDialog(ctk.CTkToplevel):
    def __init__(self, parent, entry: BatchGameEntry):
        super().__init__(parent)
        self.title(f"Report: {entry.display_name}")
        self.geometry("900x600")
        self.transient(parent)
        self.after(50, self._do_grab)

        header = f"{entry.display_name}  [{entry.kind.upper()}]"
        ctk.CTkLabel(self, text=header, font=("", 14, "bold")).pack(
            padx=16, pady=(14, 2), anchor="w"
        )
        if entry.product_code or entry.title:
            ctk.CTkLabel(
                self,
                text=f"{entry.product_code}  -  {entry.title}".strip(" -"),
                text_color="gray",
            ).pack(padx=16, anchor="w")

        if entry.error:
            ctk.CTkLabel(
                self, text=f"Error: {entry.error}", text_color="#ff6666"
            ).pack(padx=16, pady=(6, 0), anchor="w")

        summary = f"OK: {entry.ok}   Invalid: {entry.invalid}   Missing: {entry.missing}"
        ctk.CTkLabel(self, text=summary, font=("", 12, "bold")).pack(
            padx=16, pady=(8, 8), anchor="w"
        )

        table_frame = ctk.CTkFrame(self)
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        columns = ("Filename", "Size", "MD5", "Result")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        tree.pack(side="left", fill="both", expand=True)

        sb = ctk.CTkScrollbar(table_frame, orientation="vertical", command=tree.yview)
        sb.pack(side="right", fill="y")
        tree.configure(yscrollcommand=sb.set)

        col_cfg = {
            "Filename": dict(anchor="w", width=420, stretch=True),
            "Size":     dict(anchor="e", width=110, stretch=False),
            "MD5":      dict(anchor="w", width=260, stretch=False),
            "Result":   dict(anchor="w", width=110, stretch=False),
        }
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, **col_cfg[col])

        tree.tag_configure("ok",      background="#2E8B57")
        tree.tag_configure("missing", background="#9B1313")
        tree.tag_configure("invalid", background="#C76E00")
        tree.tag_configure("extra",   background="#6B6248")
        problem_rows = [r for r in entry.rows if r["tag"] in ("missing", "invalid")]
        ok_rows      = [r for r in entry.rows if r["tag"] not in ("missing", "invalid")]

        for r in problem_rows + ok_rows:
            tree.insert(
                "", "end",
                values=[
                    r["name"],
                    human_size(r["size"]) if r["size"] else "",
                    r["md5"],
                    r["result"],
                ],
                tags=(r["tag"],),
            )

        for full_path in entry.extra_files:
            tree.insert(
                "", 0,
                values=[full_path, "", "", "Extra File"],
                tags=("extra",),
            )

        ctk.CTkButton(self, text="Close", width=120, command=self._close).pack(
            pady=(0, 14)
        )

    def _do_grab(self):
        try:
            self.grab_set()
            self.focus_set()
        except Exception:
            pass

    def _close(self):
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

class BatchResultsDialog(ctk.CTkToplevel):
    def __init__(self, parent, entries: list[BatchGameEntry]):
        super().__init__(parent)
        self.title("Batch Validation Results")
        self.geometry("860x580")
        self.transient(parent)
        self.after(50, self._do_grab)

        ok      = sum(1 for e in entries if e.status == "ok")
        invalid = sum(1 for e in entries if e.status == "invalid")
        errors  = sum(1 for e in entries if e.status == "error")

        summary = f"Games: {len(entries)}   OK: {ok}   Invalid: {invalid}   Errors: {errors}"
        ctk.CTkLabel(self, text=summary, font=("", 14, "bold")).pack(
            padx=16, pady=(14, 6), anchor="w"
        )
        ctk.CTkLabel(
            self,
            text="Double-click a game (or select it and press View Report) "
                 "to see the exact per-file report for that game.",
            text_color="gray", font=("", 11),
        ).pack(padx=16, pady=(0, 8), anchor="w")

        list_frame = ctk.CTkFrame(self)
        list_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        columns = ("Game", "Type", "Status", "OK", "Invalid", "Missing")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        self.tree.pack(side="left", fill="both", expand=True)

        sb = ctk.CTkScrollbar(list_frame, orientation="vertical", command=self.tree.yview)
        sb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=sb.set)

        col_cfg = {
            "Game":    dict(anchor="w", width=380, stretch=True),
            "Type":    dict(anchor="center", width=60, stretch=False),
            "Status":  dict(anchor="center", width=90, stretch=False),
            "OK":      dict(anchor="e", width=60, stretch=False),
            "Invalid": dict(anchor="e", width=60, stretch=False),
            "Missing": dict(anchor="e", width=70, stretch=False),
        }
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, **col_cfg[col])

        self.tree.tag_configure("ok",      background="#2E8B57")
        self.tree.tag_configure("invalid", background="#C76E00")
        self.tree.tag_configure("error",   background="#9B1313")

        self._iid_to_entry: dict[str, BatchGameEntry] = {}
        status_txt_map = {"ok": "OK", "invalid": "Invalid", "error": "Error"}
        for e in entries:
            tag = e.status if e.status in ("ok", "invalid", "error") else ""
            iid = self.tree.insert(
                "", "end",
                values=[
                    e.display_name, e.kind.upper(),
                    status_txt_map.get(e.status, e.status),
                    e.ok, e.invalid, e.missing,
                ],
                tags=(tag,),
            )
            self._iid_to_entry[iid] = e

        self.tree.bind("<Double-Button-1>", self._open_detail_at_event)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=(0, 16))
        ctk.CTkButton(btn_frame, text="View Report", width=140,
                      command=self._open_detail_selected).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Close", width=120, fg_color="gray40",
                      command=self._close).pack(side="left", padx=8)

    def _do_grab(self):
        try:
            self.grab_set()
            self.focus_set()
        except Exception:
            pass

    def _close(self):
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

    def _open_detail_at_event(self, event):
        iid = self.tree.identify_row(event.y)
        entry = self._iid_to_entry.get(iid)
        if entry:
            GameReportDialog(self, entry)

    def _open_detail_selected(self):
        iid = self.tree.focus()
        entry = self._iid_to_entry.get(iid)
        if entry:
            GameReportDialog(self, entry)
        else:
            messagebox.showinfo("Batch Validation Results", "Select a game first.", parent=self)
