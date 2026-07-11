import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from utils.size_units import human_size

_FIXED_WIDTH_COLS = {"Size", "MD5", "Result"}
_TAG_COLORS = {
    "ok":      "#2E8B57",
    "missing": "#9B1313",
    "invalid": "#C76E00",
    "extra":   "#6B6248",
}

class ResultsTable:
    HEADERS = ("Filename", "Size", "MD5", "Result")
    _COL_CFG = {
        "Filename": dict(anchor="w", width=380, stretch=True,  minwidth=120),
        "Size":     dict(anchor="e", width=110, stretch=False, minwidth=80),
        "MD5":      dict(anchor="w", width=260, stretch=False, minwidth=220),
        "Result":   dict(anchor="w", width=120, stretch=False, minwidth=80),
    }

    def __init__(self, parent):
        self.container = ctk.CTkFrame(parent)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(self.container, columns=self.HEADERS, show="headings")
        self.tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ctk.CTkScrollbar(
            self.container, orientation="vertical", command=self.tree.yview
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        for col in self.HEADERS:
            self.tree.heading(col, text=col)
            self.tree.column(col, **self._COL_CFG.get(col, dict(anchor="w", width=150, stretch=False)))

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
        for tag, color in _TAG_COLORS.items():
            self.tree.tag_configure(tag, background=color)

        self._rows:         list[str] = []
        self._extra_rows:   list[str] = []
        self._row_details:  dict[str, str] = {}
        self._row_raw_size: dict[str, int] = {}

        self._tree_tip = None
        self.tree.bind("<Motion>", self._on_motion)
        self.tree.bind("<Leave>",  self._on_leave)

    def grid(self, **kwargs):
        self.container.grid(**kwargs)

    def clear(self):
        for iid in self._rows + self._extra_rows:
            self.tree.delete(iid)
        self._rows.clear()
        self._extra_rows.clear()
        self._row_details.clear()
        self._row_raw_size.clear()

    def add_row(self, values: list[str], tag: str = "", raw_size: int = 0) -> str:
        if tag in ("missing", "invalid"):
            iid = self.tree.insert("", 0, values=values, tags=(tag,))
            self._rows.insert(0, iid)
        else:
            iid = self.tree.insert("", "end", values=values, tags=(tag,))
            self._rows.append(iid)
        self._row_details[iid]  = ""
        self._row_raw_size[iid] = raw_size
        return iid

    def add_extra_row(self, values: list[str]) -> str:
        iid = self.tree.insert("", 0, values=values, tags=("extra",))
        self._extra_rows.append(iid)
        return iid

    def update_row(self, idx: int, size_str, md5_hex, result_text: str, tag: str):
        if not (0 <= idx < len(self._rows)):
            return
        iid  = self._rows[idx]
        vals = list(self.tree.item(iid, "values"))
        vals[3] = result_text or ""

        if tag == "invalid":
            ird_md5 = vals[2]
            raw_ird = self._row_raw_size.get(iid, 0)
            raw_jb  = int(size_str) if size_str and str(size_str).isdigit() else None

            def _fmt(raw):
                if raw is None:
                    return chr(8212)
                return f"{human_size(raw)}  ({raw:,} B)"

            self._row_details[iid] = (
                f"{'Size':8}  IRD  {_fmt(raw_ird)}\n"
                f"{'':8}  File {_fmt(raw_jb)}\n"
                f"\n"
                f"{'MD5':8}  IRD  {ird_md5}\n"
                f"{'':8}  File {md5_hex or chr(8212)}"
            )
        elif tag == "missing":
            self._row_details[iid] = "File not found on disk"
        else:
            raw_jb = int(size_str) if size_str and str(size_str).isdigit() else None
            if raw_jb is not None:
                self._row_raw_size[iid] = raw_jb
            self._row_details[iid] = ""

        self.tree.item(iid, values=vals, tags=(tag,))
        if tag in ("missing", "invalid"):
            self.tree.move(iid, "", 0)

    def autosize_columns(self):
        self.tree.update_idletasks()
        for col in self.tree["columns"]:
            if col in _FIXED_WIDTH_COLS:
                continue
            char_widths = (
                [len(self.tree.heading(col, option="text"))]
                + [len(str(self.tree.set(iid, col))) for iid in self.tree.get_children()]
            )
            self.tree.column(col, width=max(char_widths) * 7 + 20)

    def _on_motion(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            self._hide_tip()
            return

        col      = self.tree.identify_column(event.x)
        headers  = self.tree["columns"]
        col_idx  = int(col.lstrip("#")) - 1 if col.startswith("#") else -1
        col_name = headers[col_idx] if 0 <= col_idx < len(headers) else ""

        if col_name == "Size":
            raw = self._row_raw_size.get(iid, 0)
            tip_text = f"{raw:,} bytes" if raw else ""
        else:
            tip_text = self._row_details.get(iid, "")

        if not tip_text:
            self._hide_tip()
            return

        tip_key = (iid, col_name)
        if self._tree_tip and getattr(self._tree_tip, "_for_key", None) == tip_key:
            return
        self._hide_tip()

        x = self.tree.winfo_rootx() + event.x + 16
        y = self.tree.winfo_rooty() + event.y + 4
        try:
            tw = tk.Toplevel(self.tree)
            tw.overrideredirect(True)
            tw.withdraw()
            tw.attributes("-topmost", True)
            tw.attributes("-alpha", 0.95)
            tk.Label(
                tw, text=tip_text, font=("Consolas", 10),
                background="#2b2b2b", foreground="white",
                relief="flat", padx=6, pady=3, justify="left",
            ).pack()
            tw.update_idletasks()
            tw.wm_geometry(f"+{x}+{y}")
            tw.deiconify()
            tw._for_key = tip_key
            self._tree_tip = tw
        except Exception:
            pass

    def _on_leave(self, _event):
        self._hide_tip()

    def _hide_tip(self):
        if self._tree_tip:
            try:
                self._tree_tip.destroy()
            except Exception:
                pass
            self._tree_tip = None
