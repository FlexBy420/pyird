import customtkinter as ctk
from tkinter import ttk, Menu
from utils.size_units import human_size

def _hex(data: bytes | None) -> str:
    if not data:
        return "-"
    return data.hex()

def build_ird_info_rows(ird) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = [
        ("IRD Version",        str(ird.version)),
        ("Product Code",       ird.product_code.strip() or "-"),
        ("Title",              ird.title.strip() or "-"),
        ("Title Length",       str(ird.title_length)),
        ("Update Version",     ird.update_version.strip() or "-"),
        ("Game Version",       ird.game_version.strip() or "-"),
        ("App Version",        ird.app_version.strip() or "-"),
    ]

    if ird.version == 7:
        rows.append(("ID", f"0x{ird.id:08X}"))

    rows += [
        ("Header Length",      f"{ird.header_length:,} B"),
        ("Footer Length",      f"{ird.footer_length:,} B"),
        ("Region Count",       str(ird.region_count)),
    ]

    for i, md5 in enumerate(ird.region_md5_checksums):
        rows.append((f"Region {i} MD5", _hex(md5)))

    rows += [
        ("File Count",         str(ird.file_count)),
        ("Disc Size",          f"{human_size(ird.disc_size)}  ({ird.disc_size:,} B)"
                                if ird.disc_size else "-"),
        ("PIC",                _hex(ird.pic)),
        ("Data1",              _hex(ird.data1)),
        ("Data2",              _hex(ird.data2)),
        ("UID",                f"0x{ird.uid:08X}"),
        ("CRC32",              f"0x{ird.crc32:08X}"),
    ]
    return rows

class IrdInfoDialog(ctk.CTkToplevel):
    def __init__(self, parent, ird):
        super().__init__(parent)
        self.title("IRD Info")
        self.geometry("620x640")
        self.transient(parent)
        self.after(50, self._do_grab)

        header = ird.product_code.strip() or "Unknown product code"
        if ird.title.strip():
            header += f"  -  {ird.title.strip()}"
        ctk.CTkLabel(self, text=header, font=("", 14, "bold")).pack(
            padx=16, pady=(14, 8), anchor="w"
        )

        table_frame = ctk.CTkFrame(self)
        table_frame.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        columns = ("Field", "Value")
        self.tree = tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        tree.pack(side="left", fill="both", expand=True)

        sb = ctk.CTkScrollbar(table_frame, orientation="vertical", command=tree.yview)
        sb.pack(side="right", fill="y")
        tree.configure(yscrollcommand=sb.set)

        tree.heading("Field", text="Field")
        tree.heading("Value", text="Value")
        tree.column("Field", anchor="w", width=180, stretch=False)
        tree.column("Value", anchor="w", width=400, stretch=True)

        self._rows_data = build_ird_info_rows(ird)
        for label, value in self._rows_data:
            tree.insert("", "end", values=[label, value])

        self._menu = Menu(tree, tearoff=0, bg="#2b2b2b", fg="white",
                           activebackground="#1f6aa5", activeforeground="white", bd=0)
        self._menu.add_command(label="Copy Value", command=self._copy_value)
        self._menu.add_command(label="Copy Field: Value", command=self._copy_field_value)

        tree.bind("<Button-3>", self._on_right_click)
        tree.bind("<Control-c>", lambda _e: self._copy_value())

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=(0, 14))
        ctk.CTkButton(btn_frame, text="Copy All", width=140,
                      command=self._copy_all).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Close", width=120, fg_color="gray40",
                      command=self._close).pack(side="left", padx=8)

    def _do_grab(self):
        try:
            self.grab_set()
            self.focus_set()
        except Exception:
            pass

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        self.tree.focus(iid)
        try:
            self._menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._menu.grab_release()

    def _selected_row(self) -> tuple[str, str] | None:
        sel = self.tree.selection()
        if not sel:
            return None
        field, value = self.tree.item(sel[0], "values")
        return field, value

    def _copy_to_clipboard(self, text: str):
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
        except Exception:
            pass

    def _copy_value(self):
        row = self._selected_row()
        if row:
            self._copy_to_clipboard(row[1])

    def _copy_field_value(self):
        row = self._selected_row()
        if row:
            self._copy_to_clipboard(f"{row[0]}: {row[1]}")

    def _copy_all(self):
        text = "\n".join(f"{label}: {value}" for label, value in self._rows_data)
        self._copy_to_clipboard(text)

    def _close(self):
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()
