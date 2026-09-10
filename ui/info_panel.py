import customtkinter as ctk
from ui.tooltip import bind_tooltip

INFO_META = [
    ("Product Code",   "TITLE_ID",       "Product code printed on the disc."),
    ("Title",           "TITLE",          "Game title."),
    ("App Version",     "APP_VER",        "Game version as seen in XMB (APP_VER)."),
    ("Game Version",    "VERSION",        "Disc print version (VERSION) of this specific\ngame version (APP_VER)."),
    ("Update Version",  "PS3_SYSTEM_VER", "Minimum firmware version required (PS3_SYSTEM_VER)\nand provided on the disc for offline update."),
    ("Files",           None,             "Number of files on the disc (from IRD)."),
    ("Total Size",      None,             "Game size on disc (from IRD)."),
]

class InfoPanel:
    def __init__(self, parent, tooltip_text_fn):
        self.meta = INFO_META
        self.frame = ctk.CTkFrame(parent)
        for c in range(len(self.meta)):
            self.frame.grid_columnconfigure(c, weight=1)

        headers = [m[0] for m in self.meta]
        self.vars: list = [ctk.StringVar(value="") for _ in headers]
        self.labels: list = []

        for i, h in enumerate(headers):
            ctk.CTkLabel(self.frame, text=h, font=("", 12, "bold")).grid(
                row=0, column=i, sticky="ew", padx=4, pady=(4, 2)
            )
        for i, var in enumerate(self.vars):
            lbl = ctk.CTkLabel(self.frame, textvariable=var)
            lbl.grid(row=1, column=i, sticky="ew", padx=4, pady=(0, 6))
            self.labels.append(lbl)
            bind_tooltip(lbl, (lambda i=i: tooltip_text_fn(i)), font=("Consolas", 10))

    def grid(self, **kwargs):
        self.frame.grid(**kwargs)

    def set_values(self, values: list[str]):
        for var, v in zip(self.vars, values):
            var.set(v)

    def clear(self):
        for var in self.vars:
            var.set("")
        for label in self.labels:
            label.configure(text_color="white")
