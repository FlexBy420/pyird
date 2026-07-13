import customtkinter as ctk
from tkinter import Listbox, SINGLE, END

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
